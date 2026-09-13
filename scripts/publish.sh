#!/usr/bin/env bash
# Publish staged packages to the rolling release and regenerate the db.
#
#   GH_REPO=owner/name PKGDIR=./staging scripts/publish.sh
#
# Env:
#   PKGDIR   directory of built *.pkg.tar.* to publish
#   DRY_RUN  1 to do everything except mutate the release
#
# Ordering matters and is not incidental:
#   1. packages up first, so the db never names a file that isn't there yet
#   2. db second (.db last of the four, since that is what pacman fetches)
#   3. garbage-collect superseded packages only after the new db is live, so
#      the db being served never references a deleted asset
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/common.sh

: "${GH_REPO:?GH_REPO must be set (owner/name)}"
: "${PKGDIR:?PKGDIR must be set}"
DRY_RUN="${DRY_RUN:-0}"

[[ -d "$PKGDIR" ]] || die "PKGDIR '$PKGDIR' does not exist"
shopt -s nullglob
incoming=()
for candidate in "$PKGDIR"/*.pkg.tar.*; do
  [[ $candidate == *.sig ]] || incoming+=("$candidate")
done
((${#incoming[@]})) || die "no packages in '$PKGDIR'"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '\033[1;35mDRY-RUN\033[0m %s\n' "$*" >&2
  else
    "$@"
  fi
}

# --- stage, sanitizing epoch filenames --------------------------------------
log "Staging ${#incoming[@]} package(s)"
staged=()
for pkg in "${incoming[@]}"; do
  base="$(basename "$pkg")"
  safe="$(sanitize_asset_name "$base")"
  if [[ "$safe" != "$base" ]]; then
    log "  $base -> $safe (':' is not allowed in a release asset name)"
  fi
  [[ -f $pkg && ! -L $pkg ]] || die "unsafe incoming archive"
  cp "$pkg" "$work/$safe"
  staged+=("$safe")
  if [[ -e $pkg.sig ]]; then cp "$pkg.sig" "$work/$safe.sig"; fi
done

# A signed baseline is a prerequisite; bootstrap is a separately reviewed full
# inventory operation. Never silently downgrade to an unsigned existing feed.
fetch_current_dbs "$work"
gh release download "$REPO_TAG" --repo "$GH_REPO" --dir "$work" --clobber \
  --pattern "$DB_NAME.db.tar.zst.sig" --pattern "$DB_NAME.files.tar.zst.sig" \
  || die "signed baseline required; complete the reviewed bootstrap first"
for ext in db files; do
  cp "$work/$DB_NAME.$ext.tar.zst" "$work/$DB_NAME.$ext"
  cp "$work/$DB_NAME.$ext.tar.zst.sig" "$work/$DB_NAME.$ext.sig"
done
python3 scripts/package-signing.py verify-databases "$work"
# Reuse an already published valid signature when retrying identical bytes.
# Fresh GPG signatures have different timestamps and must not replace it.
gh release view "$REPO_TAG" --repo "$GH_REPO" --json assets --jq '.assets[].name' > "$work/remote-assets" || die "cannot read current assets"
mkdir -p "$work/existing"
for name in "${staged[@]}"; do
  if grep -Fxq "$name" "$work/remote-assets"; then
    gh release download "$REPO_TAG" --repo "$GH_REPO" --dir "$work/existing" --pattern "$name" --pattern "$name.sig" --clobber || die "published archive/signature missing"
    cmp "$work/$name" "$work/existing/$name" || die "remote filename collision: $name"
  fi
done
if find "$work/existing" -maxdepth 1 -name '*.pkg.tar.*' -print -quit | grep -q .; then
  python3 scripts/package-signing.py verify-packages "$work/existing"
  for signature in "$work/existing"/*.sig; do cp "$signature" "$work/${signature##*/}"; done
fi
python3 scripts/package-signing.py sign-packages "$work"
# Old DB signatures cannot describe the regenerated DB. Keep no stale aliases.
rm -- "$work/$DB_NAME.db.sig" "$work/$DB_NAME.db.tar.zst.sig" "$work/$DB_NAME.files.sig" "$work/$DB_NAME.files.tar.zst.sig"
db_filenames "$work/$DB_NAME.db.tar.zst" | sort > "$work/filenames.before"
before_count="$(wc -l < "$work/filenames.before" | tr -d ' ')"
log "Current db holds $before_count package(s)"

# --- repo-add ---------------------------------------------------------------
# repo-add takes %FILENAME% verbatim from the file it is handed, which is why
# the rename above has to happen first.
log "Running repo-add for: ${staged[*]}"
# --prevent-downgrade is a second line of defence behind detect-updates.sh:
# even if a stale version reached the staging dir, the db refuses to move
# backwards, which is what makes pacman -Syu offer downgrades.
( cd "$work" && repo-add --quiet --include-sigs --prevent-downgrade "$DB_NAME.db.tar.zst" "${staged[@]}" ) \
  || die "repo-add failed"

# repo-add leaves .db and .files as symlinks to the tarballs. Release assets
# must be real bytes: pacman fetches <repo>.db directly. rm first — cp would
# otherwise follow the symlink and write straight into its target.
for pair in "db:db.tar.zst" "files:files.tar.zst"; do
  plain="$DB_NAME.${pair%%:*}"; tarball="$DB_NAME.${pair##*:}"
  [[ -f "$work/$tarball" ]] || die "repo-add did not produce $tarball"
  rm -f "$work/$plain"
  cp "$work/$tarball" "$work/$plain"
done
log "Materialised .db and .files as real copies"
python3 scripts/package-signing.py sign-databases "$work"
python3 scripts/package-signing.py verify-packages "$work"
python3 scripts/package-signing.py verify-databases "$work"

# --- verify before touching the release -------------------------------------
db_filenames "$work/$DB_NAME.db.tar.zst" | sort > "$work/filenames.after"
after_count="$(wc -l < "$work/filenames.after" | tr -d ' ')"
log "New db holds $after_count package(s)"

for name in "${staged[@]}"; do
  command grep -Fxq "$name" "$work/filenames.after" \
    || die "db has no %FILENAME% entry for '$name' — pacman would 404 on it"
done
log "Every staged package is referenced by the new db"

while read -r fn; do
  [[ -n "$fn" ]] || continue
  [[ "$fn" == *:* ]] && die "db references '$fn', which contains ':' and cannot exist as a release asset"
done < "$work/filenames.after"

(( after_count >= before_count )) \
  || die "new db has $after_count entries, down from $before_count — refusing to shrink the repo"

# --- upload: packages first, then the db ------------------------------------
log "Uploading ${#staged[@]} package asset(s)"
for name in "${staged[@]}"; do
  # Exact filename reuse must be byte-identical; never overwrite archive/signature.
  for asset in "$name" "$name.sig"; do
    if grep -Fxq "$asset" "$work/remote-assets"; then
      mkdir -p "$work/existing"
      gh release download "$REPO_TAG" --repo "$GH_REPO" --pattern "$asset" --dir "$work/existing" --clobber
      cmp "$work/$asset" "$work/existing/$asset" || die "remote filename collision: $asset"
    else
      run gh release upload "$REPO_TAG" "$work/$asset" --repo "$GH_REPO" || die "failed to upload $asset"
    fi
  done
done

log "Uploading db assets (.db last)"
# Mutable edge compatibility only: separate GitHub assets cannot be switched
# atomically. Clients fail closed during a DB/signature mismatch; retain the
# prior signed snapshot and retry the exact pair. RC/stable use immutable plans.
for f in "$DB_NAME.files.tar.zst.sig" "$DB_NAME.files.tar.zst" "$DB_NAME.files.sig" "$DB_NAME.files" "$DB_NAME.db.tar.zst.sig" "$DB_NAME.db.tar.zst" "$DB_NAME.db.sig" "$DB_NAME.db"; do
  run gh release upload "$REPO_TAG" "$work/$f" --repo "$GH_REPO" --clobber \
    || die "failed to upload $f"
done

# --- garbage-collect superseded packages ------------------------------------
# Anything not named by the db we just published is dead weight, and stale
# versions are what make a hand-maintained repo confusing to browse.
log "Checking for superseded package assets"
gh release view "$REPO_TAG" --repo "$GH_REPO" --json assets \
  | jq -r '.assets[].name' | command grep '\.pkg\.tar\.' | sort > "$work/assets.now" || true

stale=()
while read -r asset; do
  [[ -n "$asset" ]] || continue
  command grep -Fxq "${asset%.sig}" "$work/filenames.after" || stale+=("$asset")
done < "$work/assets.now"

if ((${#stale[@]})); then
  log "Deleting ${#stale[@]} superseded asset(s):"
  printf '    %s\n' "${stale[@]}" >&2
  for asset in "${stale[@]}"; do
    run gh release delete-asset "$REPO_TAG" "$asset" --repo "$GH_REPO" --yes \
      || warn "could not delete $asset"
  done
else
  log "No superseded assets to delete"
fi

# Hand the new db to the caller so the README table can be rebuilt from it.
if [[ -n "${DB_OUT:-}" ]]; then
  mkdir -p "$DB_OUT"
  cp "$work/$DB_NAME.db.tar.zst" "$DB_OUT/"
  log "Copied new db to $DB_OUT"
fi
log "Done. Published: ${staged[*]}"
