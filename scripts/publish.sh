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
[[ $REPO_TAG == edge ]] || die "rolling publisher may target only edge"

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

# Any signature or durable conversion marker permanently selects strict mode.
# Missing/corrupt signatures then fail closed; they never trigger unsigned fallback.
fetch_current_dbs "$work"
gh release view "$REPO_TAG" --repo "$GH_REPO" --json assets --jq '.assets[].name' > "$work/remote-assets" || die "cannot read current assets"
mode=$(python3 scripts/edge-mode.py --database "$work/$DB_NAME.db.tar.zst" --assets "$work/remote-assets") || die "cannot establish edge signing state"
log "Edge signing state: $mode"
if [[ $mode == strict ]]; then
  gh release download "$REPO_TAG" --repo "$GH_REPO" --dir "$work" --clobber \
    --pattern "$DB_NAME.db.tar.zst.sig" --pattern "$DB_NAME.files.tar.zst.sig" \
    || die "signed edge is incomplete; resume its exact approved conversion/publication"
  for ext in db files; do
    cp "$work/$DB_NAME.$ext.tar.zst" "$work/$DB_NAME.$ext"
    cp "$work/$DB_NAME.$ext.tar.zst.sig" "$work/$DB_NAME.$ext.sig"
  done
  python3 scripts/package-signing.py verify-databases "$work"
else
  for name in "${staged[@]}"; do
    [[ ! -e $work/$name.sig ]] || die "legacy edge must remain unsigned until approved full-inventory conversion"
  done
fi
# An interrupted archive upload may lack its signature. Compare archive bytes
# first, reuse an existing valid signature if present, or create only the missing
# signature. Never replace a conflicting signature or archive.
mkdir -p "$work/existing"
for name in "${staged[@]}"; do
  if grep -Fxq "$name" "$work/remote-assets"; then
    gh release download "$REPO_TAG" --repo "$GH_REPO" --dir "$work/existing" --pattern "$name" --clobber || die "published archive missing"
    if ! cmp -s "$work/$name" "$work/existing/$name"; then
      python3 scripts/bootstrap-rc.py reuse-extra --incoming "$work/$name" --published "$work/existing/$name" --database "$work/$DB_NAME.db.tar.zst"         || die "remote filename collision: $name"
    fi
    if grep -Fxq "$name.sig" "$work/remote-assets"; then
      gh release download "$REPO_TAG" --repo "$GH_REPO" --dir "$work/existing" --pattern "$name.sig" --clobber || die "published signature missing"
      cp "$work/existing/$name.sig" "$work/$name.sig"
    fi
  elif grep -Fxq "$name.sig" "$work/remote-assets"; then
    die "orphan published signature: $name.sig"
  fi
done
if [[ $mode == strict ]]; then
  python3 scripts/package-signing.py sign-packages "$work"
  rm -- "$work/$DB_NAME.db.sig" "$work/$DB_NAME.db.tar.zst.sig" "$work/$DB_NAME.files.sig" "$work/$DB_NAME.files.tar.zst.sig"
fi
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
repo_options=(--quiet --prevent-downgrade)
[[ $mode != strict ]] || repo_options+=(--include-sigs)
( cd "$work" && repo-add "${repo_options[@]}" "$DB_NAME.db.tar.zst" "${staged[@]}" ) \
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
if [[ $mode == strict ]]; then
  python3 scripts/package-signing.py sign-databases "$work"
  python3 scripts/package-signing.py verify-packages "$work"
  python3 scripts/package-signing.py verify-databases "$work"
fi

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
  package_assets=("$name")
  [[ $mode != strict ]] || package_assets+=("$name.sig")
  for asset in "${package_assets[@]}"; do
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
# signed workflow artifacts for manual recovery. RC/stable use immutable plans.
database_assets=()
for suffix in files.tar.zst files db.tar.zst db; do
  [[ $mode != strict ]] || database_assets+=("$DB_NAME.$suffix.sig")
  database_assets+=("$DB_NAME.$suffix")
done
for f in "${database_assets[@]}"; do
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
  mkdir -p "$DB_OUT/smoke-packages"
  for name in "${staged[@]}"; do
    cp --reflink=auto "$work/$name" "$DB_OUT/smoke-packages/$name"
  done
  printf "%s\n" "$mode" > "$DB_OUT/signing-mode"
  log "Copied new db to $DB_OUT"
fi
log "Done. Published: ${staged[*]}"
