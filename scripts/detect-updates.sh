#!/usr/bin/env bash
# Compare upstream versions against the versions already published in the repo
# db, and emit the build matrix for whatever has moved.
#
#   GH_REPO=owner/name scripts/detect-updates.sh
#
# Env:
#   CATEGORIES  comma-separated categories to consider (default: any,repack)
#   PACKAGES    comma-separated pkgnames to restrict to (default: all in scope)
#
# The published db is the only state this reads. There is deliberately no
# version file in the tree to fall out of sync with what is actually served.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/common.sh

: "${GH_REPO:?GH_REPO must be set (owner/name)}"
CATEGORIES="${CATEGORIES:-any,repack,compile}"
PACKAGES="${PACKAGES:-}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch_current_dbs "$work"
db_versions   "$work/$DB_NAME.db.tar.zst" > "$work/published.tsv"
db_builddates "$work/$DB_NAME.db.tar.zst" > "$work/builddates.tsv"

# --- select the packages in scope -------------------------------------------
jq --arg cats "$CATEGORIES" --arg pkgs "$PACKAGES" '
  ($cats | split(",")) as $c
  | ($pkgs | if . == "" then [] else split(",") end) as $p
  | .packages
  | map(select(.category as $x | $c | index($x)))
  | map(select(($p | length) == 0 or (.name as $n | $p | index($n))))
  | map(select((.skip // false) | not))
  # version_check "none" packages stay in scope: they cannot be version-diffed,
  # but they can still be due for a timed rebuild.
  | map(select((.version_check // "") != "none" or (.rebuild_after_days // 0) > 0))
' "$MANIFEST" > "$work/scope.json"

count="$(jq 'length' "$work/scope.json")"
log "$count package(s) in scope (categories: $CATEGORIES)"
[[ "$count" -gt 0 ]] || { echo "matrix={\"include\":[]}" >>"${GITHUB_OUTPUT:-/dev/null}"; log "nothing in scope"; exit 0; }

# --- upstream versions: AUR in one RPC call ---------------------------------
: > "$work/upstream.tsv"
mapfile -t aur_names < <(jq -r '.[] | select(.source == "aur") | .name' "$work/scope.json")
if ((${#aur_names[@]})); then
  query=""
  for n in "${aur_names[@]}"; do query+="&arg[]=$n"; done
  log "Querying AUR RPC for ${#aur_names[@]} package(s)"
  curl -fsS --retry 3 --retry-delay 2 \
    "https://aur.archlinux.org/rpc/v5/info?${query#&}" -o "$work/aur.json" \
    || die "AUR RPC request failed"
  jq -r '.results[] | [.Name, .Version] | @tsv' "$work/aur.json" >> "$work/upstream.tsv"
fi

# --- upstream versions: omarchy-pkgs PKGBUILDs ------------------------------
# Read the version fields directly rather than sourcing the PKGBUILD, so
# detection never executes upstream code.
mapfile -t oma_bases < <(jq -r '.[] | select(.source == "omarchy-pkgs") | .pkgbase' "$work/scope.json" | sort -u)
for base in "${oma_bases[@]:-}"; do
  [[ -n "$base" ]] || continue
  url="https://raw.githubusercontent.com/$OMARCHY_PKGS_REPO/HEAD/pkgbuilds/$base/PKGBUILD"
  log "Reading $OMARCHY_PKGS_REPO pkgbuilds/$base/PKGBUILD"
  pkgbuild="$work/$base.PKGBUILD"
  curl -fsS --retry 3 --retry-delay 2 "$url" -o "$pkgbuild" \
    || die "could not fetch PKGBUILD for $base"
  epoch=$(sed -nE "s/^epoch=['\"]?([^'\"#]+)['\"]?.*/\1/p"  "$pkgbuild" | head -1)
  pkgver=$(sed -nE "s/^pkgver=['\"]?([^'\"#]+)['\"]?.*/\1/p" "$pkgbuild" | head -1)
  pkgrel=$(sed -nE "s/^pkgrel=['\"]?([^'\"#]+)['\"]?.*/\1/p" "$pkgbuild" | head -1)
  [[ -n "$pkgver" && -n "$pkgrel" ]] || die "could not parse pkgver/pkgrel for $base"
  ver="$pkgver-$pkgrel"
  [[ -n "$epoch" ]] && ver="$epoch:$ver"
  while read -r name; do
    printf '%s\t%s\n' "$name" "$ver" >> "$work/upstream.tsv"
  done < <(jq -r --arg b "$base" '.[] | select(.pkgbase == $b) | .name' "$work/scope.json")
done

# --- upstream versions: in-tree PKGBUILDs (source "local") ------------------
# "Upstream" here is this repo's own pkgbuilds/ tree: a bump lands as an edit
# to the PKGBUILD, and this comparison against the published db picks it up.
mapfile -t local_bases < <(jq -r '.[] | select(.source == "local") | .pkgbase' "$work/scope.json" | sort -u)
for base in "${local_bases[@]:-}"; do
  [[ -n "$base" ]] || continue
  pkgbuild="pkgbuilds/$base/PKGBUILD"
  log "Reading in-tree $pkgbuild"
  [[ -f "$pkgbuild" ]] || die "no in-tree PKGBUILD at $pkgbuild"
  epoch=$(sed -nE "s/^epoch=['\"]?([^'\"#]+)['\"]?.*/\1/p"  "$pkgbuild" | head -1)
  pkgver=$(sed -nE "s/^pkgver=['\"]?([^'\"#]+)['\"]?.*/\1/p" "$pkgbuild" | head -1)
  pkgrel=$(sed -nE "s/^pkgrel=['\"]?([^'\"#]+)['\"]?.*/\1/p" "$pkgbuild" | head -1)
  [[ -n "$pkgver" && -n "$pkgrel" ]] || die "could not parse pkgver/pkgrel for $base"
  ver="$pkgver-$pkgrel"
  [[ -n "$epoch" ]] && ver="$epoch:$ver"
  while read -r name; do
    printf '%s\t%s\n' "$name" "$ver" >> "$work/upstream.tsv"
  done < <(jq -r --arg b "$base" '.[] | select(.pkgbase == $b) | .name' "$work/scope.json")
done

# --- compare ----------------------------------------------------------------
: > "$work/needs-update.txt"
printf '%-38s %-24s %-24s %s\n' PACKAGE PUBLISHED UPSTREAM STATUS
printf '%.0s-' {1..100}; echo
status=0
now="$(date +%s)"
while read -r name; do
  published="$(awk -F'\t' -v n="$name" '$1 == n {print $2}' "$work/published.tsv")"
  upstream="$(awk -F'\t' -v n="$name" '$1 == n {print $2}' "$work/upstream.tsv")"

  # Timer-driven packages (VCS): age the published build rather than compare
  # versions, since upstream's declared pkgver is stale by construction.
  days="$(jq -r --arg n "$name" '.[] | select(.name == $n) | .rebuild_after_days // 0' "$work/scope.json")"
  if [[ "${days:-0}" -gt 0 ]]; then
    built="$(awk -F'\t' -v n="$name" '$1 == n {print $2}' "$work/builddates.tsv")"
    if [[ -z "$built" ]]; then
      age_days=99999
    else
      age_days=$(( (now - built) / 86400 ))
    fi
    if (( age_days >= days )); then
      printf '%-38s %-24s %-24s %s\n' "$name" "${published:-—}" "(timer)" "REBUILD (${age_days}d old, every ${days}d)"
      echo "$name" >> "$work/needs-update.txt"
    else
      printf '%-38s %-24s %-24s %s\n' "$name" "${published:-—}" "(timer)" "current (${age_days}d old, every ${days}d)"
    fi
    continue
  fi

  if [[ -z "$upstream" ]]; then
    printf '%-38s %-24s %-24s %s\n' "$name" "${published:-—}" "—" "NO UPSTREAM VERSION"
    warn "$name: no upstream version found; skipping"
    continue
  fi
  if [[ -z "$published" ]]; then
    printf '%-38s %-24s %-24s %s\n' "$name" "—" "$upstream" "NEW"
    echo "$name" >> "$work/needs-update.txt"
    continue
  fi
  cmp="$(vercmp "$upstream" "$published")"
  if   (( cmp > 0 )); then
    printf '%-38s %-24s %-24s %s\n' "$name" "$published" "$upstream" "UPDATE"
    echo "$name" >> "$work/needs-update.txt"
  elif (( cmp < 0 )); then
    # Never publish backwards: that is exactly what makes pacman -Syu offer
    # downgrades to anyone who installed a newer build another way.
    printf '%-38s %-24s %-24s %s\n' "$name" "$published" "$upstream" "AHEAD (skipped)"
    warn "$name: published $published is newer than upstream $upstream; not downgrading"
  else
    printf '%-38s %-24s %-24s %s\n' "$name" "$published" "$upstream" "current"
  fi
done < <(jq -r '.[].name' "$work/scope.json")
echo

# --- emit the matrix, grouped by pkgbase so a split package builds once -----
matrix="$(jq -c --slurpfile scope <(cat "$work/scope.json") \
  --rawfile updates "$work/needs-update.txt" '
  ($updates | split("\n") | map(select(length > 0))) as $u
  | $scope[0]
  | map(select(.name as $n | $u | index($n)))
  | group_by(.pkgbase)
  | map({
      pkgbase:  .[0].pkgbase,
      source:   .[0].source,
      category: .[0].category,
      pkgnames: (map(.name) | join(",")),
      ignorearch: (map(.ignorearch // false) | any),
      extra_makedepends: (map(.extra_makedepends // []) | add | unique | join(",")),
      allow_foreign_elf: (map(.allow_foreign_elf // []) | add | unique | join(",")),
      exclude_build_deps: (map(.exclude_build_deps // []) | add | unique | join(","))
    }
    # Every build runs in an aarch64 container, so every build wants a native
    # aarch64 runner. ubuntu-24.04-arm is free for public repos, which makes
    # emulating aarch64 on an x86 runner strictly worse: same result, plus
    # qemu. Category no longer affects the runner; phase 3 only has to add
    # "compile" to CATEGORIES.
    + { runs_on: "ubuntu-24.04-arm" })
  | {include: .}
' <<<'null')"

n_pkgs="$(wc -l < "$work/needs-update.txt" | tr -d ' ')"
n_jobs="$(jq '.include | length' <<<"$matrix")"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "matrix=$matrix"          >> "$GITHUB_OUTPUT"
  echo "has_updates=$([[ "$n_jobs" -gt 0 ]] && echo true || echo false)" >> "$GITHUB_OUTPUT"
  echo "packages=$(paste -sd, "$work/needs-update.txt")" >> "$GITHUB_OUTPUT"
fi

if [[ "$n_jobs" -eq 0 ]]; then
  log "Everything in scope is current — nothing to build."
else
  log "$n_pkgs package(s) to update across $n_jobs build job(s):"
  jq -r '.include[] | "    \(.pkgbase) [\(.category)] -> \(.pkgnames)"' <<<"$matrix" >&2
fi
exit $status
