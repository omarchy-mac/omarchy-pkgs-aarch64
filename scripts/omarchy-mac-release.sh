#!/usr/bin/env bash
# Detect and validate releases of the two fork-owned Omarchy Mac packages.
#
#   GH_REPO=owner/package-repo scripts/omarchy-mac-release.sh detect
#   RELEASE_TAG=v4.0.2-1 SOURCE_DIR=... PKGDIR=... STAGING_DIR=... \
#     scripts/omarchy-mac-release.sh verify
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/common.sh

SOURCE_REPO="${SOURCE_REPO:-omarchy-mac/omarchy-mac}"

# Release tags are either v<pkgver> or v<pkgver>-<pkgrel>. Omarchy prereleases
# use the attached form (4.1.0rc1), matching pacman's version ordering.
parse_release_tag() {
  local tag="$1"
  if [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+(rc[0-9]+)?)(-([1-9][0-9]*))?$ ]]; then
    RELEASE_PKGVER="${BASH_REMATCH[1]}"
    RELEASE_PKGREL="${BASH_REMATCH[4]:-1}"
    RELEASE_VERSION="$RELEASE_PKGVER-$RELEASE_PKGREL"
  else
    die "release tag '$tag' must be v<pkgver> or v<pkgver>-<pkgrel>"
  fi
}

output() {
  [[ -n "${GITHUB_OUTPUT:-}" ]] && printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
}

detect() {
  : "${GH_REPO:?GH_REPO must be set (owner/package-repo)}"

  local tag="${RELEASE_TAG:-}"
  if [[ -z "$tag" ]]; then
    tag="$(gh release view --repo "$SOURCE_REPO" --json tagName --jq .tagName)"
  fi
  [[ -n "$tag" ]] || die "could not resolve the latest release from $SOURCE_REPO"
  parse_release_tag "$tag"

  local work published_omarchy published_settings comparison has_update=false
  work="$(mktemp -d)"
  trap '[[ -z "${work:-}" ]] || rm -rf "$work"' EXIT
  fetch_current_dbs "$work"
  db_versions "$work/$DB_NAME.db.tar.zst" > "$work/versions.tsv"
  published_omarchy="$(awk -F'\t' '$1 == "omarchy" {print $2}' "$work/versions.tsv")"
  published_settings="$(awk -F'\t' '$1 == "omarchy-settings" {print $2}' "$work/versions.tsv")"

  for comparison in "$published_omarchy" "$published_settings"; do
    if [[ -z "$comparison" ]] || (( $(vercmp "$RELEASE_VERSION" "$comparison") > 0 )); then
      has_update=true
    elif (( $(vercmp "$RELEASE_VERSION" "$comparison") < 0 )); then
      die "release $tag maps to $RELEASE_VERSION, older than published $comparison"
    fi
  done

  log "Omarchy Mac $tag -> package version $RELEASE_VERSION"
  log "Published: omarchy=${published_omarchy:-missing}, omarchy-settings=${published_settings:-missing}"
  output release_tag "$tag"
  output pkgver "$RELEASE_PKGVER"
  output pkgrel "$RELEASE_PKGREL"
  output version "$RELEASE_VERSION"
  output has_update "$has_update"
}

pkginfo_field() {
  local pkg="$1" field="$2"
  bsdtar -xOqf "$pkg" .PKGINFO 2>/dev/null \
    | awk -F' = ' -v field="$field" '$1 == field {print $2}'
}

find_package() {
  local dir="$1" wanted="$2" pkg found=()
  shopt -s nullglob
  for pkg in "$dir"/*.pkg.tar.*; do
    [[ "$(artifact_pkgname "$pkg")" == "$wanted" ]] && found+=("$pkg")
  done
  (( ${#found[@]} == 1 )) \
    || die "expected one $wanted artifact in $dir, found ${#found[@]}"
  printf '%s' "${found[0]}"
}

assert_absent_path() {
  local pkg="$1" path="$2"
  if bsdtar -tf "$pkg" | sed 's#^\./##' \
    | awk -v path="$path" '$0 == path || index($0, path "/") == 1 { found=1 } END { exit !found }'; then
    die "$(basename "$pkg") contains forbidden aarch64 path: $path"
  fi
}

verify() {
  : "${RELEASE_TAG:?RELEASE_TAG must be set}"
  : "${SOURCE_DIR:?SOURCE_DIR must be set}"
  : "${PKGDIR:?PKGDIR must be set}"
  : "${STAGING_DIR:?STAGING_DIR must be set}"
  parse_release_tag "$RELEASE_TAG"

  [[ -f "$SOURCE_DIR/version" ]] || die "$SOURCE_DIR has no version file"
  local source_version
  source_version="$(tr -d '[:space:]' < "$SOURCE_DIR/version")"
  [[ "$source_version" == "$RELEASE_PKGVER" ]] \
    || die "$RELEASE_TAG says pkgver $RELEASE_PKGVER but source version is $source_version"

  local omarchy settings pkg name version arch depend
  omarchy="$(find_package "$PKGDIR" omarchy)"
  settings="$(find_package "$PKGDIR" omarchy-settings)"

  for pkg in "$omarchy" "$settings"; do
    name="$(pkginfo_field "$pkg" pkgname)"
    version="$(pkginfo_field "$pkg" pkgver)"
    arch="$(pkginfo_field "$pkg" arch)"
    [[ "$version" == "$RELEASE_VERSION" ]] \
      || die "$name built as $version, expected $RELEASE_VERSION from $RELEASE_TAG"
    [[ "$arch" == "aarch64" ]] \
      || die "$name built for $arch, expected aarch64"
  done

  while IFS= read -r depend; do
    case "$depend" in
      limine|limine-mkinitcpio-hook|limine-snapper-sync|snapper)
        die "omarchy aarch64 package has x86 boot dependency: $depend" ;;
    esac
  done < <(pkginfo_field "$omarchy" depend)

  pkginfo_field "$omarchy" depend | grep -Fxq "omarchy-settings=$RELEASE_PKGVER" \
    || die "omarchy does not pin omarchy-settings=$RELEASE_PKGVER"
  pkginfo_field "$omarchy" depend | grep -Fxq iwd \
    || die "omarchy aarch64 package does not depend on iwd"
  pkginfo_field "$omarchy" depend | grep -Fxq networkmanager \
    || die "omarchy aarch64 package does not depend on networkmanager"

  # These are x86 Limine/memory-stack defaults. Shipping any of them on ARM
  # can alter the next initramfs or enable services that Apple Silicon lacks.
  assert_absent_path "$settings" etc/limine-entry-tool.d
  assert_absent_path "$settings" etc/mkinitcpio.conf.d
  assert_absent_path "$settings" usr/share/omarchy/default/limine
  assert_absent_path "$settings" etc/systemd/oomd.conf.d
  assert_absent_path "$settings" etc/systemd/zram-generator.conf

  bsdtar -tf "$omarchy" | sed 's#^\./##' \
    | grep -Fxq usr/share/omarchy/install/helpers/arm-package-sources.sh \
    || die "omarchy package is missing the ARM package-sources policy"

  mkdir -p "$STAGING_DIR"
  find "$STAGING_DIR" -maxdepth 1 -type f -name '*.pkg.tar.*' -delete
  cp "$omarchy" "$settings" "$STAGING_DIR/"
  log "Verified and staged the atomic package pair for $RELEASE_TAG"
  printf '    %s\n' "$STAGING_DIR"/*.pkg.tar.* >&2
}

main() {
  case "${1:-}" in
    detect) detect ;;
    verify) verify ;;
    *) die "usage: $0 detect|verify" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
