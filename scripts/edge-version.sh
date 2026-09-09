#!/bin/bash
# Evaluate the pinned development recipe functions exactly as the source build does.
set -euo pipefail
source_root=$(realpath "$1")
recipe_root=$(realpath "$2")
srcdir=$(mktemp -d)
trap 'rm -rf "$srcdir"' EXIT
ln -s "$source_root" "$srcdir/omarchy"
versions=()
for package in omarchy-dev omarchy-settings-dev; do
  version=$(
    set -e
    CARCH=aarch64
    source "$recipe_root/pkgbuilds/$package/PKGBUILD"
    _pkgver_base=$(tr -d '[:space:]' < "$source_root/version")
    pkgver
  )
  versions+=("$version")
done
[[ ${versions[0]} == "${versions[1]}" ]] || { echo 'Recipe package versions differ' >&2; exit 1; }
printf '%s\n' "${versions[0]}"
