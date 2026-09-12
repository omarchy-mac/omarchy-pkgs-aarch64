#!/usr/bin/env bash
# The omarchy-pkgs 0.2.1 recipe pins RUSTUP_TOOLCHAIN=nightly. ALARM has
# rust 1.98, and the -git package this repo already shipped builds with
# stable. Rewrite the pin before makepkg. Fail if the recipe no longer
# has a toolchain pin we recognise, so a future upstream change is not
# silently ignored.
set -euo pipefail

recipe_root=${1:?Usage: prepare-share-picker-recipe.sh PACKAGE_REPOSITORY}
pkgbuild="$recipe_root/pkgbuilds/hyprland-preview-share-picker/PKGBUILD"
[[ -f "$pkgbuild" ]] || { echo "Error: no $pkgbuild" >&2; exit 1; }

if grep -q 'RUSTUP_TOOLCHAIN=nightly' "$pkgbuild"; then
  sed -i 's/RUSTUP_TOOLCHAIN=nightly/RUSTUP_TOOLCHAIN=stable/g' "$pkgbuild"
  echo 'Pinned hyprland-preview-share-picker to the stable Rust toolchain'
elif grep -q 'RUSTUP_TOOLCHAIN=stable' "$pkgbuild"; then
  echo 'hyprland-preview-share-picker already uses the stable Rust toolchain'
else
  echo 'Error: upstream recipe no longer pins RUSTUP_TOOLCHAIN; review before building' >&2
  exit 1
fi
