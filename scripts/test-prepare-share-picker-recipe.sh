#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
prepare_script="$PWD/scripts/prepare-share-picker-recipe.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
recipe_dir="$work/recipes/pkgbuilds/hyprland-preview-share-picker"
mkdir -p "$recipe_dir"
pkgbuild="$recipe_dir/PKGBUILD"

cat > "$pkgbuild" <<'RECIPE'
pkgname=hyprland-preview-share-picker
pkgver=0.2.1
pkgrel=1
prepare() {
    export RUSTUP_TOOLCHAIN=nightly
    cargo fetch --locked
}
build() {
    export RUSTUP_TOOLCHAIN=nightly
    cargo build --frozen --release
}
RECIPE
cp "$pkgbuild" "$work/original"

bash "$prepare_script" "$work/recipes"
grep -q 'RUSTUP_TOOLCHAIN=stable' "$pkgbuild"
! grep -q 'RUSTUP_TOOLCHAIN=nightly' "$pkgbuild"
cp "$pkgbuild" "$work/applied"

# Idempotent once rewritten.
bash "$prepare_script" "$work/recipes"
cmp "$pkgbuild" "$work/applied"

# Already-stable upstream is accepted without rewriting anything else.
cp "$work/applied" "$pkgbuild"
bash "$prepare_script" "$work/recipes"
cmp "$pkgbuild" "$work/applied"

# A recipe with no toolchain pin must fail before any write.
cp "$work/original" "$pkgbuild"
sed -i '/RUSTUP_TOOLCHAIN/d' "$pkgbuild"
cp "$pkgbuild" "$work/before"
if bash "$prepare_script" "$work/recipes" > "$work/error" 2>&1; then
  echo 'Error: pinless recipe unexpectedly accepted' >&2
  exit 1
fi
grep -q 'no longer pins RUSTUP_TOOLCHAIN' "$work/error"
cmp "$pkgbuild" "$work/before"
