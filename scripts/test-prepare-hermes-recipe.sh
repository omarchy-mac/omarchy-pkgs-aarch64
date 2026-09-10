#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
prepare_script="$PWD/scripts/prepare-hermes-recipe.sh"
patch_path="$PWD/patches/hermes-desktop-aarch64.patch"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/recipes/pkgbuilds/hermes-desktop"
git -C "$work/recipes" init -q
recipe="$work/recipes/pkgbuilds/hermes-desktop/PKGBUILD"

# Minimal executable recipe: exercise package() with both Electron layouts,
# without downloading Electron or running an npm build in the offline suite.
cat > "$recipe" <<'RECIPE'
pkgname=hermes-desktop
pkgver=2026.8.31
pkgrel=3
pkgdesc='Native desktop shell for Hermes Agent'
arch=('x86_64')
url='https://github.com/NousResearch/hermes-agent'
license=('MIT')
_srcdir="hermes-agent-${pkgver}"
check() {
  :
}

package() {
  cd "${srcdir}/${_srcdir}/apps/desktop/release/linux-unpacked"

  install -dm755 "${pkgdir}/opt/${pkgname}"
  cp -a . "${pkgdir}/opt/${pkgname}/"
}
RECIPE
cp "$recipe" "$work/original"
bash "$prepare_script" "$work/recipes"
cp "$recipe" "$work/applied"
bash "$prepare_script" "$work/recipes"
cmp "$recipe" "$work/applied"
git -C "$work/recipes" apply --reverse --check "$patch_path"

(
  source "$recipe"
  [[ " ${arch[*]} " == *' aarch64 '* ]]
  [[ "$pkgver-$pkgrel" == 2026.8.31-3 ]]
  for layout in linux-unpacked linux-arm64-unpacked; do
    srcdir="$work/$layout/src"
    pkgdir="$work/$layout/pkg"
    mkdir -p "$srcdir/$_srcdir/apps/desktop/release/$layout"
    printf 'Electron payload\n' > "$srcdir/$_srcdir/apps/desktop/release/$layout/Hermes"
    ( package )
    cmp "$srcdir/$_srcdir/apps/desktop/release/$layout/Hermes" "$pkgdir/opt/hermes-desktop/Hermes"
  done
)

# Neither a future pkgrel nor a pkgver bump should conflict with the patch.
for state in original applied; do
  sed -e 's/pkgver=2026.8.31/pkgver=2026.9.9/' -e 's/pkgrel=3/pkgrel=4/' \
    "$work/$state" > "$recipe"
  bash "$prepare_script" "$work/recipes"
  ( source "$recipe"; [[ "$pkgver-$pkgrel" == 2026.9.9-4 ]] )
done

# A partial upstream fix or changed output layout must fail before any write.
for state in partial conflict; do
  cp "$work/original" "$recipe"
  if [[ "$state" == partial ]]; then
    sed -i "s/arch=('x86_64')/arch=('x86_64' 'aarch64')/" "$recipe"
  else
    sed -i 's@release/linux-unpacked@release/new-layout@' "$recipe"
  fi
  cp "$recipe" "$work/before"
  if bash "$prepare_script" "$work/recipes" > "$work/error" 2>&1; then
    echo "Error: $state recipe unexpectedly accepted" >&2
    exit 1
  fi
  grep -q 'upstream recipe changed' "$work/error"
  cmp "$recipe" "$work/before"
done
