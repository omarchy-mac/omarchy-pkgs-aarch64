#!/bin/bash
# Carry omacom/omarchy-pkgs#341 and restore the Mac zram package contract.
set -euo pipefail

recipe_root=${1:?Usage: prepare-omarchy-recipes.sh PACKAGE_REPOSITORY}
patch_path=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../patches" && pwd)/omarchy-first-run-packages.patch

# Check the entire patch before writing. Unknown/partially applied upstream
# changes require review instead of silently building without a required fix.
if git -C "$recipe_root" apply --check "$patch_path" 2>/dev/null; then
  git -C "$recipe_root" apply "$patch_path"
  echo 'Applied ARM first-run and zram package fixes'
elif git -C "$recipe_root" apply --reverse --check "$patch_path" 2>/dev/null; then
  echo 'ARM first-run and zram package fixes already present'
else
  echo 'Error: upstream recipes changed; review the ARM package patch before building' >&2
  exit 1
fi
