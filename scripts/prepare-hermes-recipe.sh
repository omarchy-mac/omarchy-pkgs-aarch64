#!/usr/bin/env bash
# Carry the ARM fixes from omacom/omarchy-pkgs#373 until upstream has them.
# Keep upstream's version: detection compares the unpatched recipe to our db.
set -euo pipefail

recipe_root=${1:?Usage: prepare-hermes-recipe.sh PACKAGE_REPOSITORY}
patch_path=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../patches" && pwd)/hermes-desktop-aarch64.patch

if git -C "$recipe_root" apply --check "$patch_path" 2>/dev/null; then
  git -C "$recipe_root" apply "$patch_path"
  echo 'Applied Hermes ARM package fixes (upstream PR #373)'
elif git -C "$recipe_root" apply --reverse --check "$patch_path" 2>/dev/null; then
  echo 'Hermes ARM package fixes already present'
else
  echo 'Error: upstream recipe changed; review the Hermes ARM package patch before building' >&2
  exit 1
fi
