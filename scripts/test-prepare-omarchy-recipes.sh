#!/bin/bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
patch_path="$PWD/patches/omarchy-first-run-packages.patch"
prepare_script="$PWD/scripts/prepare-omarchy-recipes.sh"
test_directory=$(mktemp -d)
trap 'rm -rf "$test_directory"' EXIT

# Reconstruct only the old-side context from the carried diff, not a second
# copy of upstream recipes that would need independent maintenance. This is
# an application/conflict fixture; real package staging is tested separately.
mkdir -p "$test_directory/recipes"
awk -v root="$test_directory/recipes" '
  /^--- a\// {
    path = substr($0, 7)
    directory = path
    sub(/\/[^/]+$/, "", directory)
    system("mkdir -p " root "/" directory)
    file = root "/" path
    next
  }
  /^diff --git/ || /^index / || /^\+\+\+/ || /^@@/ { next }
  /^[ -]/ { print substr($0, 2) > file }
' "$patch_path"
git -C "$test_directory/recipes" init -q
git -C "$test_directory/recipes" add pkgbuilds
bash "$prepare_script" "$test_directory/recipes"
git -C "$test_directory/recipes" diff >"$test_directory/once.patch"
[[ -s "$test_directory/once.patch" ]]
git -C "$test_directory/recipes" apply --reverse --check "$patch_path"
bash "$prepare_script" "$test_directory/recipes"
git -C "$test_directory/recipes" diff >"$test_directory/twice.patch"
cmp "$test_directory/once.patch" "$test_directory/twice.patch"

# Return this disposable fixture to its old form, then simulate an upstream
# recipe restructuring. Check that preparation refuses it without any writes.
git -C "$test_directory/recipes" apply --reverse "$patch_path"
sed -i 's/ttf-jetbrains-mono-nerd-basic/renamed-font/' "$test_directory/recipes/pkgbuilds/omarchy/PKGBUILD"
git -C "$test_directory/recipes" diff >"$test_directory/before-conflict.patch"
if bash "$prepare_script" "$test_directory/recipes" >"$test_directory/error" 2>&1; then
  echo 'Error: conflicting recipes unexpectedly accepted' >&2
  exit 1
fi
grep -q 'upstream recipes changed' "$test_directory/error"
git -C "$test_directory/recipes" diff >"$test_directory/after-conflict.patch"
cmp "$test_directory/before-conflict.patch" "$test_directory/after-conflict.patch"

# Check actual workflow structure so a comment cannot keep this guard green.
python3 - <<'PY'
import yaml
with open(".github/workflows/update-omarchy-mac.yml") as source:
    steps = yaml.safe_load(source)["jobs"]["build"]["steps"]
prepare = next(i for i, step in enumerate(steps)
               if step.get("run") == "bash scripts/prepare-omarchy-recipes.sh vendor/omarchy-pkgs")
checkout = next(i for i, step in enumerate(steps)
                if step.get("with", {}).get("path") == "vendor/omarchy-pkgs")
build = next(i for i, step in enumerate(steps)
             if "bash /w/vendor/omarchy-mac/build-packages.sh" in step.get("run", ""))
assert checkout < prepare < build
PY
