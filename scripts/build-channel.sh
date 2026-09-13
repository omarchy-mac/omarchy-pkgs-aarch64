#!/bin/bash
# Run inside a disposable ARM build container; never on the installed desktop.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${CHANNEL:?stable, rc or edge}"
: "${SOURCE_SHA:?exact desktop source commit}"
: "${RECIPE_SHA:?exact package-recipe commit}"
: "${BASE_TAG:?existing complete channel release, or legacy edge for bootstrap}"
: "${GH_REPO:?publisher owner/repository}"
case "$CHANNEL" in stable|rc|edge) ;; *) echo 'Invalid channel' >&2; exit 1 ;; esac
case "$BASE_TAG" in edge|channel-stable|channel-rc|channel-edge) ;; *) echo 'Invalid baseline release' >&2; exit 1 ;; esac
for commit in "$SOURCE_SHA" "$RECIPE_SHA"; do
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo 'Source and recipes require full commit SHAs' >&2; exit 1; }
done
[[ $(uname -m) == "aarch64" && $EUID == 0 && -e /.dockerenv ]] || { echo 'Use a disposable ARM Docker container' >&2; exit 1; }
readonly workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT
readonly output="${CHANNEL_OUTPUT:-$PWD/channel-output}"
[[ ! -e $output ]] || { echo 'Output already exists' >&2; exit 1; }

bash scripts/container-bootstrap.sh build >/dev/null
publisher_sha=$(git -c safe.directory="$PWD" rev-parse HEAD)
[[ $publisher_sha =~ ^[0-9a-f]{40}$ ]] || { echo 'Cannot resolve publisher commit' >&2; exit 1; }
readonly publisher_sha
pacman -S --needed --noconfirm sudo python gnupg curl libarchive pacman-contrib >/dev/null
# Both source trees are pinned before package code runs. No source tag is required.
git clone "https://github.com/${SOURCE_REPO:-omarchy-mac/omarchy-mac}.git" "$workspace/source"
git -C "$workspace/source" checkout --detach "$SOURCE_SHA"
git clone "https://github.com/${RECIPE_REPO:-omacom/omarchy-pkgs}.git" "$workspace/recipes"
git -C "$workspace/recipes" checkout --detach "$RECIPE_SHA"
bash scripts/prepare-omarchy-recipes.sh "$workspace/recipes"
useradd -m builder
printf 'builder ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/builder
chmod 0440 /etc/sudoers.d/builder
mkdir -p "$workspace/built" "$workspace/cache"
chown -R builder:builder "$workspace"
chmod 755 "$workspace"
runuser -u builder -- env OMARCHY_PACKAGE_CHANNEL="$CHANNEL" OMARCHY_PKGREL="${PKGREL:-1}" \
  OMARCHY_PKGS_PATH="$workspace/recipes" OMARCHY_PACKAGE_OUTPUT="$workspace/built" \
  OMARCHY_PACKAGE_SRCDEST="$workspace/cache" bash "$workspace/source/build-packages.sh"

# Resolve the selected stack plus its missing dependencies against the current
# ARM base. Capturing those archives includes e.g. an Aquamarine ABI provider
# from ALARM, not just the three explicit Omarchy packages.
mkdir -p "$workspace/db/sync"
: > "$workspace/import-plan"
if [[ $CHANNEL == "edge" || $BASE_TAG == "edge" ]]; then
  cp /etc/pacman.conf "$workspace/pacman.conf"
  cat >> "$workspace/pacman.conf" <<'REPO'
  
  [omarchy]
  Usage = Sync
  SigLevel = Required DatabaseOptional
  Server = https://pkgs.omarchy.org/edge/$arch
REPO
  pacman-key --recv-keys 40DFB630FF42BCFFB047046CF0134EE680CAC571 --keyserver hkps://keys.openpgp.org
  pacman-key --lsign-key 40DFB630FF42BCFFB047046CF0134EE680CAC571
  cp -a /var/lib/pacman/local "$workspace/db/local"
  pacman --config "$workspace/pacman.conf" --dbpath "$workspace/db" -Sy --noconfirm
  pacman --config "$workspace/pacman.conf" --dbpath "$workspace/db" -Sp --print-format '%r|%n|%v|%l' \
    omarchy/hyprland omarchy/hyprtoolkit omarchy/hyprland-guiutils > "$workspace/import-plan"
else
  # RC/final builds inherit the already frozen dependency snapshot. Rebuilding
  # the final desktop version must not silently refresh its tested libraries.
  pacman-key --recv-keys 40DFB630FF42BCFFB047046CF0134EE680CAC571 --keyserver hkps://keys.openpgp.org
  pacman-key --lsign-key 40DFB630FF42BCFFB047046CF0134EE680CAC571
fi
base_url="https://github.com/$GH_REPO/releases/download/$BASE_TAG"
curl --fail --location --retry 3 "$base_url/omarchy-aarch64.db.tar.zst" -o "$workspace/base.db"
python3 scripts/collect-channel.py --base-url "$base_url" --base-db "$workspace/base.db" \
  --import-plan "$workspace/import-plan" --sync-db-dir "$workspace/db/sync" \
  --overlay "$workspace/built" --channel "$CHANNEL" --output "$workspace/collected"
python3 scripts/channel-snapshot.py prepare --packages "$workspace/collected" --channel "$CHANNEL" \
  --inventory "$workspace/collected/inventory.json" --signed-inventory "$workspace/collected/signed-inventory.json" \
  --source-sha "$SOURCE_SHA" --recipe-sha "$RECIPE_SHA" --publisher-sha "$publisher_sha" --output "$output"
pacman -Q > "$output/build-base-packages.txt"
