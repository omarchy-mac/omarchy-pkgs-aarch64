#!/bin/bash
# Read-only remote capture/build. Run only inside a disposable native ARM container.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ $(uname -m) == "aarch64" && $EUID == 0 && -e /.dockerenv ]] || { echo 'Disposable ARM Docker container required' >&2; exit 1; }
: "${GH_REPO:?publisher repository}"
SOURCE_REPO=${SOURCE_REPO:-omacom/omarchy-mac}
SOURCE_BRANCH=${SOURCE_BRANCH:-quattro}
RECIPE_REPO=${RECIPE_REPO:-omacom/omarchy-pkgs}
RECIPE_BRANCH=${RECIPE_BRANCH:-master}
for repo in "$GH_REPO" "$SOURCE_REPO" "$RECIPE_REPO"; do
  [[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || exit 1
done
bash scripts/container-bootstrap.sh build >/dev/null
pacman -S --needed --noconfirm sudo python python-yaml gnupg curl libarchive pacman-contrib >/dev/null
bash scripts/self-test.sh
publisher_sha=$(git -c safe.directory="$PWD" rev-parse HEAD)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
output=${EDGE_OUTPUT:-$PWD/edge-output}
[[ ! -e $output ]] || { echo 'Output exists' >&2; exit 1; }
mkdir -p "$output" "$work/db/sync" "$work/empty"
base_url="https://github.com/$GH_REPO/releases/download/channel-edge"
# An existing functional edge release is mandatory; no legacy/stable fallback.
curl -fL --retry 3 "$base_url/channel-manifest.json" -o "$output/baseline.json"
curl -fL --retry 3 "$base_url/omarchy-aarch64.db.tar.zst" -o "$work/base.db"
overlay_url="https://github.com/$GH_REPO/releases/download/edge"
curl -fL --retry 3 "$overlay_url/omarchy-aarch64.db.tar.zst" -o "$work/overlay.db"
for kind in source recipe; do
  if [[ $kind == "source" ]]; then repo=$SOURCE_REPO; branch=$SOURCE_BRANCH; else repo=$RECIPE_REPO; branch=$RECIPE_BRANCH; fi
  git check-ref-format "refs/heads/$branch"
  commit=$(git ls-remote "https://github.com/$repo.git" "refs/heads/$branch" | cut -f1)
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo 'Branch did not resolve to one immutable SHA' >&2; exit 1; }
  git clone --no-checkout "https://github.com/$repo.git" "$work/$kind"
  git -C "$work/$kind" checkout --detach "$commit"
done
jq -n --arg source_repo "$SOURCE_REPO" --arg source_branch "$SOURCE_BRANCH" --arg recipe_repo "$RECIPE_REPO" --arg recipe_branch "$RECIPE_BRANCH" \
  '{source_repo:$source_repo,source_branch:$source_branch,recipe_repo:$recipe_repo,recipe_branch:$recipe_branch}' > "$output/remotes.json"
source_sha=$(git -C "$work/source" rev-parse HEAD)
recipe_sha=$(git -C "$work/recipe" rev-parse HEAD)
bash scripts/prepare-omarchy-recipes.sh "$work/recipe"
useradd -m builder
printf 'builder ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/builder
chmod 0440 /etc/sudoers.d/builder
chmod 755 "$work"
chown -R builder:builder "$work/source" "$work/recipe"
# Evaluate the pinned recipes' own version functions, using the identical source
# version override and full Git history used by build-packages.sh.
pkgver=$(runuser -u builder -- bash scripts/edge-version.sh "$work/source" "$work/recipe")
pacman-key --recv-keys 40DFB630FF42BCFFB047046CF0134EE680CAC571 --keyserver hkps://keys.openpgp.org
pacman-key --lsign-key 40DFB630FF42BCFFB047046CF0134EE680CAC571
cp /etc/pacman.conf "$work/pacman.conf"
cat >> "$work/pacman.conf" <<'REPO'

[omarchy]
Usage = Sync
SigLevel = Required DatabaseOptional
Server = https://pkgs.omarchy.org/edge/$arch
REPO
# Empty local DB resolves the complete selected stack dependency closure,
# independent of which libraries happen to be installed in the builder image.
mkdir "$work/db/local"
pacman --config "$work/pacman.conf" --dbpath "$work/db" -Sy --noconfirm
pacman --config "$work/pacman.conf" --dbpath "$work/db" -Sp --print-format '%r|%n|%v|%l' \
  omarchy/hyprland omarchy/hyprtoolkit omarchy/hyprland-guiutils > "$work/import-plan"
python3 scripts/collect-channel.py --base-url "$base_url" --base-db "$work/base.db" \
  --import-plan "$work/import-plan" --sync-db-dir "$work/db/sync" --overlay "$work/empty" \
  --overlay-db "$work/overlay.db" --overlay-url "$overlay_url" \
  --output "$work/captured" --channel edge --reuse-edge-manifest "$output/baseline.json" \
  --source-sha "$(jq -r .source_sha "$output/baseline.json")" --recipe-sha "$(jq -r .recipe_sha "$output/baseline.json")"
python3 - "$work/captured" "$source_sha" "$recipe_sha" "$publisher_sha" "$pkgver" > "$output/desired.json" <<'PY'
import importlib.util, json, pathlib, sys
spec = importlib.util.spec_from_file_location('snapshot', 'scripts/channel-snapshot.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
packages = [m.inspect_package(p) for p in sorted(pathlib.Path(sys.argv[1]).glob('*.pkg.tar.*')) if not p.name.endswith('.sig')]
print(json.dumps(dict(source_sha=sys.argv[2], recipe_sha=sys.argv[3], publisher_sha=sys.argv[4], pkgver=sys.argv[5], packages=packages)))
PY
python3 scripts/edge-plan.py --baseline "$output/baseline.json" --desired "$output/desired.json" > "$output/plan.json"
action=$(jq -r .action "$output/plan.json")
if [[ $action == "skip" ]]; then exit 0; fi
if [[ $action == "build" ]]; then
  mkdir "$work/built" "$work/cache"
  chown builder:builder "$work/built" "$work/cache"
  runuser -u builder -- env OMARCHY_PACKAGE_CHANNEL=edge OMARCHY_PKGREL="$(jq -r .pkgrel "$output/plan.json")" \
    OMARCHY_PKGS_PATH="$work/recipe" OMARCHY_PACKAGE_OUTPUT="$work/built" OMARCHY_PACKAGE_SRCDEST="$work/cache" \
    bash "$work/source/build-packages.sh"
  # Keep unchanged ancillary identities byte-for-byte, but carry deliberately
  # versioned recipe updates and rebind the plan to their actual archive hashes.
  python3 - "$work/built" "$work/captured" "$output/desired.json" <<'PYINNER'
import importlib.util, json, pathlib, shutil, subprocess, sys
spec = importlib.util.spec_from_file_location('snapshot', 'scripts/channel-snapshot.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
built, captured, desired_path = map(pathlib.Path, sys.argv[1:])
desired = json.loads(desired_path.read_text())
rows = {row['name']: row for row in desired['packages']}
signed_path = captured / 'signed-inventory.json'
signed = set(json.loads(signed_path.read_text()))
for archive in built.glob('*.pkg.tar.*'):
    if archive.name.endswith('.sig'): continue
    row = m.inspect_package(archive)
    if row['name'] in m.PAIRS: continue
    previous = rows.get(row['name'])
    if previous and previous['version'] == row['version']: continue
    if previous:
        assert int(subprocess.run(['vercmp', row['version'], previous['version']], check=True, capture_output=True, text=True).stdout) >= 0, 'Recipe ancillary downgrade requires review'
        (captured / previous['filename']).unlink()
        (captured / (previous['filename'] + '.sig')).unlink(missing_ok=True)
    shutil.copy2(archive, captured / archive.name)
    signed.discard(row['name'])
    if 'signature_sha256' in row:
        shutil.copy2(str(archive) + '.sig', captured / (archive.name + '.sig'))
        signed.add(row['name'])
    rows[row['name']] = row
signed_path.write_text(json.dumps(sorted(signed)))
(captured / 'inventory.json').write_text(json.dumps(sorted(set(rows) - m.PAIRS)))
desired['packages'] = list(rows.values()); desired_path.write_text(json.dumps(desired))
PYINNER
  python3 scripts/edge-plan.py --baseline "$output/baseline.json" --desired "$output/desired.json" > "$output/plan.json"
  # Replace only the selected desktop pair after dependency inputs are frozen.
  rm "$work/captured/omarchy-dev-"*.pkg.tar.* "$work/captured/omarchy-settings-dev-"*.pkg.tar.*
  cp "$work/built/omarchy-dev-"*.pkg.tar.* "$work/built/omarchy-settings-dev-"*.pkg.tar.* "$work/captured/"
  python3 - "$work/captured/input-provenance.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); data = json.loads(p.read_text())
for key in ('desktop_build', 'reused_from_manifest_sha256'): data.pop(key, None)
p.write_text(json.dumps(data))
PY
  # Rebuilt pair may be unsigned even if its predecessor carried signatures.
  python3 - "$work/captured/signed-inventory.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); p.write_text(json.dumps([n for n in json.loads(p.read_text()) if n not in ('omarchy-dev', 'omarchy-settings-dev')]))
PY
fi
python3 scripts/channel-snapshot.py prepare --packages "$work/captured" --channel edge \
  --inventory "$work/captured/inventory.json" --signed-inventory "$work/captured/signed-inventory.json" \
  --source-sha "$source_sha" --recipe-sha "$recipe_sha" --publisher-sha "$publisher_sha" --output "$output/snapshot"
python3 scripts/edge-execution.py --plan "$output/plan.json" --baseline "$output/baseline.json" --snapshot "$output/snapshot"
pacman -Q > "$output/build-base-packages.txt"
