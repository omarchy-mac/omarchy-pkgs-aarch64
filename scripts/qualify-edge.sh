#!/bin/bash
# Install the exact candidate in a NEW disposable ARM container, never the build container.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ $(uname -m) == "aarch64" && $EUID == 0 && -e /.dockerenv ]] || { echo 'Disposable ARM Docker container required' >&2; exit 1; }
: "${EDGE_CANDIDATE:?read-only candidate directory}"
: "${EDGE_EVIDENCE:?writable evidence directory}"
mkdir -p "$EDGE_EVIDENCE"
exec > >(tee "$EDGE_EVIDENCE/install.log") 2>&1
bash scripts/container-bootstrap.sh build
pacman -S --needed --noconfirm python gnupg libarchive pacman-contrib curl >/dev/null
pacman-key --recv-keys 40DFB630FF42BCFFB047046CF0134EE680CAC571 --keyserver hkps://keys.openpgp.org
pacman-key --lsign-key 40DFB630FF42BCFFB047046CF0134EE680CAC571
python3 scripts/edge-execution.py --plan "$EDGE_CANDIDATE/plan.json" --baseline "$EDGE_CANDIDATE/baseline.json" --snapshot "$EDGE_CANDIDATE/snapshot"
python3 scripts/channel-snapshot.py verify --snapshot "$EDGE_CANDIDATE/snapshot"
pacman -Q > "$EDGE_EVIDENCE/base-before.txt"
# File repository first: dependency resolution cannot substitute official edge
# or a newer ALARM build for the selected managed stack.
python3 - "$EDGE_CANDIDATE/snapshot" <<'PY'
from pathlib import Path
import sys
p = Path('/etc/pacman.conf'); text = p.read_text()
position = text.index('[core]')
repo = '\n[omarchy-aarch64]\nSigLevel = Optional TrustAll\nServer = file://' + str(Path(sys.argv[1]).resolve()) + '\n\n'
p.write_text(text[:position] + repo + text[position:])
PY
pacman -Sy --noconfirm
mapfile -t archives < <(python3 - "$EDGE_CANDIDATE/snapshot" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for row in json.loads((root / 'channel-manifest.json').read_text())['packages']:
    if row['name'] in ('omarchy-dev', 'omarchy-settings-dev', 'hyprland', 'hyprtoolkit', 'hyprland-guiutils'):
        print(root / row['filename'])
PY
)
# The overlay includes mutually exclusive optional alternatives. Install the
# desktop pair and selected stack, letting the frozen repo resolve dependencies.
# No rebuilds, --nodeps, --dbonly, or global overwrite. Scriptlets and normal
# package transactions run; container cannot provide M2 session/hardware checks.
pacman -U --noconfirm "${archives[@]}"
pacman -Q > "$EDGE_EVIDENCE/installed.txt"
python3 - "$EDGE_CANDIDATE" "$EDGE_EVIDENCE" <<'PY'
import hashlib, json, pathlib, subprocess, sys
candidate, evidence = map(pathlib.Path, sys.argv[1:])
manifest_path = candidate / 'snapshot/channel-manifest.json'
manifest = json.loads(manifest_path.read_text())
required = {'omarchy-dev', 'omarchy-settings-dev', 'hyprland', 'hyprtoolkit', 'hyprland-guiutils'}
selected = []
for row in manifest['packages']:
    query = subprocess.run(['pacman', '-Q', row['name']], capture_output=True, text=True)
    if query.returncode:
        assert row['name'] not in required, 'Required selected archive was not installed'
        continue
    result = query.stdout.strip()
    assert result == row['name'] + ' ' + row['version'], 'Installed package differs from frozen archive: ' + result
    selected.append(row['name'])
subprocess.run(['pacman', '-Dk'], check=True)
report = dict(schema=1, selected_packages=selected, result='PASS', kind='fresh-container-archive-install', architecture='aarch64',
              manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
              plan_sha256=hashlib.sha256((candidate / 'plan.json').read_bytes()).hexdigest(),
              publisher_sha=manifest['publisher_sha'])
(evidence / 'qualification.json').write_text(json.dumps(report, indent=2))
PY
