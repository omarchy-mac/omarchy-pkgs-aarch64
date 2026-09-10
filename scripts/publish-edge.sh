#!/bin/bash
# Called only by the write-permission job holding the shared channel-publish lock.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${GH_REPO:?publisher repository}"
: "${EDGE_CANDIDATE:?qualified candidate directory}"
: "${EDGE_EVIDENCE:?qualification directory}"
: "${EXPECTED_PUBLISHER_SHA:?workflow commit}"
: "${SIGNATURE_KEYRING:?explicit trusted public keyring}"
: "${APPROVED_SIGNERS:?explicit approved signer policy}"
# This is mandatory even after archive qualification; unsigned candidates are not publishable.
python3 scripts/channel-snapshot.py verify --snapshot "$EDGE_CANDIDATE/snapshot" --require-all-signatures --signature-keyring "$SIGNATURE_KEYRING" --approved-signers "$APPROVED_SIGNERS"
python3 scripts/edge-execution.py --plan "$EDGE_CANDIDATE/plan.json" --baseline "$EDGE_CANDIDATE/baseline.json" --snapshot "$EDGE_CANDIDATE/snapshot"
python3 - "$EDGE_CANDIDATE" "$EDGE_EVIDENCE" "$EXPECTED_PUBLISHER_SHA" <<'PY'
import hashlib, json, pathlib, sys
candidate, evidence = map(pathlib.Path, sys.argv[1:3])
report = json.loads((evidence / 'qualification.json').read_bytes())
manifest = json.loads((candidate / 'snapshot/channel-manifest.json').read_bytes())
assert manifest['channel'] == 'edge' and manifest['publisher_sha'] == sys.argv[3]
assert report['result'] == 'PASS' and report['kind'] == 'fresh-container-archive-install' and report['architecture'] == 'aarch64'
assert report['publisher_sha'] == sys.argv[3]
for key, path in [('manifest_sha256', candidate / 'snapshot/channel-manifest.json'), ('plan_sha256', candidate / 'plan.json')]:
    assert report[key] == hashlib.sha256(path.read_bytes()).hexdigest(), 'Qualification does not cover candidate bytes'
PY
current=$(mktemp)
trap 'rm -f "$current"' EXIT
curl -fL --retry 3 "https://github.com/$GH_REPO/releases/download/channel-edge/channel-manifest.json" -o "$current"
[[ $(sha256sum "$current" | cut -d' ' -f1) == "$(jq -r .baseline_manifest_sha256 "$EDGE_CANDIDATE/plan.json")" ]] || { echo 'Published edge baseline changed; retry capture and qualification' >&2; exit 1; }
python3 scripts/channel-snapshot.py publish --snapshot "$EDGE_CANDIDATE/snapshot" --repo "$GH_REPO" --signature-keyring "$SIGNATURE_KEYRING" --approved-signers "$APPROVED_SIGNERS"
