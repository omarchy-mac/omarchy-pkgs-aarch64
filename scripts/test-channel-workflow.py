#!/usr/bin/python3
from pathlib import Path
import subprocess
import yaml

root = Path(__file__).resolve().parent.parent
workflow = yaml.load((root / '.github/workflows/channels.yml').read_text(), Loader=yaml.BaseLoader)
assert set(workflow['on']) == {'workflow_dispatch'}
assert workflow['concurrency'] == {'group': 'channel-publish', 'cancel-in-progress': 'false'}
assert workflow['permissions'] == {'contents': 'read'}
build, publish = workflow['jobs']['build'], workflow['jobs']['publish']
assert build['if'] == "inputs.operation == 'build'"
assert publish['permissions']['contents'] == 'write'
for job in (build, publish):
    assert job['runs-on'] == 'ubuntu-24.04-arm'
    for step in job['steps']:
        if step.get('uses', '').startswith('actions/checkout@'):
            assert step['with']['persist-credentials'] == 'false'
        if 'run' in step:
            result = subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True)
            assert result.returncode == 0, result.stderr
build_text = str(build)
publish_text = str(publish)
assert 'channel-snapshot.py publish' not in build_text
assert 'build-channel.sh' not in publish_text
assert 'channel-snapshot.py promote' in publish_text
assert 'ARTIFACT_RUN' in publish_text and 'gh run download' in publish_text
assert 'channel-$source_channel' in publish_text
assert 'SOURCE_MANIFEST_SHA256' in publish_text and 'sha256sum -c -' in publish_text
assert '.conclusion == "success"' in publish_text and '.publisher_sha' in publish_text
assert 'publish-signed' in workflow['on']['workflow_dispatch']['inputs']['operation']['options']
assert 'signed_artifact_tag' in workflow['on']['workflow_dispatch']['inputs']
assert 'SIGNED_ARTIFACT_SHA256' in publish_text and 'channel-signatures.py unpack' in publish_text
assert 'signing/public-keyring.gpg' in publish_text and 'signing/approved-signers.json' in publish_text
assert '--manifest-sha256' in publish_text and '--archive-sha256' in publish_text
assert '--repo "$GH_REPO" --pattern "$SIGNED_ARTIFACT_NAME"' in publish_text
for step in publish['steps']:
    script = step.get('run', '')
    if 'channel-snapshot.py publish' in script:
        assert 'publish --snapshot snapshot --repo "$GH_REPO" "${policy[@]}"' in script
        assert 'promote --snapshot source-snapshot --channel "$CHANNEL" --output snapshot "${policy[@]}"' in script
print('channel workflow validation PASS')
