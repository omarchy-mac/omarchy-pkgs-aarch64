#!/usr/bin/python3
from pathlib import Path
import os
import subprocess
import tempfile
import yaml

root = Path(__file__).resolve().parent.parent
workflow = yaml.load((root / '.github/workflows/edge-follow.yml').read_text(), Loader=yaml.BaseLoader)
assert set(workflow['on']) == {'schedule', 'workflow_dispatch'}
assert workflow['permissions'] == {'contents': 'read'}
assert '@sha256:' in workflow['env']['ARM_IMAGE']
jobs = workflow['jobs']
assert jobs['publish']['permissions'] == {'contents': 'write'}
assert jobs['publish']['concurrency'] == {'group': 'channel-publish', 'cancel-in-progress': 'false'}
assert set(jobs['publish']['needs']) == {'prepare', 'source-tests', 'qualify'}
assert 'needs.qualify.result' in jobs['publish']['if']
assert 'needs.source-tests.result' in jobs['publish']['if']
for name, job in jobs.items():
    assert name == 'publish' or 'write' not in str(job.get('permissions', {}))
    for step in job['steps']:
        if step.get('uses', '').startswith('actions/checkout@'):
            assert step['with']['persist-credentials'] == 'false'
        if 'run' in step:
            result = subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True)
            assert result.returncode == 0, result.stderr
assert 'GH_TOKEN' not in str(jobs['prepare']) and 'GH_TOKEN' not in str(jobs['qualify'])
assert '$PWD:/w:ro' in str(jobs['qualify'])
assert 'prepare-omarchy-recipes.sh' in str(jobs['source-tests'])
assert '${{ github.sha }}' in str(jobs['source-tests'])
for name in ('edge-follow.sh', 'qualify-edge.sh', 'publish-edge.sh', 'edge-version.sh'):
    subprocess.run(['bash', '-n', str(root / 'scripts' / name)], check=True)
follow = (root / 'scripts/edge-follow.sh').read_text()
assert 'git ls-remote' in follow and 'checkout --detach' in follow
assert '--overlay-db' in follow and '/releases/download/edge' in follow
assert '--base' not in follow or '/releases/download/channel-edge' in follow
assert 'scripts/edge-execution.py' in follow
publish = (root / 'scripts/publish-edge.sh').read_text()
assert publish.index('baseline_manifest_sha256') < publish.index('channel-snapshot.py publish')
assert "manifest['channel'] == 'edge'" in publish
assert 'qualification.json' in publish and 'manifest_sha256' in publish
qualify = (root / 'scripts/qualify-edge.sh').read_text()
assert 'pacman -U --noconfirm "${archives[@]}"' in qualify
assert "['pacman', '-Dk']" in qualify
assert 'fresh-container-archive-install' in qualify
# Execute bootstrap with command fixtures: no package manager or host keyring writes.
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary); log = directory / 'commands'
    for command in ('pacman', 'pacman-key', 'git', 'jq', 'makepkg', 'bsdtar', 'file'):
        path = directory / command
        path.write_text('#!/bin/bash\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$BOOTSTRAP_LOG"\n')
        path.chmod(0o755)
    subprocess.run(['bash', str(root / 'scripts/container-bootstrap.sh'), 'build'], check=True,
                   env=dict(os.environ, PATH=str(directory) + ':' + os.environ['PATH'], BOOTSTRAP_LOG=str(log)), capture_output=True)
    assert 'pacman-key --init' in log.read_text()
print('automatic edge workflow and container bootstrap PASS')
