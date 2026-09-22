#!/usr/bin/python3
"""Poll the collaboration branch and reuse only successful trusted candidate jobs."""
import hashlib
import json
import os
import re
import subprocess
from urllib.parse import quote


# Hash committed file identities, so unrelated package-repository commits do
# not rebuild the same desktop. Keep workflow trigger coverage in sync.
BUILD_INPUTS = (
    'pkgbuilds/omarchy-mac',
    'pkgbuilds/asdcontrol',
    'pkgbuilds/tobi-try',
    'pkgbuilds/qemu-user-static',
    'pkgbuilds/libva-v4l2_request-avd',
    'pkgbuilds/omarchy-steam-fex/omarchy-launch-steam',
    'scripts/build-quattro-image-inputs.py',
    'scripts/sign-quattro-image-inputs.py',
    'scripts/test-sign-quattro-image-inputs.py',
    'scripts/package-signing.py',
    '.github/publisher.Dockerfile',
    'pkgbuilds/omarchy-mac-keyring',
    'scripts/detect-quattro-image-inputs.py',
    'scripts/test-quattro-image-inputs.py',
    'scripts/test-quattro-image-inputs-detection.py',
    'scripts/quattro-image-inputs-recipes-revision',
    'scripts/quattro-image-inputs-iso-revision',
    'scripts/container-bootstrap.sh',
    'scripts/prepare-omarchy-recipes.sh',
    'patches/omarchy-first-run-packages.patch',
    'patches/quattro-desktop-test-fixtures.patch',
    '.github/workflows/build-quattro-image-inputs.yml',
)


def api(path, paginate=False):
    args = ['gh', 'api']
    if paginate:
        args += ['--paginate', '--slurp']
    return json.loads(subprocess.check_output([*args, path], text=True))


def trusted_artifact(artifact):
    run = artifact.get('workflow_run', {})
    return (not artifact['expired'] and run.get('head_branch') == 'main'
            and run.get('head_repository_id') is not None
            and run.get('head_repository_id') == run.get('repository_id'))


def successful_build(run, jobs, require_signed=True):
    required_jobs = ['Build eight candidate packages']
    if require_signed:
        required_jobs.append('Sign eight candidate packages')
    return (run['event'] in ('schedule', 'workflow_dispatch', 'push') and run['conclusion'] == 'success'
            and run['path'] == '.github/workflows/build-quattro-image-inputs.yml'
            and all(any(job['name'] == name and job['conclusion'] == 'success' for job in jobs)
                    for name in required_jobs))


def main():
    repo = os.environ['GITHUB_REPOSITORY']
    source_ref = os.environ.get('SOURCE_REF') or 'quattro-upstream'
    source = api('repos/omacom/omarchy-mac/commits/' + quote(source_ref, safe=''))['sha']
    assert re.fullmatch('[0-9a-f]{40}', source)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    inputs = subprocess.check_output(['git', 'ls-tree', '-r', 'HEAD', '--', *BUILD_INPUTS])
    assert inputs
    digest = hashlib.sha256(inputs).hexdigest()[:24]
    name = f'quattro-image-inputs-{source}-{digest}'
    signed_name = 'signed-' + name
    require_signed = source_ref == 'quattro-upstream'
    lookup_name = signed_name if require_signed else name
    needed = True
    if os.environ.get('FORCE_BUILD') != 'true':
        pages = api(f'repos/{repo}/actions/artifacts?name={lookup_name}&per_page=100', paginate=True)
        for artifact in (a for page in pages for a in page['artifacts']):
            if not trusted_artifact(artifact):
                continue
            run_id = artifact['workflow_run']['id']
            run = api(f'repos/{repo}/actions/runs/{run_id}')
            jobs = [j for page in api(f'repos/{repo}/actions/runs/{run_id}/jobs?per_page=100', paginate=True)
                    for j in page['jobs']]
            if successful_build(run, jobs, require_signed=require_signed):
                needed = False
                break
    result = dict(source_sha=source, recipe_sha=revision, artifact_name=name, signed_artifact_name=signed_name,
                  needs_build=str(needed).lower())
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        for key, value in result.items():
            output.write(f'{key}={value}\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
