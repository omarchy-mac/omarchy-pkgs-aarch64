#!/usr/bin/python3
"""Poll the collaboration branch and reuse only successful trusted candidate jobs."""
import hashlib
import json
import os
import re
import subprocess


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


def successful_build(run, jobs):
    return (run['event'] in ('schedule', 'workflow_dispatch')
            and run['path'] in ('.github/workflows/update-omarchy-mac.yml',
                                '.github/workflows/build-mac-addon-candidate.yml')
            and any(job['name'].endswith('Build add-on archive') and job['conclusion'] == 'success'
                    for job in jobs))


def main():
    repo = os.environ['GITHUB_REPOSITORY']
    source = api('repos/omacom/omarchy-mac/commits/quattro-upstream')['sha']
    assert re.fullmatch('[0-9a-f]{40}', source)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    inputs = subprocess.check_output(['git', 'ls-tree', '-r', 'HEAD', '--',
        'pkgbuilds/omarchy-mac', 'scripts/build-mac-addon-candidate.py',
        'scripts/detect-mac-addon-candidate.py', '.github/workflows/build-mac-addon-candidate.yml'])
    assert inputs
    digest = hashlib.sha256(inputs).hexdigest()[:24]
    name = f'omarchy-mac-candidate-{source}-{digest}'
    needed = True
    if os.environ.get('FORCE_BUILD') != 'true':
        pages = api(f'repos/{repo}/actions/artifacts?name={name}&per_page=100', paginate=True)
        for artifact in (a for page in pages for a in page['artifacts']):
            if not trusted_artifact(artifact):
                continue
            run_id = artifact['workflow_run']['id']
            run = api(f'repos/{repo}/actions/runs/{run_id}')
            jobs = [j for page in api(f'repos/{repo}/actions/runs/{run_id}/jobs?per_page=100', paginate=True)
                    for j in page['jobs']]
            if successful_build(run, jobs):
                needed = False
                break
    result = dict(source_sha=source, recipe_sha=revision, artifact_name=name,
                  needs_build=str(needed).lower())
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        for key, value in result.items():
            output.write(f'{key}={value}\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
