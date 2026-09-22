#!/usr/bin/env python3
"""One bounded unsigned edge bootstrap. No rebuilding, signing, GC or retries."""
import importlib.util
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

spec = importlib.util.spec_from_file_location('edge_dryrun', Path(__file__).with_name('edge-keyring-dryrun.py'))
dry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dry)
require = dry.require
ORDER = (dry.KEYRING,) + tuple(dry.DB + '.' + s for s in ('files.tar.zst', 'files', 'db.tar.zst', 'db'))


HEAD = 'f3f17d7e952c8c99d5a1d87dbe39b9f477cda94d'
BEFORE = {
    'db': (13373, '4a5a34a42d60f66933dc894aa8db51df238c7d6c9e1c2151ff0fe2d1c44cfdec'),
    'files': (276985, '80fdc2c4ce6ba9955989d60a5f35c5241bf5b24eecee1487da50d15c83317ee6'),
}
AFTER = {
    'db': (13348, '64fd336af09b0f850c618b97998e92a5da8d6b506827771b74b5c2adfa2c1d39'),
    'files': (276588, 'c8943e950bce7146db937021733615c36d8f17ff38a0b5c538dbacbcbfaef339'),
}


RUN = 35714377495
ARTIFACT = 10689146736
ARTIFACT_NAME = 'edge-keyring-dryrun-35714377495-1'
ZIP_SIZE = 2366438
ZIP_SHA = '30a59068366d011fe085dfdb96861596cc6929bec1fff4d29a6fb9960317c8f7'
MEMBERS = (
    'inputs/edge-assets.json', 'inputs/rc-keyring-asset.json', 'inputs/' + dry.KEYRING,
    'output/source-commit.txt', 'output/keyring-result/signing-mode',
    'output/keyring-result/smoke-packages/' + dry.KEYRING,
) + tuple(prefix + dry.DB + '.' + suffix for prefix in ('inputs/before/', 'output/keyring-result/')
          for suffix in dry.SUFFIXES)


def acquire(transport, root):
    import io
    import zipfile
    run = transport.api(f'actions/runs/{RUN}')
    expected = dict(id=RUN, run_attempt=1, head_sha=HEAD, conclusion='success',
                    status='completed', event='workflow_dispatch', path='.github/workflows/test.yml')
    require(all(run.get(k) == v for k, v in expected.items()) and
            run['repository']['id'] == 1327386148, 'retained run identity changed')
    artifact = transport.api(f'actions/artifacts/{ARTIFACT}')
    expected = dict(id=ARTIFACT, name=ARTIFACT_NAME, expired=False,
                    size_in_bytes=ZIP_SIZE, digest='sha256:' + ZIP_SHA)
    require(all(artifact.get(k) == v for k, v in expected.items()), 'retained artifact identity changed')
    expected_run = dict(id=RUN, head_sha=HEAD, repository_id=1327386148, head_repository_id=1327386148)
    require(all(artifact['workflow_run'].get(k) == v for k, v in expected_run.items()),
            'artifact producer changed')
    raw = checked(transport.api(f'actions/artifacts/{ARTIFACT}/zip', raw=True), ZIP_SIZE, ZIP_SHA)
    require(not root.exists() or not list(root.iterdir()), 'acquisition directory must be empty')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'duplicate ZIP members')
        # Read only fixed safe relative names; never extractall, scripts or synthetic output.
        for name in MEMBERS:
            member = archive.getinfo(name)
            require(member.file_size <= 1024 * 1024 and not member.is_dir() and
                    (member.external_attr >> 16) & 0o170000 != 0o120000, 'unsafe ZIP member')
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))


def checked(data, size, sha):
    require(len(data) == size and dry.digest(data) == sha, 'pinned bytes differ')
    return data


def validate(root):
    inputs = root / 'inputs'
    result = root / 'output/keyring-result'  # NEVER next-publication-fixture-result
    require((root / 'output/source-commit.txt').read_text().strip() == HEAD, 'dry-run checkout changed')
    require((result / 'signing-mode').read_text().strip() == 'legacy', 'signing mode changed')
    rows = json.loads((inputs / 'edge-assets.json').read_text())
    require(len(rows) == 58, 'baseline asset count changed')
    keyring = dry.check_keyring_asset([json.loads((inputs / 'rc-keyring-asset.json').read_text())])
    package = checked((inputs / dry.KEYRING).read_bytes(), 9740, dry.KEYRING_SHA)
    require((result / 'smoke-packages' / dry.KEYRING).read_bytes() == package, 'keyring copy changed')
    for directory, pins in ((inputs / 'before', BEFORE), (result, AFTER)):
        for suffix in dry.SUFFIXES:
            checked((directory / (dry.DB + '.' + suffix)).read_bytes(), *pins[suffix.split('.')[0]])
    before = dry.inventory(inputs / 'before', rows)
    require(len(before[0]) == 54, 'baseline package count changed')
    selected = {dry.KEYRING: package}
    selected.update({name: (result / name).read_bytes() for name in ORDER[1:]})
    new_rows = [r for r in rows if r['name'] not in ORDER] + [keyring]
    new_rows += [dict(name=name, size=len(data), digest='sha256:' + dry.digest(data))
                 for name, data in selected.items() if name != dry.KEYRING]
    after = dry.inventory(result, new_rows)
    entry = 'omarchy-mac-keyring-20260914-2'
    for old, new in zip(before, after):
        dry.preserved(old, new, {entry})
    fields = dry.fields(after[0][entry]['desc'])
    require(fields['NAME'] == ['omarchy-mac-keyring'] and fields['VERSION'] == ['20260914-2']
            and fields['FILENAME'] == [dry.KEYRING], 'wrong keyring record')
    return rows, selected


def assets(transport):
    rows = []
    page = 1
    while True:
        batch = transport.api(f'releases/{dry.EDGE_RELEASE}/assets?per_page=100&page={page}')
        rows.extend({k: r[k] for k in ('id', 'name', 'size', 'digest', 'updated_at')} for r in batch)
        if len(batch) < 100:
            break
        page += 1
    require(len({r['name'] for r in rows}) == len(rows), 'duplicate asset names')
    require(len({r['id'] for r in rows}) == len(rows), 'duplicate asset IDs')
    return sorted(rows, key=lambda r: r['name'])


def snapshot(transport, expected):
    require(transport.api('releases/tags/edge')['id'] == dry.EDGE_RELEASE, 'edge release changed')
    require(assets(transport) == sorted(expected, key=lambda r: r['name']), 'edge baseline drift')


def publish(transport, baseline, selected):
    require(tuple(selected) == ORDER, 'only the five approved assets in exact order')
    snapshot(transport, baseline)
    by_name = {r['name']: r for r in baseline}
    require(dry.KEYRING not in by_name, 'keyring collision')
    # Fresh authenticated byte capture of all four aliases under the job lock.
    for name in ORDER[1:]:
        row = by_name[name]
        data = transport.api(f"releases/assets/{row['id']}", raw=True)
        require(len(data) == row['size'] and 'sha256:' + dry.digest(data) == row['digest'],
                'live baseline bytes differ: ' + name)
    snapshot(transport, baseline)  # immediately before the first write
    expected = [r for r in baseline if r['name'] not in ORDER]
    try:
        for name in ORDER:
            if name in by_name:
                transport.api(f"releases/assets/{by_name[name]['id']}", method='DELETE')
            from urllib.parse import quote
            endpoint = (f'https://uploads.github.com/repos/{dry.REPO}/releases/'
                        f'{dry.EDGE_RELEASE}/assets?name={quote(name, safe="")}')
            row = transport.api(endpoint, method='POST', data=selected[name])
            require(row['name'] == name and row['size'] == len(selected[name]) and
                    row['digest'] == 'sha256:' + dry.digest(selected[name]), 'upload identity mismatch')
            expected.append({k: row[k] for k in ('id', 'name', 'size', 'digest', 'updated_at')})
        snapshot(transport, expected)
        for name in ORDER:
            require(transport.public(name) == selected[name], 'public byte readback mismatch: ' + name)
        snapshot(transport, expected)
    except Exception:
        raise RuntimeError('PARTIAL PUBLICATION POSSIBLE: stop; no retry or automatic rollback. '
                           'Inspect the complete edge inventory before any separately approved recovery.') from None
    return expected


class GitHub:
    def api(self, endpoint, *, method='GET', data=None, raw=False):
        url = endpoint if endpoint.startswith('https://uploads.github.com/') else f'repos/{dry.REPO}/{endpoint}'
        args = ['gh', 'api', '--method', method, url]
        if raw and endpoint.startswith('releases/assets/'):
            args += ['-H', 'Accept: application/octet-stream']
        kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if data is not None:
            args += ['-H', 'Content-Type: application/octet-stream', '--input', '-']
            kwargs['input'] = data
        else:
            kwargs['stdin'] = subprocess.DEVNULL
        result = subprocess.run(args, **kwargs)
        require(result.returncode == 0, f'GitHub {method} request failed (no retry)')
        if raw:
            return result.stdout
        return json.loads(result.stdout) if result.stdout.strip() else None

    def public(self, name):
        require(name in ORDER, 'unapproved public download')
        request = urllib.request.Request(f'https://github.com/{dry.REPO}/releases/download/edge/{name}',
                                         headers={'Cache-Control': 'no-cache'})
        # No gh, token, Authorization header or authenticated API download here.
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read(1024 * 1024)


def execution_guard():
    for key, value in dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY=dry.REPO,
                          GITHUB_REPOSITORY_ID='1327386148', GITHUB_EVENT_NAME='workflow_dispatch',
                          GITHUB_RUN_ATTEMPT='1').items():
        require(os.environ.get(key) == value, 'execution context rejected: ' + key)
    approved = os.environ.get('APPROVED_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', approved) is not None and
            approved == os.environ.get('GITHUB_SHA'), 'reviewed execution SHA mismatch')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], stdin=subprocess.DEVNULL).decode().strip()
    require(actual == approved, 'checkout differs from reviewed execution SHA')


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish', type=Path, required=True, metavar='EMPTY_DIRECTORY')
    args = parser.parse_args()
    execution_guard()
    transport = GitHub()
    acquire(transport, args.publish)
    baseline, selected = validate(args.publish)
    final = publish(transport, baseline, selected)
    (args.publish / 'verified-edge-assets.json').write_text(json.dumps(final, indent=2) + '\n')
    print('PASS: exact bootstrap bytes publicly read back; complete edge inventory verified. '
          'No signing, policy transition or client qualification.')


if __name__ == '__main__':
    main()
