#!/usr/bin/env python3
"""Bounded retained-keyring experiment. Never publishes or uses signing keys."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
REPO = 'omarchy-mac/omarchy-pkgs-aarch64'
DB = 'omarchy-aarch64'
EDGE_RELEASE = 367100318
RC_RELEASE = 390634001
SOURCE = 'fec792c8784a8bfd48d401a6d3c0bff5ec896860'
KEYRING = 'omarchy-mac-keyring-20260914-2-any.pkg.tar.xz'
KEYRING_SHA = '8ca587d9c24d36cd2e67237ca69b3eeac1b3726e691228131d6d062d258cdfb7'
PUBLIC_SHA = '118b1a5b48a74a2dd993860c4dc3f9d477d5c47c3b1422ea40e8e91f3c7e73d1'
SUFFIXES = ('db', 'db.tar.zst', 'files', 'files.tar.zst')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def api(endpoint, raw=False):
    args = ['gh', 'api', '--method', 'GET', f'repos/{REPO}/{endpoint}']
    if raw:
        args += ['-H', 'Accept: application/octet-stream']
    data = subprocess.check_output(args, stdin=subprocess.DEVNULL)
    return data if raw else json.loads(data)


def assets(release):
    rows = []
    page = 1
    while True:
        batch = api(f'releases/{release}/assets?per_page=100&page={page}')
        rows.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    # Only identity/freshness metadata, not volatile download counters.
    rows = [{k: r[k] for k in ('id', 'name', 'size', 'digest', 'updated_at')} for r in rows]
    require(len({r['name'] for r in rows}) == len(rows), 'duplicate release asset names')
    return sorted(rows, key=lambda row: row['name'])


def check_keyring_asset(rows):
    selected = [r for r in rows if r['id'] == 570814012 or r['name'] == KEYRING]
    require(len(selected) == 1, 'missing/duplicate selected RC asset')
    row = selected[0]
    require(all(row[k] == v for k, v in dict(id=570814012, name=KEYRING, size=9740,
            digest='sha256:' + KEYRING_SHA).items()), 'selected RC asset identity changed')
    return row


def download(row, target):
    data = api(f"releases/assets/{row['id']}", raw=True)
    require(len(data) == row['size'] and 'sha256:' + digest(data) == row['digest'],
            'download size/hash mismatch: ' + row['name'])
    target.write_bytes(data)


def recheck(directory):
    require(api('releases/tags/edge')['id'] == EDGE_RELEASE, 'edge release changed')
    require(api('releases/tags/rc')['id'] == RC_RELEASE, 'RC release changed')
    require(assets(EDGE_RELEASE) == json.loads((directory / 'edge-assets.json').read_text()),
            'edge drifted: rerun requires a fresh reviewed snapshot')
    check_keyring_asset(assets(RC_RELEASE))


def acquire(directory):
    require(not list(directory.iterdir()), 'acquisition directory must be empty')
    require(api('releases/tags/edge')['id'] == EDGE_RELEASE, 'unexpected edge release')
    require(api('releases/tags/rc')['id'] == RC_RELEASE, 'unexpected RC release')
    rows = assets(EDGE_RELEASE)
    require(not any(r['name'].endswith('.sig') or r['name'] == 'edge-signing.json' for r in rows),
            'strict edge is outside this unsigned experiment')
    require(not any(r['name'].startswith('omarchy-mac-keyring-') for r in rows),
            'edge already has a keyring asset; review changed inputs')
    (directory / 'edge-assets.json').write_text(json.dumps(rows, indent=2) + '\n')
    before = directory / 'before'
    before.mkdir()
    for suffix in SUFFIXES:
        name = f'{DB}.{suffix}'
        selected = [r for r in rows if r['name'] == name]
        require(len(selected) == 1, 'missing database alias: ' + name)
        download(selected[0], before / name)
    selected = check_keyring_asset(assets(RC_RELEASE))
    (directory / 'rc-keyring-asset.json').write_text(json.dumps(selected, indent=2) + '\n')
    download(selected, directory / KEYRING)
    # Compare all three public payload files to the production-pinned source.
    with tarfile.open(directory / KEYRING) as archive:
        info = archive.extractfile('.PKGINFO').read().decode()
        for line in ('pkgname = omarchy-mac-keyring', 'pkgver = 20260914-2', 'arch = any'):
            require(line in info.splitlines(), 'wrong keyring package metadata')
        for name in ('omarchy-mac.gpg', 'omarchy-mac-trusted', 'omarchy-mac-revoked'):
            endpoint = f'contents/pkgbuilds/omarchy-mac-keyring/{name}?ref={SOURCE}'
            source = subprocess.check_output(['gh', 'api', '--method', 'GET',
                f'repos/{REPO}/{endpoint}', '-H', 'Accept: application/vnd.github.raw+json'],
                stdin=subprocess.DEVNULL)
            payload = archive.extractfile('usr/share/pacman/keyrings/' + name).read()
            require(payload == source, 'public keyring payload differs: ' + name)
            if name.endswith('.gpg'):
                require(digest(payload) == PUBLIC_SHA, 'wrong public certificate')
    recheck(directory)



def require(condition, message):
    if not condition:
        raise ValueError(message)


def records(path):
    """All raw DB/files records, not only identity fields or entry counts."""
    data = path.read_bytes()
    if data[:4] == b'\x28\xb5\x2f\xfd':
        data = subprocess.check_output(['zstd', '-dc', str(path)])
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            if member.isdir():
                continue
            parts = member.name.removeprefix('./').split('/')
            require(member.isfile() and len(parts) == 2 and parts[1] in ('desc', 'files'),
                    'unexpected database member')
            record = result.setdefault(parts[0], {})
            require(parts[1] not in record, 'duplicate database member')
            record[parts[1]] = archive.extractfile(member).read()
    require(result and all('desc' in row for row in result.values()), 'empty/incomplete database')
    return result


def fields(desc):
    result = {}
    for block in desc.decode().strip().split('\n\n'):
        lines = block.splitlines()
        require(lines[0].startswith('%') and lines[0].endswith('%'), 'invalid DB field')
        key = lines[0].strip('%')
        require(key not in result, 'duplicate DB field')
        result[key] = lines[1:]
    return result


def inventory(directory, rows):
    """Require complete legacy inventory and identical DB/files descriptions."""
    db = records(directory / f'{DB}.db.tar.zst')
    files = records(directory / f'{DB}.files.tar.zst')
    require(set(db) == set(files), 'DB/files inventory differs')
    by_name = {row['name']: row for row in rows}
    require(len(by_name) == len(rows), 'duplicate release assets')
    expected = {f'{DB}.{suffix}' for suffix in SUFFIXES}
    names = set()
    for entry, record in db.items():
        require(set(record) == {'desc'} and set(files[entry]) == {'desc', 'files'}, 'incomplete record')
        require(record['desc'] == files[entry]['desc'], 'DB/files metadata differs')
        data = fields(record['desc'])
        require('PGPSIG' not in data, 'signed DB outside experiment')
        for key in ('NAME', 'VERSION', 'FILENAME', 'CSIZE', 'SHA256SUM'):
            require(len(data.get(key, [])) == 1, 'missing/ambiguous identity: ' + key)
        name = data['NAME'][0]
        require(name not in names, 'duplicate package name')
        names.add(name)
        filename = data['FILENAME'][0]
        require(filename not in expected, 'duplicate filename')
        expected.add(filename)
        asset = by_name.get(filename)
        require(asset is not None, 'missing release package: ' + filename)
        require(asset.get('size') == int(data['CSIZE'][0]) and
                asset.get('digest') == 'sha256:' + data['SHA256SUM'][0], 'package identity differs: ' + filename)
    require(set(by_name) == expected, 'unexpected/orphan release assets')
    for suffix in SUFFIXES:
        path = directory / f'{DB}.{suffix}'
        row = by_name[path.name]
        raw = path.read_bytes()
        require(len(raw) == row['size'] and 'sha256:' + digest(raw) == row['digest'], 'database hash differs')
    for ext in ('db', 'files'):
        require((directory / f'{DB}.{ext}').read_bytes() == (directory / f'{DB}.{ext}.tar.zst').read_bytes(),
                'database aliases differ')
    return db, files


def snapshot_gh(args):
    """Test-only read adapter; repo-add and publish.sh remain the real tools."""
    require(len(args) >= 3 and args[0] == 'release' and args[2] == 'edge', 'edge-only snapshot')
    require('--repo' in args and args[args.index('--repo') + 1] == REPO, 'wrong repository')
    require(args[1] in ('view', 'download'), 'snapshot transport is read-only')
    snapshot = Path(os.environ['SNAPSHOT'])
    with open(os.environ['SNAPSHOT_LOG'], 'a') as log:
        log.write(json.dumps(args) + '\n')
    rows = json.loads((snapshot / 'edge-assets.json').read_text())
    if args[1] == 'view':
        print('\n'.join(row['name'] for row in rows) if '--jq' in args else json.dumps({'assets': rows}))
    else:
        target = Path(args[args.index('--dir') + 1])
        target.mkdir(parents=True, exist_ok=True)
        patterns = [args[i + 1] for i, arg in enumerate(args) if arg == '--pattern']
        require(patterns, 'missing snapshot download pattern')
        for name in patterns:
            require(name in {f'{DB}.{suffix}' for suffix in SUFFIXES}, 'only DB snapshot downloads allowed')
            shutil.copyfile(snapshot / 'before' / name, target / name)


def publisher(incoming, snapshot, output):
    output.mkdir()
    bindir = output / 'bin'
    bindir.mkdir()
    shim = bindir / 'gh'
    import shlex
    shim.write_text('#!/bin/sh\nexec python3 ' + shlex.quote(str(Path(__file__).resolve())) +
                    ' --snapshot-gh "$@"\n')
    shim.chmod(0o755)
    # Whitelist, never forward ambient GitHub/signing credentials or lane flags.
    env = {k: os.environ[k] for k in ('HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG') if k in os.environ}
    env.update(PATH=str(bindir) + os.pathsep + os.environ['PATH'], GH_REPO=REPO,
               PKGDIR=str(incoming), DB_OUT=str(output), DRY_RUN='1', REPO_TAG='edge',
               SNAPSHOT=str(snapshot), SNAPSHOT_LOG=str(output / 'snapshot-reads.jsonl'),
               PYTHONDONTWRITEBYTECODE='1')
    with (output / 'publisher.log').open('w') as log:
        result = subprocess.run(['bash', 'scripts/publish.sh'], cwd=ROOT, env=env,
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    text = (output / 'publisher.log').read_text()
    require(result.returncode == 0, 'publisher failed; see ' + str(output / 'publisher.log'))
    require('delete-asset' not in text, 'unexpected planned garbage collection')


def preserved(before, after, additions):
    require(set(after) == set(before) | set(additions) and not set(before) & set(additions),
            'unexpected added/removed records')
    for name, record in before.items():
        require(after[name] == record, f'changed existing record: {name}')


def native(inputs, output):
    require(sys.platform == 'linux' and os.uname().machine == 'aarch64', 'hosted native ARM Linux only')
    for tool in ('repo-add', 'bsdtar', 'zstd', 'xz', 'jq', 'findmnt', 'bash'):
        require(shutil.which(tool), 'missing native publisher tool: ' + tool)
    rows = json.loads((inputs / 'edge-assets.json').read_text())
    before = inventory(inputs / 'before', rows)
    require(not any(fields(r['desc'])['NAME'] == ['omarchy-mac-keyring'] for r in before[0].values()),
            'keyring already indexed; review changed edge')
    keyring_row = check_keyring_asset([json.loads((inputs / 'rc-keyring-asset.json').read_text())])
    require(digest((inputs / KEYRING).read_bytes()) == KEYRING_SHA and (inputs / KEYRING).stat().st_size == 9740,
            'keyring bytes changed')
    incoming = output / 'keyring-only'
    incoming.mkdir()
    shutil.copyfile(inputs / KEYRING, incoming / KEYRING)
    first = output / 'keyring-result'
    publisher(incoming, inputs, first)

    def resulting(previous, directory, package_row):
        result = [row for row in previous if row['name'] not in {f'{DB}.{s}' for s in SUFFIXES}]
        result.append(package_row)
        for suffix in SUFFIXES:
            path = directory / f'{DB}.{suffix}'
            data = path.read_bytes()
            result.append(dict(name=path.name, size=len(data), digest='sha256:' + digest(data)))
        require((directory / 'signing-mode').read_text().strip() == 'legacy', 'unexpected signing transition')
        return result, inventory(directory, result)

    first_rows, after = resulting(rows, first, keyring_row)
    keyring_entry = 'omarchy-mac-keyring-20260914-2'
    for old, new in zip(before, after):
        preserved(old, new, {keyring_entry})
    keyring_fields = fields(after[0][keyring_entry]['desc'])
    require(keyring_fields['NAME'] == ['omarchy-mac-keyring'] and
            keyring_fields['VERSION'] == ['20260914-2'] and keyring_fields['FILENAME'] == [KEYRING],
            'wrong added keyring record')
    require((first / 'smoke-packages' / KEYRING).read_bytes() == (inputs / KEYRING).read_bytes(),
            'publisher changed selected package')

    # Disposable next-publication fixture, never an artifact to publish.
    # Synthetic tar creation is not a package build or a mock of repo-add.
    snapshot = output / 'next-snapshot'
    snapshot.mkdir()
    (snapshot / 'before').mkdir()
    for suffix in SUFFIXES:
        shutil.copyfile(first / f'{DB}.{suffix}', snapshot / 'before' / f'{DB}.{suffix}')
    (snapshot / 'edge-assets.json').write_text(json.dumps(first_rows, indent=2) + '\n')
    fixture = output / 'unrelated-fixture'
    fixture.mkdir()
    name = 'edge-keyring-preservation-fixture'
    require(not any(fields(r['desc'])['NAME'] == [name] for r in after[0].values()), 'fixture name collision')
    package = fixture / f'{name}-1-1-any.pkg.tar.xz'
    with tarfile.open(package, 'w:xz') as archive:
        for filename, data in {
            '.PKGINFO': f'pkgname = {name}\npkgbase = {name}\npkgver = 1-1\npkgdesc = Disposable preservation fixture\narch = any\nsize = 8\nbuilddate = 1\nlicense = MIT\n'.encode(),
            'usr/share/edge-keyring-preservation-fixture/probe': b'fixture\n',
        }.items():
            member = tarfile.TarInfo(filename)
            member.size = len(data)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))
    second = output / 'next-publication-fixture-result'
    publisher(fixture, snapshot, second)
    fixture_row = dict(name=package.name, size=package.stat().st_size, digest='sha256:' + digest(package.read_bytes()))
    _, final = resulting(first_rows, second, fixture_row)
    for old, new in zip(after, final):
        preserved(old, new, {name + '-1-1'})
    report = [
        'PASS: native repo-add + existing publish.sh DRY_RUN=1 against a read-only edge snapshot.',
        f'Before: {len(before[0])}; keyring insertion: {len(after[0])}; unrelated fixture: {len(final[0])}.',
        'Every old DB description and files record preserved byte-for-byte at both steps.',
        'Complete asset filename/size/SHA-256 reconciliation passed; versions preserved in full records.',
        'No GC deletions planned at either step; keyring survives next unrelated publication fixture.',
        'No live publication, signing, independent trust authentication, or client qualification.',
        'Only keyring-result contains the proposed derived DB assets; next-publication-fixture-result is synthetic.',
        f'Pinned public payload source: {SOURCE}; selected RC asset: 570814012.',
    ]
    for label, directory in [('before', inputs / 'before'), ('keyring-result', first)]:
        for suffix in SUFFIXES:
            path = directory / f'{DB}.{suffix}'
            report.append(f'{label}/{path.name}  {path.stat().st_size}  {digest(path.read_bytes())}')
    text = '\n'.join(report) + '\n'
    (output / 'report.txt').write_text(text)
    print(text)


def main():
    if sys.argv[1:2] == ['--snapshot-gh']:
        snapshot_gh(sys.argv[2:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--acquire', type=Path, metavar='EMPTY_DIRECTORY')
    mode.add_argument('--recheck', type=Path, metavar='INPUTS')
    mode.add_argument('--native', type=Path, nargs=2, metavar=('INPUTS', 'OUTPUT'))
    args = parser.parse_args()
    if args.acquire:
        acquire(args.acquire.resolve())
    elif args.recheck:
        recheck(args.recheck.resolve())
    else:
        native(*(p.resolve() for p in args.native))


if __name__ == '__main__':
    main()
