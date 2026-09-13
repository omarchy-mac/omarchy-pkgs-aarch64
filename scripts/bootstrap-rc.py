#!/usr/bin/env python3
"""Manual initial signed RC baseline. No mutation without --execute and explicit alias acceptance."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tarfile
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('release_bundle', Path(__file__).with_name('release-bundle.py'))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)
REPO = 'omarchy-mac/omarchy-pkgs-aarch64'
FLOOR = 3 * 1024**3
DB = bundle.DB
DATABASES = [f'{DB}.{suffix}' for suffix in ('files.tar.zst', 'files', 'db.tar.zst', 'db')]
require = bundle.require


def guard(path, reserve=0):
    fs = bundle.run('findmnt', '-n', '-o', 'FSTYPE', '-T', path).decode().strip()
    require(fs and fs not in ('tmpfs', 'ramfs'), 'Temporary storage must be disk-backed')
    require(shutil.disk_usage(path).free >= FLOOR + reserve, '3 GiB storage floor/reserve required')


def validate(path, expected_manifest, expected_source, trust_policy=bundle.SIGNING_POLICY, signed=True):
    require(re.fullmatch('[a-f0-9]{64}', expected_manifest), 'Exact manifest SHA256 required')
    require(re.fullmatch('[a-f0-9]{40}', expected_source), 'Exact source commit required')
    require(bundle.digest(path / 'manifest.json') == expected_manifest, 'Input manifest differs from approval')
    manifest = bundle.check(path, trust_policy)
    names = [p['name'] for p in manifest['packages']]
    inventory = [p['name'] for p in json.loads((ROOT / 'packages.json').read_text())['packages']]
    require(len(names) == len(inventory) == 52 and set(names) == set(inventory), 'Complete exact 52-package inventory required')
    require(manifest['channel'] == 'rc' and 'rc' in manifest['version'], 'Only an RC baseline is supported')
    require(manifest['source']['commit'] == expected_source, 'Source differs from approved commit')
    if signed:
        require(manifest['signature_policy'] == bundle.STRICT_POLICY, 'Strict signed baseline required')
    return manifest


def prepare(args):
    guard(args.output.parent)
    manifest = validate(args.input, args.manifest_sha256, args.source_commit, args.trust_policy, signed=False)
    require(not args.output.exists(), 'Output already exists; preserve/reuse its exact signed artifact')
    # Conservatively reserve a full copy even when reflinks are available.
    reserve = sum(p.stat().st_size for p in args.input.rglob('*') if p.is_file())
    guard(args.output.parent, reserve)
    if manifest['signature_policy'] == bundle.STRICT_POLICY:
        args.output.mkdir()
        for path in args.input.rglob('*'):
            if path.is_file():
                bundle.copy_file(path, args.output / path.relative_to(args.input))
    else:
        bundle.seal(argparse.Namespace(bundle=args.input, output=args.output,
                                      public_key=args.public_key, trust_policy=args.trust_policy))
    digest = bundle.digest(args.output / 'manifest.json')
    validate(args.output, digest, args.source_commit, args.trust_policy)
    guard(args.output.parent)
    print(json.dumps({'bundle': str(args.output), 'manifest_sha256': digest,
                      'source_commit': args.source_commit, 'signature_policy': bundle.STRICT_POLICY}))


class GitHub:
    """All absence checks require a successful paginated response, never an error guess."""
    def __init__(self, scratch):
        self.scratch = scratch

    def api(self, endpoint):
        return json.loads(bundle.run('gh', 'api', endpoint))

    def pages(self, endpoint):
        pages = json.loads(bundle.run('gh', 'api', '--paginate', '--slurp', endpoint))
        require(isinstance(pages, list) and all(isinstance(p, list) for p in pages), 'Malformed paginated GitHub response')
        return [item for page in pages for item in page]

    def release(self, tag, require_prerelease=True):
        matches = [x for x in self.pages(f'repos/{REPO}/releases?per_page=100') if x['tag_name'] == tag]
        require(len(matches) <= 1, 'Duplicate release tag')
        if not matches:
            return None
        release = matches[0]
        require(not require_prerelease or release['prerelease'], 'Refusing a non-prerelease target')
        assets = self.pages(f'repos/{REPO}/releases/{release["id"]}/assets?per_page=100')
        require(len({a['name'] for a in assets}) == len(assets), 'Duplicate remote asset')
        release['asset_map'] = {a['name']: a for a in assets}
        return release

    def read(self, release, name, public=False, destination=None):
        asset = release['asset_map'][name]
        size = asset['size']
        require(isinstance(size, int) and 0 <= size <= 2 * 1024**3, 'Invalid remote asset size')
        guard(self.scratch, size)
        fd, filename = tempfile.mkstemp(prefix='readback-', dir=self.scratch)
        os.close(fd)
        path = Path(filename)
        try:
            with path.open('wb') as stream:
                if public:
                    url = f'https://github.com/{REPO}/releases/download/{release["tag_name"]}/{name}'
                    command = ['curl', '--fail', '--silent', '--show-error', '--location', '--retry', '2', '--max-time', '180', url]
                else:
                    command = ['gh', 'api', f'repos/{REPO}/releases/assets/{asset["id"]}', '-H', 'Accept: application/octet-stream']
                child = subprocess.Popen(command, stdout=stream)
                try:
                    while child.poll() is None:
                        guard(self.scratch)
                        time.sleep(0.5)
                    require(child.returncode == 0, 'Remote readback/download failed')
                finally:
                    if child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill(); child.wait()
            require(path.stat().st_size == size, 'Remote readback length differs')
            result = bundle.digest(path)
            if destination is not None:
                shutil.copyfile(path, destination)
            return result
        finally:
            path.unlink()

    def tag_commit(self, tag):
        refs = self.api(f'repos/{REPO}/git/matching-refs/tags/{tag}')
        require(isinstance(refs, list), 'Malformed tag reference response')
        refs = [r for r in refs if r['ref'] == f'refs/tags/{tag}']
        require(len(refs) <= 1, 'Duplicate tag reference')
        if not refs:
            return None
        obj = refs[0]['object']
        for _ in range(8):
            if obj['type'] == 'commit':
                require(re.fullmatch('[a-f0-9]{40}', obj['sha']), 'Malformed tag commit')
                return obj['sha']
            require(obj['type'] == 'tag', 'Tag does not resolve to a commit')
            obj = self.api(f'repos/{REPO}/git/tags/{obj["sha"]}')['object']
        raise ValueError('Tag nesting exceeds supported depth')

    def create(self, tag, commit, body):
        existing = self.tag_commit(tag)
        require(existing in (None, commit), 'Existing tag points to a different commit')
        if existing is None:
            bundle.run('gh', 'api', '--method', 'POST', f'repos/{REPO}/git/refs',
                       '-f', f'ref=refs/tags/{tag}', '-f', f'sha={commit}')
        require(self.tag_commit(tag) == commit, 'Created tag commit differs')
        notes = self.scratch / 'release-notes.md'
        notes.write_text(body)
        bundle.run('gh', 'release', 'create', tag, '--repo', REPO, '--target', commit,
                   '--draft', '--prerelease', '--latest=false', '--title', tag, '--notes-file', notes)

    def upload(self, tag, path, clobber=False):
        command = ['gh', 'release', 'upload', tag, str(path), '--repo', REPO]
        if clobber:
            command.append('--clobber')
        bundle.run(*command)

    def delete(self, tag, name):
        bundle.run('gh', 'release', 'delete-asset', tag, name, '--repo', REPO, '--yes')

    def expose(self, tag):
        bundle.run('gh', 'release', 'edit', tag, '--repo', REPO, '--draft=false', '--prerelease', '--latest=false')


class Asset(NamedTuple):
    path: Path
    sha256: str
    size: int


def assets_for(path, manifest, manifest_sha256):
    """Keep candidate names consumable; flatten rollback/provenance without collisions."""
    result = {}
    for file in sorted(path.rglob('*')):
        if not file.is_file():
            continue
        relative = file.relative_to(path)
        name = file.name if relative.parts[0] == 'assets' or relative == Path('manifest.json') else '--'.join(relative.parts)
        bundle.safe_name(name)
        require(name not in result, 'Snapshot asset-name collision')
        expected = manifest_sha256 if relative == Path('manifest.json') else manifest['files'][relative.as_posix()]
        require(bundle.digest(file) == expected, f'Local artifact drift: {relative}')
        result[name] = Asset(file, expected, file.stat().st_size)
    return result


def preflight(release, expected, transport, allowed_db=(), obsolete=None):
    if release is None:
        return
    for name, asset in release['asset_map'].items():
        if name in (obsolete or {}):
            old = obsolete[name]
            if old is not None:
                require(transport.read(release, name) == old, f'Previous archive changed: {name}')
            continue
        require(name in expected, f'Unexpected remote asset: {name}')
        if name in allowed_db:
            continue
        require(asset['size'] == expected[name].size, f'Remote size collision: {name}')
        require(transport.read(release, name) == expected[name].sha256, f'Remote byte collision: {name}')


def readback(tag, expected, transport, public=False, obsolete=None):
    release = transport.release(tag)
    require(release is not None and set(expected) <= set(release['asset_map']) <= set(expected) | set(obsolete or {}), 'Incomplete/unexpected remote inventory')
    for name, artifact in expected.items():
        require(transport.read(release, name, public=public) == artifact.sha256, f'Readback failed: {name}')
    return release


def selected(release, transport):
    if release is None or f'{DB}.db' not in release['asset_map']:
        return 'absent'
    return transport.read(release, f'{DB}.db')



def selection_guard(current, previous, target, transport, expected_rc, db_assets,
                    snapshot, expected_snapshot, publisher):
    value = selected(current, transport)
    if value in {previous, target}:
        return
    # gh --clobber deletes an existing asset before uploading. Recognize only
    # the exact final-.db interruption, never arbitrary absence or a new lane.
    require(value == 'absent' and previous != 'absent' and current is not None,
            'RC database changed since approval')
    retained = transport.release(snapshot)
    require(retained is not None and not retained['draft'], 'Partial selection lacks public immutable snapshot')
    require(transport.tag_commit(snapshot) == publisher, 'Snapshot tag commit differs')
    readback(snapshot, expected_snapshot, transport)
    require(set(expected_rc) - db_assets <= set(current['asset_map']), 'Partial selection lacks complete packages/signatures')
    for name in set(expected_rc) - db_assets | {f'{DB}.db.sig'}:
        require(name in current['asset_map'] and transport.read(current, name) == expected_rc[name].sha256,
                f'Unrecognized interrupted selection: {name}')


def publish_checked(args, manifest, transport):
    """The caller has completed canonical cryptographic validation before this operation."""
    require(args.lane == 'rc', 'RC is the only permitted destination')
    require(re.fullmatch('[a-f0-9]{40}', args.publisher_commit), 'Exact publisher commit required')
    require(args.expected_rc_db == 'absent' or re.fullmatch('[a-f0-9]{64}', args.expected_rc_db), 'Explicit previous RC database hash or absent required')
    require(not args.execute or args.accept_mutable_alias_window, 'Execution requires explicit mutable DB/signature window acceptance')
    digest = args.manifest_sha256
    require(bundle.digest(args.bundle / 'manifest.json') == digest, 'Manifest changed after validation')
    target = manifest['files'][f'assets/{DB}.db']
    snapshot = f'rc-baseline-{manifest["version"]}-{digest[:16]}'
    expected_snapshot = assets_for(args.bundle, manifest, digest)
    expected_rc = {p.name: expected_snapshot[p.name] for p in (args.bundle / 'assets').iterdir()}
    db_assets = {name for name in expected_rc if name in DATABASES or name.removesuffix('.sig') in DATABASES}
    current = transport.release('rc')
    prior_snapshot = transport.release(snapshot)
    require(transport.tag_commit(snapshot) in (None, args.publisher_commit), 'Snapshot tag commit differs')
    require(prior_snapshot is None or transport.tag_commit(snapshot) == args.publisher_commit, 'Snapshot tag missing or differs')
    if current is None:
        require(transport.tag_commit('rc') in (None, args.publisher_commit), 'Orphan RC tag differs')
    obsolete = {}
    if args.expected_rc_db != 'absent':
        previous = args.scratch / 'previous-rc.db'
        if selected(current, transport) == args.expected_rc_db:
            transport.read(current, f'{DB}.db', destination=previous)
        else:
            require(prior_snapshot is not None and 'previous-rc.db' in prior_snapshot['asset_map'],
                    'Retry needs the retained approved previous RC database')
            transport.read(prior_snapshot, 'previous-rc.db', destination=previous)
        require(bundle.digest(previous) == args.expected_rc_db, 'Retained previous database differs from approval')
        rows = bundle.database(previous)
        allowed_names = {p['name'] for p in manifest['packages']}
        require(set(rows) <= allowed_names, 'Previous database contains unapproved package names')
        for record in rows.values():
            filename = bundle.safe_name(bundle.field(record, 'FILENAME'))
            require('.pkg.tar.' in filename and not filename.endswith('.sig'), 'Malformed previous archive filename')
            if filename not in expected_rc:
                obsolete[filename] = bundle.field(record, 'SHA256SUM')
                obsolete[filename + '.sig'] = None
        expected_snapshot['previous-rc.db'] = Asset(previous, args.expected_rc_db, previous.stat().st_size)
    # Superseded files are authorized only by this hash-approved prior DB and
    # retained until the complete new public inventory verifies.
    preflight(current, expected_rc, transport, db_assets, obsolete)
    preflight(prior_snapshot, expected_snapshot, transport)
    selection_guard(current, args.expected_rc_db, target, transport, expected_rc, db_assets,
                    snapshot, expected_snapshot, args.publisher_commit)
    plan = {'mode': 'execute' if args.execute else 'dry-run', 'repo': REPO, 'lane': 'rc',
            'snapshot_tag': snapshot, 'manifest_sha256': digest, 'packages': 52,
            'previous_rc_db': args.expected_rc_db, 'target_rc_db': target,
            'mutable_alias_risk': 'DB and signature are separate assets; clients can fail closed during replacement',
            'retry': 'Reuse the exact retained signed artifact and expected prior DB; never reseal an interrupted upload'}
    if not args.execute:
        return plan
    body = f'Signed RC baseline {manifest["version"]}.\n\nManifest SHA256: {digest}\nSource: {manifest["source"]["commit"]}\nPublisher: {args.publisher_commit}\n\nPackage integrity verified; this does not assert full installer or physical-hardware qualification.\n'
    guard(args.scratch, sum(artifact.size for artifact in expected_snapshot.values()))
    with tempfile.TemporaryDirectory(prefix='bootstrap-uploads-', dir=args.scratch) as temporary:
        upload = Path(temporary)
        for name, artifact in expected_snapshot.items():
            bundle.copy_file(artifact.path, upload / name)
            require(bundle.digest(upload / name) == artifact.sha256, f'Artifact changed while staging: {name}')
        if prior_snapshot is None:
            transport.create(snapshot, args.publisher_commit, body)
        existing = transport.release(snapshot)
        preflight(existing, expected_snapshot, transport)
        for name in expected_snapshot:
            if name not in existing['asset_map']:
                transport.upload(snapshot, upload / name)
        # Immutable snapshot is complete before it becomes public, and public
        # bytes are checked before the RC alias can select any database.
        existing = readback(snapshot, expected_snapshot, transport)
        if existing['draft']:
            transport.expose(snapshot)
        readback(snapshot, expected_snapshot, transport, public=True)
        require(transport.tag_commit(snapshot) == args.publisher_commit, 'Public snapshot tag differs')
        print(json.dumps({'phase': 'immutable_snapshot_verified_public', 'snapshot': snapshot}), flush=True)
        current = transport.release('rc')
        selection_guard(current, args.expected_rc_db, target, transport, expected_rc, db_assets,
                        snapshot, expected_snapshot, args.publisher_commit)
        preflight(current, expected_rc, transport, db_assets, obsolete)
        if current is None:
            transport.create('rc', args.publisher_commit, body)
            current = transport.release('rc')
        for name, artifact in expected_rc.items():
            if name not in db_assets and name not in current['asset_map']:
                require(bundle.digest(upload / name) == artifact.sha256, 'Upload staging changed')
                transport.upload('rc', upload / name)
        # Verify every package/signature, then recheck the selection immediately
        # before replacing DB aliases under the shared workflow writer lock.
        current = transport.release('rc')
        preflight(current, expected_rc, transport, db_assets, obsolete)
        require(set(expected_rc) - db_assets <= set(current['asset_map']), 'Missing package/signature after upload')
        selection_guard(current, args.expected_rc_db, target, transport, expected_rc, db_assets,
                        snapshot, expected_snapshot, args.publisher_commit)
        print(json.dumps({'phase': 'rc_packages_and_signatures_verified'}), flush=True)
        for name in DATABASES:
            for asset in (name + '.sig', name):
                artifact = expected_rc[asset]
                path = upload / asset
                require(bundle.digest(path) == artifact.sha256, 'Database staging changed')
                current = transport.release('rc')
                if asset in current['asset_map'] and transport.read(current, asset) == artifact.sha256:
                    continue
                transport.upload('rc', path, clobber=asset in current['asset_map'])
        current = readback('rc', expected_rc, transport, obsolete=obsolete)
        if current['draft']:
            transport.expose('rc')
        readback('rc', expected_rc, transport, public=True, obsolete=obsolete)
        print(json.dumps({'phase': 'rc_database_and_full_inventory_verified_public'}), flush=True)
        for name in sorted(obsolete):
            current = transport.release('rc')
            require(selected(current, transport) == target, 'RC changed before obsolete cleanup')
            if name in current['asset_map']:
                if obsolete[name] is not None:
                    require(transport.read(current, name) == obsolete[name], 'Obsolete archive changed; preserving it')
                transport.delete('rc', name)
        readback('rc', expected_rc, transport, public=True)
    plan['result'] = 'PASS complete signed snapshot and RC public readback'
    return plan



def capture(args):
    require(re.fullmatch('[a-f0-9]{64}', args.database_sha256), 'Approved edge database SHA256 required')
    require(not args.output.exists(), 'Capture output must be new')
    guard(args.output.parent)
    args.output.mkdir()
    transport = GitHub(args.output)
    release = transport.release('edge', require_prerelease=False)
    require(release is not None, 'Existing edge baseline is missing')
    path = args.output / f'{DB}.db.tar.zst'
    transport.read(release, path.name, destination=path)
    require(bundle.digest(path) == args.database_sha256, 'Edge database changed from approved capture')
    records = bundle.database(path)
    inventory = {p['name'] for p in json.loads((ROOT / 'packages.json').read_text())['packages']}
    require(set(records) in (inventory, inventory - {'omarchy-mac-keyring'}), 'Captured edge inventory is not the complete baseline')
    reserve = sum(int(bundle.field(row, 'CSIZE')) for row in records.values())
    guard(args.output, reserve)
    packages = args.output / 'packages'; packages.mkdir()
    for row in records.values():
        name = bundle.safe_name(bundle.field(row, 'FILENAME'))
        require(name in release['asset_map'], 'Baseline archive is absent')
        target = packages / name
        transport.read(release, name, destination=target)
        require(target.stat().st_size == int(bundle.field(row, 'CSIZE')) and bundle.digest(target) == bundle.field(row, 'SHA256SUM'),
                'Captured archive differs from approved database')
    bundle.validate_inventory(records, bundle.archives(packages))
    print(json.dumps({'database_sha256': args.database_sha256, 'archives': len(records), 'source': 'edge read-only capture'}))


def functional_payload(path):
    # Only reproducibility metadata is excluded. File kinds/content/modes/
    # ownership/links and functional .PKGINFO fields must remain identical.
    result = {}
    with tarfile.open(path, 'r:*') as archive:
        for item in archive.getmembers():
            name = item.name.removeprefix('./').rstrip('/')
            if not name or name in {'.BUILDINFO', '.MTREE'}:
                continue
            require(name not in result, 'Duplicate package payload entry')
            content = archive.extractfile(item).read() if item.isfile() else b''
            if name == '.PKGINFO':
                content = b'\n'.join(line for line in content.splitlines() if line and not line.startswith((b'builddate = ', b'#')))
            result[name] = (item.type, item.mode, item.uid, item.gid, item.linkname, hashlib.sha256(content).hexdigest())
    return result


def stage_input(args):
    require(not args.candidates.exists(), 'Candidate directory must be new')
    guard(args.candidates.parent)
    built = bundle.archives(args.built)
    require(set(built) == bundle.CANDIDATES, 'Canonical build must produce exactly five release inputs')
    baseline = bundle.archives(args.capture / 'packages')
    args.candidates.mkdir()
    for name, (path, record) in built.items():
        if name in {'omarchy-keyring', 'ttf-jetbrains-mono-nerd-basic'} and name in baseline:
            previous = baseline[name][0]
            require(functional_payload(path) == functional_payload(previous),
                    f'{name} functional payload differs; reviewed pkgrel/version replacement required')
            path = previous
        bundle.copy_file(path, args.candidates / path.name)
    bundle.copy_file(args.built / 'build-inputs.txt', args.candidates / 'build-inputs.txt')
    release = (args.source / 'version').read_text().strip()
    bundle.stage(argparse.Namespace(base_db=args.capture / f'{DB}.db.tar.zst',
                                    base_packages=args.capture / 'packages', candidates=args.candidates,
                                    source=args.source, source_git=None, source_commit=args.source_commit,
                                    release=release, output=args.output))
    digest = bundle.digest(args.output / 'manifest.json')
    validate(args.output, digest, args.source_commit, signed=False)
    print(json.dumps({'manifest_sha256': digest, 'source_commit': args.source_commit,
                      'packages': 52, 'qualification': 'build/capture/integrity only; runtime approval is separate'}))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    capture_parser = commands.add_parser('capture')
    capture_parser.add_argument('--database-sha256', required=True)
    capture_parser.add_argument('--output', type=Path, required=True)
    stage_parser = commands.add_parser('stage-input')
    for option in ['capture', 'built', 'candidates', 'source', 'output']:
        stage_parser.add_argument('--' + option, type=Path, required=True)
    stage_parser.add_argument('--source-commit', required=True)
    prepare_parser = commands.add_parser('prepare')
    prepare_parser.add_argument('--input', type=Path, required=True)
    prepare_parser.add_argument('--output', type=Path, required=True)
    publish = commands.add_parser('publish')
    publish.add_argument('--bundle', type=Path, required=True)
    publish.add_argument('--publisher-commit', required=True)
    publish.add_argument('--expected-rc-db', required=True)
    publish.add_argument('--lane', choices=['rc'], default='rc')
    publish.add_argument('--execute', action='store_true')
    publish.add_argument('--accept-mutable-alias-window', action='store_true')
    for sub in (prepare_parser, publish):
        sub.add_argument('--manifest-sha256', required=True)
        sub.add_argument('--source-commit', required=True)
        sub.add_argument('--trust-policy', type=Path, default=bundle.SIGNING_POLICY)
    prepare_parser.add_argument('--public-key', type=Path, default=bundle.signing.PUBLIC)
    args = parser.parse_args()
    if args.command == 'capture':
        capture(args)
    elif args.command == 'stage-input':
        stage_input(args)
    elif args.command == 'prepare':
        prepare(args)
    else:
        manifest = validate(args.bundle, args.manifest_sha256, args.source_commit, args.trust_policy)
        with tempfile.TemporaryDirectory(prefix='rc-bootstrap-', dir=os.environ.get('TMPDIR')) as temp:
            args.scratch = Path(temp)
            guard(args.scratch)
            print(json.dumps(publish_checked(args, manifest, GitHub(args.scratch)), indent=2))

if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'RC bootstrap stopped: {error}')
