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


def temporary_root():
    location = Path(os.environ.get('TMPDIR') or Path.home() / '.cache/omarchy-publisher/tmp')
    parent = location
    while not parent.exists():
        parent = parent.parent
    guard(parent)
    location.mkdir(parents=True, exist_ok=True)
    guard(location)
    os.environ.update(TMPDIR=str(location), TMP=str(location), TEMP=str(location))
    return location


def validate(path, expected_manifest, expected_source, trust_policy=bundle.SIGNING_POLICY, signed=True, channel="rc"):
    require(re.fullmatch('[a-f0-9]{64}', expected_manifest), 'Exact manifest SHA256 required')
    require(re.fullmatch('[a-f0-9]{40}', expected_source), 'Exact source commit required')
    require(bundle.digest(path / 'manifest.json') == expected_manifest, 'Input manifest differs from approval')
    manifest = bundle.check(path, trust_policy)
    names = [p['name'] for p in manifest['packages']]
    catalog = path / 'provenance/catalog.json' if 'capture_manifest_sha256' in manifest else ROOT / 'packages.json'
    inventory = [p['name'] for p in json.loads(catalog.read_text())['packages']]
    require(len(names) == len(inventory) and len(names) == len(set(names)) and set(names) == set(inventory), 'Complete exact configured package inventory required')
    require(channel in ('rc', 'stable') and manifest['channel'] == channel, 'Baseline channel differs')
    require(('rc' in manifest['version']) == (channel == 'rc'), 'Baseline version/channel differs')
    require(manifest['source']['commit'] == expected_source, 'Source differs from approved commit')
    if signed:
        require(manifest['signature_policy'] == bundle.STRICT_POLICY, 'Strict signed baseline required')
    return manifest


def prepare(args):
    guard(args.output.parent)
    manifest = validate(args.input, args.manifest_sha256, args.source_commit, args.trust_policy, signed=False, channel=getattr(args, "channel", "rc"))
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
    validate(args.output, digest, args.source_commit, args.trust_policy, channel=getattr(args, "channel", "rc"))
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


def lane_release(transport, tag):
    return transport.release(tag, require_prerelease=False) if tag == "edge" else transport.release(tag)


def readback(tag, expected, transport, public=False, obsolete=None):
    release = lane_release(transport, tag)
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
    selection_evidence = ({f'{DB}.db.sig'} if f'{DB}.db.sig' in expected_rc
                          else set(DATABASES) - {f'{DB}.db'})
    for name in set(expected_rc) - db_assets | selection_evidence:
        require(name in current['asset_map'] and transport.read(current, name) == expected_rc[name].sha256,
                f'Unrecognized interrupted selection: {name}')


def publish_checked(args, manifest, transport, *, old_trust_transition=False, edge_conversion=False):
    """The caller has completed canonical package/bundle validation before this operation."""
    require(args.lane == ('edge' if edge_conversion else 'rc'), 'Unexpected destination')
    if edge_conversion:
        require(not old_trust_transition and manifest['channel'] == 'stable' and 'rc' not in manifest['version'], 'Edge conversion requires a final stable inventory')
        require(getattr(args, 'accept_client_trust_bootstrap', False), 'Explicit completed client trust bootstrap acceptance required')
        require(args.expected_rc_db != 'absent', 'Edge conversion requires an existing approved database')
    require(re.fullmatch('[a-f0-9]{40}', args.publisher_commit), 'Exact publisher commit required')
    require(args.expected_rc_db == 'absent' or re.fullmatch('[a-f0-9]{64}', args.expected_rc_db), 'Explicit previous RC database hash or absent required')
    require(not args.execute or args.accept_mutable_alias_window, 'Execution requires explicit mutable DB/signature window acceptance')
    if old_trust_transition:
        require(getattr(args, 'accept_final_old_trust_publication', False), 'Explicit final old-trust publication acceptance required')
        require(re.fullmatch(r'4\.0\.3rc4-[1-9][0-9]*', manifest['version']), 'Old-trust transition is restricted to 4.0.3rc4')
        require(manifest['signature_policy'] == 'optional-existing-signatures; no signer authority asserted', 'Strict manifests cannot use the old-trust transition')
        require(not any(name.endswith('.sig') for name in manifest['files'] if name.startswith('assets/')),
                'Old-trust transition candidate must be entirely unsigned')
    else:
        require(manifest['signature_policy'] == bundle.STRICT_POLICY, 'Signed bootstrap requires strict manifest')
    digest = args.manifest_sha256
    require(bundle.digest(args.bundle / 'manifest.json') == digest, 'Manifest changed after validation')
    target = manifest['files'][f'assets/{DB}.db']
    prefix = 'edge-signed-baseline' if edge_conversion else ('rc4-old-trust' if old_trust_transition else 'rc-baseline')
    snapshot = f'{prefix}-{manifest["version"]}-{digest[:16]}'
    expected_snapshot = assets_for(args.bundle, manifest, digest)
    expected_rc = {p.name: expected_snapshot[p.name] for p in (args.bundle / 'assets').iterdir()}
    db_assets = {name for name in expected_rc if name in DATABASES or name.removesuffix('.sig') in DATABASES}
    if edge_conversion:
        marker = args.scratch / 'edge-signing.json'
        marker.write_text(json.dumps({'schema': 1, 'manifest_sha256': digest, 'target_database_sha256': target,
                                      'snapshot': snapshot, 'signature_policy': bundle.STRICT_POLICY}, sort_keys=True) + '\n')
        marker_asset = Asset(marker, bundle.digest(marker), marker.stat().st_size)
        expected_snapshot[marker.name] = marker_asset
        expected_rc = {marker.name: marker_asset, **expected_rc}
    current = lane_release(transport, args.lane)
    # Older RC publications carried the builder provenance file at the lane
    # root. Preserve that immutable asset during this one-shot transition;
    # silently deleting it would discard the prior build-input evidence.
    if old_trust_transition and current is not None and 'build-inputs.txt' in current['asset_map']:
        provenance = args.scratch / 'previous-build-inputs.txt'
        checksum = transport.read(current, 'build-inputs.txt', destination=provenance)
        retained = Asset(provenance, checksum, provenance.stat().st_size)
        expected_snapshot['build-inputs.txt'] = retained
        expected_rc['build-inputs.txt'] = retained
    if edge_conversion:
        require(current is not None and not current['draft'], 'Published existing edge baseline required')
    prior_snapshot = transport.release(snapshot)
    if old_trust_transition and current is not None:
        require(not any(name in current['asset_map'] for name in (f'{DB}.db.sig', f'{DB}.db.tar.zst.sig')),
                'Refusing old-trust publication over a signed database')
    require(transport.tag_commit(snapshot) in (None, args.publisher_commit), 'Snapshot tag commit differs')
    require(prior_snapshot is None or transport.tag_commit(snapshot) == args.publisher_commit, 'Snapshot tag missing or differs')
    if current is None:
        require(transport.tag_commit(args.lane) in (None, args.publisher_commit), 'Orphan RC tag differs')
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
        if edge_conversion:
            candidate = {p['name']: (args.bundle / 'assets' / p['filename'], p) for p in manifest['packages']}
            bundle.validate_inventory(rows, candidate)
            require('omarchy-mac-keyring' in candidate, 'Approved edge lacks fork trust bootstrap package')
            verify_initial_keyring(candidate['omarchy-mac-keyring'][0], args.trust_policy)
            if selected(current, transport) == args.expected_rc_db:
                require(transport.read(current, f'{DB}.db', public=True) == args.expected_rc_db, 'Public selected edge database differs')
        if old_trust_transition:
            for name in ('omarchy', 'omarchy-settings'):
                require(name in rows and int(bundle.run('vercmp', bundle.field(rows[name], 'VERSION'), manifest['version']).strip()) <= 0,
                        'Old-trust transition cannot downgrade a newer RC/stable selection')
                require(not rows[name].get('PGPSIG'), 'Refusing old-trust publication over signed packages')
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
    plan = {'mode': 'execute' if args.execute else 'dry-run', 'repo': REPO, 'lane': args.lane,
            'snapshot_tag': snapshot, 'manifest_sha256': digest, 'packages': len(manifest['packages']),
            'previous_rc_db': args.expected_rc_db, 'target_rc_db': target,
            'mutable_alias_risk': ('DB aliases are separate assets; interruption can temporarily remove the selected DB' if old_trust_transition
                                   else 'DB and signature are separate assets; clients can fail closed during replacement'),
            'retry': 'Reuse the exact retained artifact and expected prior DB; never rebuild or reseal an interrupted upload',
            'signature_policy': manifest['signature_policy'],
            'final_old_trust_transition': old_trust_transition}
    if not args.execute:
        return plan
    label = 'FINAL unsigned old-trust RC4 transition' if old_trust_transition else ('Signed edge conversion' if edge_conversion else 'Signed RC baseline')
    body = f'{label} {manifest["version"]}.\n\nManifest SHA256: {digest}\nSource: {manifest["source"]["commit"]}\nPublisher: {args.publisher_commit}\n\nPackage integrity verified; this does not assert full installer or physical-hardware qualification.\n'
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
        current = lane_release(transport, args.lane)
        selection_guard(current, args.expected_rc_db, target, transport, expected_rc, db_assets,
                        snapshot, expected_snapshot, args.publisher_commit)
        preflight(current, expected_rc, transport, db_assets, obsolete)
        if current is None:
            transport.create(args.lane, args.publisher_commit, body)
            current = lane_release(transport, args.lane)
        for name, artifact in expected_rc.items():
            if name not in db_assets and name not in current['asset_map']:
                require(bundle.digest(upload / name) == artifact.sha256, 'Upload staging changed')
                transport.upload(args.lane, upload / name)
        # Verify every package/signature, then recheck the selection immediately
        # before replacing DB aliases under the shared workflow writer lock.
        current = lane_release(transport, args.lane)
        preflight(current, expected_rc, transport, db_assets, obsolete)
        require(set(expected_rc) - db_assets <= set(current['asset_map']), 'Missing package/signature after upload')
        selection_guard(current, args.expected_rc_db, target, transport, expected_rc, db_assets,
                        snapshot, expected_snapshot, args.publisher_commit)
        print(json.dumps({'phase': args.lane + '_packages_and_signatures_verified'}), flush=True)
        for name in DATABASES:
            for asset in ([name + '.sig'] if name + '.sig' in expected_rc else []) + [name]:
                artifact = expected_rc[asset]
                path = upload / asset
                require(bundle.digest(path) == artifact.sha256, 'Database staging changed')
                current = lane_release(transport, args.lane)
                if asset in current['asset_map'] and transport.read(current, asset) == artifact.sha256:
                    continue
                transport.upload(args.lane, path, clobber=asset in current['asset_map'])
        current = readback(args.lane, expected_rc, transport, obsolete=obsolete)
        if current['draft']:
            transport.expose(args.lane)
        readback(args.lane, expected_rc, transport, public=True, obsolete=obsolete)
        print(json.dumps({'phase': args.lane + '_database_and_full_inventory_verified_public'}), flush=True)
        for name in sorted(obsolete):
            current = lane_release(transport, args.lane)
            require(selected(current, transport) == target, 'RC changed before obsolete cleanup')
            if name in current['asset_map']:
                if obsolete[name] is not None:
                    require(transport.read(current, name) == obsolete[name], 'Obsolete archive changed; preserving it')
                transport.delete(args.lane, name)
        readback(args.lane, expected_rc, transport, public=True)
    plan['result'] = 'PASS complete snapshot and lane public readback'
    if old_trust_transition:
        plan['next_gate'] = 'Existing clients must install/verify the fork trust anchor before separately approved strict signed bootstrap; no automatic transition'
    return plan



def capture(args, trust_policy=bundle.SIGNING_POLICY):
    lane = getattr(args, 'lane', 'edge')
    require(lane in ('edge', 'rc'), 'Capture lane must be edge or rc')
    require(re.fullmatch('[a-f0-9]{64}', args.database_sha256), 'Approved baseline database SHA256 required')
    require(not args.output.exists(), 'Capture output must be new')
    guard(args.output.parent)
    args.output.mkdir()
    transport = GitHub(args.output)
    release = transport.release(lane, require_prerelease=lane == 'rc')
    require(release is not None, 'Existing approved baseline is missing')
    require(not release['draft'], 'Baseline must already be published')
    require(f'{DB}.db' in release['asset_map'] and transport.read(release, f'{DB}.db', public=True) == args.database_sha256,
            'Published selected database differs from approved baseline')
    path = args.output / f'{DB}.db.tar.zst'
    transport.read(release, path.name, destination=path)
    require(bundle.digest(path) == args.database_sha256, 'Baseline database changed from approved capture')
    records = bundle.database(path)
    catalog = (ROOT / 'packages.json').read_text()
    (args.output / 'catalog.json').write_text(catalog)
    inventory = {p['name'] for p in json.loads(catalog)['packages']}
    sources = args.output / 'sources'; sources.mkdir()
    bundle.copy_file(path, sources / f'{lane}.db')
    source_records = {lane: dict(records)}
    releases = {lane: release}
    origins = {name: lane for name in records if name in inventory}
    # Lane DBs may contain extras (e.g. omarchy-steam-fex on edge). Do not pull
    # those into the RC/signing inventory. Edge may omit omarchy-mac-keyring;
    # Prepare rebuilds that candidate. Missing configured names still fail.
    core = inventory - {'omarchy-mac-keyring'}
    require(core <= set(records), 'Captured inventory is missing required baseline packages')
    records = {name: row for name, row in records.items() if name in inventory}
    require(set(records) in (inventory, core), 'Captured inventory is not the complete baseline')
    overlay_lane = getattr(args, 'overlay_lane', None)
    overlay_hash = getattr(args, 'overlay_database_sha256', None)
    require((overlay_lane is None) == (overlay_hash is None), 'Overlay lane and database hash must be supplied together')
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
    if overlay_lane is not None:
        require(overlay_lane in ('edge', 'rc') and overlay_lane != lane, 'Overlay lane must differ from baseline lane')
        require(re.fullmatch('[a-f0-9]{64}', overlay_hash), 'Approved overlay database SHA256 required')
        overlay = transport.release(overlay_lane, require_prerelease=overlay_lane == 'rc')
        require(overlay is not None and not overlay['draft'], 'Existing approved overlay is missing')
        require(f'{DB}.db' in overlay['asset_map'] and transport.read(overlay, f'{DB}.db', public=True) == overlay_hash,
                'Published overlay database differs from approved overlay')
        overlay_db = args.output / '.overlay.db.tar.zst'
        transport.read(overlay, f'{DB}.db.tar.zst', destination=overlay_db)
        require(bundle.digest(overlay_db) == overlay_hash, 'Overlay database changed from approved capture')
        bundle.copy_file(overlay_db, sources / f'{overlay_lane}.db')
        overlay_records_all = bundle.database(overlay_db)
        source_records[overlay_lane] = overlay_records_all
        releases[overlay_lane] = overlay
        overlay_records = {name: row for name, row in overlay_records_all.items() if name in inventory}
        overlay_dir = args.output / '.overlay-packages'; overlay_dir.mkdir()
        for package_name, row in overlay_records.items():
            name = bundle.safe_name(bundle.field(row, 'FILENAME'))
            require(name in overlay['asset_map'], 'Overlay archive is absent')
            target = overlay_dir / name
            transport.read(overlay, name, destination=target)
            require(target.stat().st_size == int(bundle.field(row, 'CSIZE')) and bundle.digest(target) == bundle.field(row, 'SHA256SUM'),
                    'Captured overlay archive differs from approved database')
            destination = packages / name
            if package_name in records:
                previous = bundle.safe_name(bundle.field(records[package_name], 'FILENAME'))
                (packages / previous).unlink()
            shutil.move(target, destination)
            records[package_name] = row
            origins[package_name] = overlay_lane
        overlay_db.unlink()
        shutil.rmtree(overlay_dir)
        require('omarchy-mac-keyring' in overlay_records, 'Overlay must include the installed trust anchor')
        verify_initial_keyring(packages / bundle.field(overlay_records['omarchy-mac-keyring'], 'FILENAME'), trust_policy)
    bundle.validate_inventory(records, bundle.archives(packages))
    if lane == 'rc':
        require('omarchy-mac-keyring' in records, 'RC capture must include the installed trust anchor')
        verify_initial_keyring(packages / bundle.field(records['omarchy-mac-keyring'], 'FILENAME'), trust_policy)
    # Approved lane DB may contain extras (ignored above). Stage requires
    # database names == archive names, so rebuild a filtered capture DB from the
    # downloaded inventory only. Preserve the approved lane DB hash as provenance.
    lane_database_sha256 = args.database_sha256
    extras = sorted({name for rows in source_records.values() for name in rows if name not in inventory})
    path.unlink()
    for suffix in ['db', 'files', 'db.tar.zst', 'files.tar.zst']:
        (args.output / f'{DB}.{suffix}').unlink(missing_ok=True)
        (packages / f'{DB}.{suffix}').unlink(missing_ok=True)
    names = sorted(p.name for p in packages.glob('*.pkg.tar.*'))
    require(names, 'Filtered capture produced no archives')
    bundle.run('repo-add', '--quiet', f'{DB}.db.tar.zst', *names, cwd=packages)
    for suffix in ['db', 'files']:
        plain = packages / f'{DB}.{suffix}'
        plain.unlink(missing_ok=True)
        bundle.copy_file(packages / f'{DB}.{suffix}.tar.zst', plain)
    for suffix in ['db', 'files', 'db.tar.zst', 'files.tar.zst']:
        src = packages / f'{DB}.{suffix}'
        if src.is_file():
            bundle.copy_file(src, args.output / f'{DB}.{suffix}')
    # Keep packages/ archive-only so stage/archives() does not see repo-add DB files.
    for leftover in packages.glob(f'{DB}.*'):
        leftover.unlink()
    filtered = bundle.database(args.output / f'{DB}.db.tar.zst')
    bundle.validate_inventory(filtered, bundle.archives(packages))
    evidence = {
        'database_sha256': bundle.digest(args.output / f'{DB}.db.tar.zst'),
        'lane_database_sha256': lane_database_sha256,
        'archives': len(records),
        'lane': lane,
        'filtered_extras': extras,
        'overlay_lane': overlay_lane,
        'overlay_database_sha256': overlay_hash,
    }
    evidence['selected'] = {name: {'lane': origins[name], 'filename': bundle.field(row, 'FILENAME'),
                                  'sha256': bundle.field(row, 'SHA256SUM')}
                            for name, row in sorted(records.items())}
    evidence['excluded_catalog_extras'] = {tag: sorted(set(rows) - inventory) for tag, rows in source_records.items()}
    evidence['remote_assets'] = {}
    for tag, observed in releases.items():
        referenced = {bundle.field(row, 'FILENAME') for row in source_records[tag].values()}
        observations = {}
        for name, metadata in sorted(observed['asset_map'].items()):
            classification = ('database' if name.removesuffix('.sig') in DATABASES else
                              'provenance' if name == 'build-inputs.txt' else
                              'db-referenced' if name.removesuffix('.sig') in referenced else 'unreferenced')
            item = {'classification': classification, 'verification': 'metadata-only',
                    'metadata': metadata}
            retained = None
            if name in (f'{DB}.db', f'{DB}.db.tar.zst'):
                retained = sources / f'{tag}.db'
            elif name == 'build-inputs.txt':
                retained = sources / f'{tag}-build-inputs.txt'
                checksum = transport.read(observed, name, destination=retained)
                require(bundle.digest(retained) == checksum, 'Provenance readback differs')
            elif any(origin == tag and bundle.field(records[p], 'FILENAME') == name for p, origin in origins.items()):
                retained = packages / name
            if retained is not None:
                item.update(verification='downloaded-verified', path=retained.relative_to(args.output).as_posix(),
                            sha256=bundle.digest(retained))
            observations[name] = item
        evidence['remote_assets'][tag] = observations
    # Fresh metadata and public selected bytes: do not approve a moving lane.
    for tag, checksum in [(lane, lane_database_sha256)] + ([(overlay_lane, overlay_hash)] if overlay_lane else []):
        current = transport.release(tag, require_prerelease=tag == 'rc')
        require(current is not None and not current['draft'] and f'{DB}.db' in current['asset_map'] and
                transport.read(current, f'{DB}.db', public=True) == checksum,
                f'{tag} database changed during capture')
    bundle.write_json(args.output / 'capture.json', evidence)
    manifest = {'schema': 1, 'files': {p.relative_to(args.output).as_posix(): bundle.digest(p)
                                     for p in sorted(args.output.rglob('*')) if p.is_file()}}
    bundle.write_json(args.output / 'capture-manifest.json', manifest)
    print(json.dumps({**{k: evidence[k] for k in ('database_sha256', 'lane_database_sha256', 'archives', 'lane', 'filtered_extras')},
                      'manifest_sha256': bundle.digest(args.output / 'capture-manifest.json')}))


def check_capture(path, manifest_sha256):
    """Verify an externally approved capture using retained inputs only."""
    require(isinstance(manifest_sha256, str) and re.fullmatch('[a-f0-9]{64}', manifest_sha256),
            'Exact capture manifest SHA256 required')
    require(path.is_dir() and not path.is_symlink(), 'Capture must be a real directory')
    actual = set()
    for item in path.rglob('*'):
        require(not item.is_symlink(), 'Capture symlinks are forbidden')
        require(item.is_file() or item.is_dir(), 'Capture special files are forbidden')
        if item.is_file():
            actual.add(item.relative_to(path).as_posix())
    require('capture-manifest.json' in actual, 'Missing capture manifest')
    require(bundle.digest(path / 'capture-manifest.json') == manifest_sha256, 'Capture manifest differs from approval')
    manifest = json.loads((path / 'capture-manifest.json').read_text())
    require(isinstance(manifest, dict) and set(manifest) == {'schema', 'files'} and
            type(manifest['schema']) is int and manifest['schema'] == 1 and isinstance(manifest['files'], dict),
            'Unsupported capture manifest schema')
    for name, checksum in manifest['files'].items():
        require(isinstance(name, str) and name and not name.startswith('/') and
                '\\' not in name and all(part not in ('', '.', '..') for part in name.split('/')),
                'Unsafe capture relative path')
        require(isinstance(checksum, str) and re.fullmatch('[a-f0-9]{64}', checksum), 'Invalid capture file digest')
    require(actual == set(manifest['files']) | {'capture-manifest.json'} and
            'capture-manifest.json' not in manifest['files'], 'Capture file inventory differs')
    for name, checksum in manifest['files'].items():
        require(bundle.digest(path / name) == checksum, f'Capture file changed: {name}')
    evidence = json.loads((path / 'capture.json').read_text())
    catalog = json.loads((path / 'catalog.json').read_text())
    names = [p['name'] for p in catalog['packages']]
    require(all(isinstance(n, str) and n for n in names) and len(names) == len(set(names)), 'Invalid captured catalog')
    inventory = set(names)
    lane, overlay = evidence['lane'], evidence['overlay_lane']
    require(lane in ('edge', 'rc') and (overlay is None or overlay in ('edge', 'rc') and overlay != lane), 'Invalid captured lanes')
    require((overlay is None) == (evidence['overlay_database_sha256'] is None), 'Invalid overlay approval')
    rows, origins, excluded = {}, {}, {}
    for tag, checksum in [(lane, evidence['lane_database_sha256'])] + ([(overlay, evidence['overlay_database_sha256'])] if overlay else []):
        database = path / 'sources' / f'{tag}.db'
        require(bundle.digest(database) == checksum, 'Captured source database differs')
        source = bundle.database(database)
        if tag == lane:
            require(inventory - {'omarchy-mac-keyring'} <= set(source), 'Captured catalog baseline incomplete')
        excluded[tag] = sorted(set(source) - inventory)
        for name, row in source.items():
            if name in inventory:
                rows[name], origins[name] = row, tag
    require(set(rows) in (inventory, inventory - {'omarchy-mac-keyring'}), 'Captured catalog inventory differs')
    require(not (lane == 'rc' or overlay) or 'omarchy-mac-keyring' in rows, 'Captured trust anchor missing')
    require(not overlay or origins.get('omarchy-mac-keyring') == overlay, 'Overlay must include the installed trust anchor')
    archives = bundle.archives(path / 'packages')
    bundle.validate_inventory(rows, archives)
    for name in DATABASES:
        bundle.validate_inventory(bundle.database(path / name), archives)
    require(bundle.digest(path / f'{DB}.db') == bundle.digest(path / f'{DB}.db.tar.zst') == evidence['database_sha256'], 'Captured database aliases differ')
    require(bundle.digest(path / f'{DB}.files') == bundle.digest(path / f'{DB}.files.tar.zst'), 'Captured files aliases differ')
    selected = {name: {'lane': origins[name], 'filename': bundle.field(row, 'FILENAME'),
                       'sha256': bundle.field(row, 'SHA256SUM')} for name, row in rows.items()}
    require(evidence['selected'] == selected and evidence['archives'] == len(rows), 'Captured package origins differ')
    require(evidence['excluded_catalog_extras'] == excluded and evidence['filtered_extras'] == sorted({n for extra in excluded.values() for n in extra}), 'Captured exclusions differ')
    require(set(evidence['remote_assets']) == set(excluded), 'Captured remote lanes differ')
    for tag, observations in evidence['remote_assets'].items():
        source = bundle.database(path / 'sources' / f'{tag}.db')
        referenced = {bundle.field(row, 'FILENAME') for row in source.values()}
        require({f'{DB}.db', f'{DB}.db.tar.zst'} <= set(observations), 'Missing source DB observations')
        for name, item in observations.items():
            classification = ('database' if name.removesuffix('.sig') in DATABASES else
                              'provenance' if name == 'build-inputs.txt' else
                              'db-referenced' if name.removesuffix('.sig') in referenced else 'unreferenced')
            require(item['classification'] == classification and isinstance(item['metadata'], dict), 'Invalid remote classification')
            retained = (f'sources/{tag}.db' if name in (f'{DB}.db', f'{DB}.db.tar.zst') else
                        f'sources/{tag}-build-inputs.txt' if name == 'build-inputs.txt' else
                        f'packages/{name}' if any(p['lane'] == tag and p['filename'] == name for p in selected.values()) else None)
            if retained:
                require(set(item) == {'classification', 'verification', 'metadata', 'path', 'sha256'} and
                        item['verification'] == 'downloaded-verified' and item['path'] == retained and
                        retained in manifest['files'] and item['sha256'] == manifest['files'][retained],
                        'Invalid downloaded-byte evidence')
            else:
                require(set(item) == {'classification', 'verification', 'metadata'} and item['verification'] == 'metadata-only',
                        'Unverified asset cannot assert downloaded bytes')
    return evidence


def functional_payload(path):
    # libarchive handles zstd/xz irrespective of the runner Python version.
    # PACKAGER, build-date, MTREE and timestamps are reproducibility metadata;
    # file kinds, content, links, modes, ownership and other PKGINFO fields match.
    result = {}
    process = subprocess.Popen(['bsdtar', '-cf', '-', '--format=pax', '@' + str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            for item in archive:
                name = item.name.removeprefix('./').rstrip('/')
                if not name or name in {'.BUILDINFO', '.MTREE'}:
                    continue
                require(name not in result, 'Duplicate package payload entry')
                content = archive.extractfile(item).read() if item.isfile() else b''
                if name == '.PKGINFO':
                    content = b'\n'.join(line for line in content.splitlines() if line and not line.startswith((b'builddate = ', b'packager = ', b'#')))
                result[name] = (item.type, item.mode, item.uid, item.gid, item.linkname, hashlib.sha256(content).hexdigest())
        require(process.wait() == 0, 'libarchive could not read package payload')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill(); process.wait()
    return result


def verify_initial_keyring(path, trust_policy=bundle.SIGNING_POLICY):
    policy = bundle.signing.policy(trust_policy)
    prefix = 'usr/share/pacman/keyrings/'
    public = bundle.run('bsdtar', '-xOf', path, prefix + 'omarchy-mac.gpg')
    require(hashlib.sha256(public).hexdigest() == policy['public_key_sha256'], 'Bootstrap keyring differs from approved production trust anchor')
    trusted = bundle.run('bsdtar', '-xOf', path, prefix + 'omarchy-mac-trusted').decode().strip()
    require(trusted == bundle.signing.trusted_file(policy), 'Bootstrap keyring trust fingerprint differs')
    revoked = bundle.run('bsdtar', '-xOf', path, prefix + 'omarchy-mac-revoked')
    require(revoked == b'', 'Initial bootstrap revocation file must be present and empty')


def reuse_published_extra(incoming, published, database, trust_policy=bundle.SIGNING_POLICY):
    incoming, published = Path(incoming), Path(published)
    require(incoming.name == published.name, 'Extra reuse requires the same immutable filename')
    record = bundle.package_record(incoming)
    require(record['name'] in {'omarchy-keyring', 'omarchy-mac-keyring', 'ttf-jetbrains-mono-nerd-basic'}, 'Ordinary package filename collision')
    rows = bundle.database(database)
    require(record['name'] in rows, 'Published extra is not in the approved current database')
    bundle.validate_inventory({record['name']: rows[record['name']]},
                              {record['name']: (published, bundle.package_record(published))})
    require(functional_payload(incoming) == functional_payload(published), 'Published extra functional payload differs; bump version/pkgrel')
    if record['name'] == 'omarchy-mac-keyring':
        verify_initial_keyring(incoming, trust_policy)
        verify_initial_keyring(published, trust_policy)
    bundle.copy_file(published, incoming)
    require(bundle.digest(incoming) == bundle.digest(published), 'Published extra reuse readback differs')


def stage_input(args, trust_policy=bundle.SIGNING_POLICY):
    capture_evidence = check_capture(args.capture, getattr(args, 'capture_manifest_sha256', None))
    require(not args.candidates.exists(), 'Candidate directory must be new')
    guard(args.candidates.parent)
    built = bundle.archives(args.built)
    require(set(built) == bundle.CANDIDATES, 'Canonical build must produce exactly five release inputs')
    baseline = bundle.archives(args.capture / 'packages')
    release = (args.source / 'version').read_text().strip()
    pkgrel = str(getattr(args, 'pkgrel', ''))
    require(re.fullmatch(r'[1-9][0-9]*', pkgrel), 'Explicit package release number required')
    package_version = f'{release}-{pkgrel}'
    require(capture_evidence['database_sha256'] == bundle.digest(args.capture / f'{DB}.db.tar.zst'), 'Capture provenance database differs')
    conversion = getattr(args, 'edge_conversion', False)
    if conversion:
        require(capture_evidence['lane'] == 'edge' and 'rc' not in release and 'omarchy-mac-keyring' in baseline, 'Conversion producer requires final edge baseline with trust anchor')
    if release == '4.0.3rc5':
        require(capture_evidence['lane'] == 'rc' and 'omarchy-mac-keyring' in baseline, 'RC5 requires the approved published RC4 baseline and trust anchor')
        require(all(re.fullmatch(r'4\.0\.3rc4-[1-9][0-9]*', baseline[name][1]['version']) for name in ('omarchy', 'omarchy-settings')),
                'RC5 initial signing baseline must be RC4')
    args.candidates.mkdir()
    for name, (path, record) in built.items():
        if name in {'omarchy', 'omarchy-settings'}:
            require(record['version'] == package_version,
                    f'{name} package identity must match explicit pkgrel {package_version}')
        if conversion:
            require(name in baseline and path.name == baseline[name][0].name, 'Conversion cannot change package identity')
            require(functional_payload(path) == functional_payload(baseline[name][0]), 'Conversion rebuilt payload differs from published package')
            path = baseline[name][0]
        if name == 'omarchy-mac-keyring':
            verify_initial_keyring(path, trust_policy)
            if name in baseline and path.name == baseline[name][0].name:
                previous = baseline[name][0]
                verify_initial_keyring(previous, trust_policy)
                require(functional_payload(path) == functional_payload(previous), 'Fork keyring payload differs under unchanged filename; bump pkgrel explicitly')
                path = previous
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
                                    release=package_version, output=args.output,
                                    capture=args.capture, capture_manifest_sha256=args.capture_manifest_sha256))
    digest = bundle.digest(args.output / 'manifest.json')
    manifest = validate(args.output, digest, args.source_commit, trust_policy, signed=False, channel='stable' if conversion else 'rc')
    print(json.dumps({'manifest_sha256': digest, 'source_commit': args.source_commit,
                      'packages': len(manifest['packages']), 'qualification': 'build/capture/integrity only; runtime approval is separate'}))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    reuse_parser = commands.add_parser('reuse-extra')
    reuse_parser.add_argument('--incoming', type=Path, required=True)
    reuse_parser.add_argument('--published', type=Path, required=True)
    reuse_parser.add_argument('--database', type=Path, required=True)
    capture_parser = commands.add_parser('capture')
    capture_parser.add_argument('--database-sha256', required=True)
    capture_parser.add_argument('--lane', choices=['edge', 'rc'], default='edge')
    capture_parser.add_argument('--overlay-lane', choices=['edge', 'rc'])
    capture_parser.add_argument('--overlay-database-sha256')
    capture_parser.add_argument('--output', type=Path, required=True)
    check_parser = commands.add_parser('check-capture')
    check_parser.add_argument('--capture', type=Path, required=True)
    check_parser.add_argument('--manifest-sha256', required=True)
    stage_parser = commands.add_parser('stage-input')
    for option in ['capture', 'built', 'candidates', 'source', 'output']:
        stage_parser.add_argument('--' + option, type=Path, required=True)
    stage_parser.add_argument('--capture-manifest-sha256', required=True)
    stage_parser.add_argument('--source-commit', required=True)
    stage_parser.add_argument('--edge-conversion', action='store_true')
    stage_parser.add_argument('--pkgrel', required=True,
                              help='Explicit package release number for the rebuilt package pair')
    eligibility_parser = commands.add_parser('check-eligibility', help='Credential-free approved-input signing preflight')
    eligibility_parser.add_argument('--input', type=Path, required=True)
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
    for sub in (eligibility_parser, prepare_parser, publish):
        sub.add_argument('--manifest-sha256', required=True)
        sub.add_argument('--source-commit', required=True)
        sub.add_argument('--trust-policy', type=Path, default=bundle.SIGNING_POLICY)
    prepare_parser.add_argument('--public-key', type=Path, default=bundle.signing.PUBLIC)
    args = parser.parse_args()
    if args.command == 'reuse-extra':
        reuse_published_extra(args.incoming, args.published, args.database)
    elif args.command == 'capture':
        capture(args)
    elif args.command == 'check-capture':
        evidence = check_capture(args.capture, args.manifest_sha256)
        print(json.dumps({'result': 'PASS', 'manifest_sha256': args.manifest_sha256, 'archives': evidence['archives']}))
    elif args.command == 'stage-input':
        stage_input(args)
    elif args.command == 'check-eligibility':
        manifest = validate(args.input, args.manifest_sha256, args.source_commit, args.trust_policy, signed=False)
        bundle.signing_eligibility(manifest)
        print('PASS signing eligibility', args.input)
    elif args.command == 'prepare':
        prepare(args)
    else:
        manifest = validate(args.bundle, args.manifest_sha256, args.source_commit, args.trust_policy)
        with tempfile.TemporaryDirectory(prefix='rc-bootstrap-', dir=temporary_root()) as temp:
            args.scratch = Path(temp)
            guard(args.scratch)
            print(json.dumps(publish_checked(args, manifest, GitHub(args.scratch)), indent=2))

if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'RC bootstrap stopped: {error}')
