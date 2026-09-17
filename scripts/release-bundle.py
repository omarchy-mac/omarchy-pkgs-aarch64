#!/usr/bin/python3
"""Offline release inventories and explicit RC/final publication; edge updater stays separate."""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

DB = 'omarchy-aarch64'
CANDIDATES = {'omarchy', 'omarchy-settings', 'omarchy-keyring', 'ttf-jetbrains-mono-nerd-basic'}
LEGACY_CANDIDATES = set(CANDIDATES)
CANDIDATES = CANDIDATES | {'omarchy-mac-keyring'}
SIGNING_POLICY = Path(__file__).resolve().parent.parent / 'pkgbuilds/omarchy-mac-keyring/signing-policy.json'
STRICT_POLICY = 'PackageRequired DatabaseRequired TrustedOnly'
_sign_spec = importlib.util.spec_from_file_location('package_signing', Path(__file__).with_name('package-signing.py'))
signing = importlib.util.module_from_spec(_sign_spec)
_sign_spec.loader.exec_module(signing)
CHECKS = {'source_payload', 'package_contract', 'fresh_install', 'released_upgrade', 'review'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs).stdout


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def safe_name(name):
    require(re.fullmatch(r'[A-Za-z0-9_+@.=-]+', name) and name not in {'.', '..'},
            f'Unsafe asset name: {name}')
    return name


def field(data, key):
    values = data.get(key, [])
    require(len(values) == 1 and values[0], f'Expected one {key}')
    return values[0]


def pkginfo(path):
    info = {}
    for line in run('bsdtar', '-xOf', path, '.PKGINFO').decode().splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            info.setdefault(key, []).append(value)
    return info


def database(path):
    result = {}
    for name in run('bsdtar', '-tf', path).decode().splitlines():
        if not name.endswith('/desc'):
            continue
        data, key = {}, None
        for line in run('bsdtar', '-xOf', path, name).decode().splitlines():
            if line.startswith('%') and line.endswith('%'):
                key = line.strip('%')
                data[key] = []
            elif line and key:
                data[key].append(line)
        package = field(data, 'NAME')
        require(package not in result, f'Duplicate database package: {package}')
        result[package] = data
    require(result, 'Empty repository database')
    return result


def package_record(path):
    info = pkginfo(path)
    arch = field(info, 'arch')
    require(arch in {'any', 'aarch64'}, f'Unsupported package architecture: {path}')
    return dict(name=field(info, 'pkgname'), version=field(info, 'pkgver'), arch=arch,
                filename=safe_name(path.name), sha256=digest(path), depends=info.get('depend', []))


def archives(directory):
    found = {}
    require(directory.is_dir(), f'Archive directory missing: {directory}')
    for path in sorted(directory.iterdir()):
        # build-inputs.txt is the builder's declared provenance, not an archive.
        if path.name == 'build-inputs.txt':
            continue
        require(path.is_file() and not path.is_symlink(), f'Unexpected archive input: {path}')
        if path.name.endswith('.sig'):
            require(not path.name[:-4].endswith('.sig') and Path(str(path)[:-4]).is_file(), f'Orphan signature: {path}')
            continue
        require('.pkg.tar.' in path.name, f'Unexpected archive input: {path}')
        record = package_record(path)
        require(record['name'] not in found, f'Duplicate package: {record["name"]}')
        found[record['name']] = (path, record)
    return found


def copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    run('cp', '--reflink=auto', '--', source, destination)


def source_identity(source, repository, commit):
    actual_commit = run('git', '-C', repository, 'rev-parse', f'{commit}^{{commit}}').decode().strip()
    require(re.fullmatch('[0-9a-f]{40}', actual_commit), 'Unsupported source commit identity')
    tracked = {}
    entries = run('git', '-C', repository, 'ls-tree', '-rz', '--full-tree', actual_commit)
    for entry in entries.split(b'\0'):
        if not entry:
            continue
        metadata, raw_name = entry.split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        name = raw_name.decode()
        require(kind == 'blob' and mode in {'100644', '100755', '120000'}, f'Unsupported source entry: {name}')
        path = source / name
        require(path.is_file() or path.is_symlink(), f'Source path missing: {name}')
        if mode == '120000':
            require(path.is_symlink(), f'Source symlink changed: {name}')
            content = os.readlink(path).encode()
        else:
            require(not path.is_symlink(), f'Source file became symlink: {name}')
            content = path.read_bytes()
            require(bool(path.stat().st_mode & 0o111) == (mode == '100755'), f'Source executable mode changed: {name}')
        blob = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
        require(blob == oid, f'Source bytes differ from commit: {name}')
        tracked[name] = {'mode': mode, 'sha256': hashlib.sha256(content).hexdigest()}
    actual, actual_dirs = set(), set()
    for root, dirs, files in os.walk(source, followlinks=False):
        if Path(root) == source:
            dirs[:] = [d for d in dirs if d != '.git']
            files = [f for f in files if f != '.git']
        for item in list(dirs):
            path = Path(root) / item
            if path.is_symlink():
                files.append(item)
                dirs.remove(item)
            else:
                actual_dirs.add(path.relative_to(source).as_posix())
        actual.update((Path(root) / item).relative_to(source).as_posix() for item in files)
    expected_dirs = {str(parent) for name in tracked for parent in Path(name).parents if str(parent) != '.'}
    require(actual == set(tracked) and actual_dirs == expected_dirs,
            'Source contains untracked/ignored paths or missing tracked paths; use an exact export')
    pin = (source / 'build-inputs/omarchy-pkgs-revision').read_text().strip()
    require(re.fullmatch('[0-9a-f]{40}', pin), 'Missing immutable recipe pin')
    return {'commit': actual_commit, 'files': tracked, 'recipe_commit': pin,
            'builder_sha256': digest(source / 'build-packages.sh'),
            'overlay_sha256': digest(source / 'build-inputs/omarchy-first-run-packages.patch')}


def release_version(tag):
    match = re.fullmatch(r'v?([0-9]+\.[0-9]+\.[0-9]+(?:rc[1-9][0-9]*)?)(?:-([1-9][0-9]*))?', tag)
    require(match, 'Release must be X.Y.Z[rcN][-pkgrel], with attached rcN')
    version = match[1] + '-' + (match[2] or '1')
    return version, match[1], 'rc' if 'rc' in match[1] else 'stable'


def build_db(directory):
    names = sorted(p.name for p in directory.iterdir() if '.pkg.tar.' in p.name and not p.name.endswith('.sig'))
    run('repo-add', '--quiet', '--include-sigs', DB + '.db.tar.zst', *names, cwd=directory)
    for suffix in ['db', 'files']:
        plain = directory / f'{DB}.{suffix}'
        plain.unlink()
        shutil.copyfile(directory / f'{DB}.{suffix}.tar.zst', plain)
    for old in directory.glob('*.old'):
        old.unlink()


def validate_inventory(db, packages):
    require(set(db) == set(packages), 'Database/archive package inventories differ')
    for name, data in db.items():
        path, record = packages[name]
        require(field(data, 'FILENAME') == path.name, f'Database filename mismatch: {name}')
        require(field(data, 'SHA256SUM') == record['sha256'], f'Database checksum mismatch: {name}')
        require(field(data, 'VERSION') == record['version'] and field(data, 'ARCH') == record['arch'],
                f'Database identity mismatch: {name}')
        require(int(field(data, 'CSIZE')) == path.stat().st_size, f'Database size mismatch: {name}')


def stage(args):
    require(not args.output.exists(), 'Bundle output exists; retained bundles cannot be overwritten')
    version, pkgver, channel = release_version(args.release)
    source = source_identity(args.source.resolve(), args.source_git or args.source, args.source_commit)
    require((args.source / 'version').read_text().strip() == pkgver, 'Source/runtime release version differs')
    baseline = archives(args.base_packages)
    base_db = database(args.base_db)
    validate_inventory(base_db, baseline)
    candidate = archives(args.candidates)
    build_input_path = args.candidates / 'build-inputs.txt'
    require(build_input_path.is_file(), 'Candidate build-inputs.txt is required')
    build_inputs = {}
    for line in build_input_path.read_text().splitlines():
        if re.match(r'^[a-z_]+=', line):
            key, value = line.split('=', 1)
            require(key not in build_inputs, 'Duplicate build provenance field')
            build_inputs[key] = value
    expected_inputs = {'recipe_commit': source['recipe_commit'], 'recipe_pin': source['recipe_commit'],
                       'custom_recipes': '0', 'source_commit': source['commit'],
                       'source_version': pkgver, 'source_dirty': '0'}
    require(all(build_inputs.get(key) == value for key, value in expected_inputs.items()),
            'Candidate build provenance differs from exact source/pinned release recipes')
    require(set(candidate) in (LEGACY_CANDIDATES, CANDIDATES), 'Candidate must contain the atomic pair, upstream keyring/font and optional bootstrap fork keyring')
    for name in ['omarchy', 'omarchy-settings']:
        record = candidate[name][1]
        require(record['version'] == version and record['arch'] == 'aarch64', f'Candidate pair mismatch: {name}')
    dependencies = candidate['omarchy'][1]['depends']
    require({'omarchy-settings=' + pkgver, 'snapper', 'iwd', 'networkmanager', 'omarchy-keyring',
             'ttf-jetbrains-mono-nerd-basic'} <= set(dependencies), 'Candidate hard dependencies are incomplete')
    require(not any(re.match(r'limine(?:$|[-<>=])', dep) for dep in dependencies), 'Candidate requires Limine')
    for name, (path, record) in candidate.items():
        if name in baseline:
            old = baseline[name][1]
            require(path.name != old['filename'] or record['sha256'] == old['sha256'],
                    f'Same filename with different bytes: {path.name}; reuse validated bytes or bump pkgrel')
            require(int(run('vercmp', record['version'], old['version']).strip()) >= 0,
                    f'Candidate downgrades baseline package: {name}')
    combined = {**baseline, **candidate}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.release-bundle-', dir=args.output.parent))
    try:
        for subdir, inventory in [('assets', combined), ('rollback', baseline)]:
            destination = staging / subdir
            destination.mkdir()
            for path, record in inventory.values():
                copy_file(path, destination / record['filename'])
                signature = Path(str(path) + '.sig')
                if signature.is_file():
                    copy_file(signature, destination / signature.name)
            build_db(destination)
        # Preserve the exact captured selected database, while retaining a
        # complete freshly generated files database for its archived packages.
        for suffix in ['db', 'db.tar.zst']:
            copy_file(args.base_db, staging / 'rollback' / f'{DB}.{suffix}')
        validate_inventory(database(staging / 'assets' / f'{DB}.db'), combined)
        copy_file(build_input_path, staging / 'provenance/build-inputs.txt')
        files = {p.relative_to(staging).as_posix(): digest(p) for p in sorted(staging.rglob('*')) if p.is_file()}
        manifest = {'schema': 1, 'version': version, 'package_release': version,
                    'channel': channel, 'source': source,
                    'baseline_db_sha256': digest(args.base_db), 'publisher_sha256': digest(Path(__file__)),
                    'candidates': sorted(candidate),
                    'reused_candidates': sorted(name for name in candidate if name in baseline and candidate[name][1]['sha256'] == baseline[name][1]['sha256']),
                    'candidate_build_inputs_sha256': digest(build_input_path), 'build_inputs': expected_inputs,
                    'packages': [v[1] for k, v in sorted(combined.items())],
                    'files': files, 'signature_policy': 'optional-existing-signatures; no signer authority asserted'}
        if re.fullmatch(r'.+-[1-9][0-9]*', version):
            manifest['pkgrel'] = version.rsplit('-', 1)[1]
        write_json(staging / 'manifest.json', manifest)
        check(staging)
        staging.rename(args.output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    print(f'BUNDLE {args.output} {digest(args.output / "manifest.json")}')


def check(bundle, trust_policy=SIGNING_POLICY):
    manifest = json.loads((bundle / 'manifest.json').read_text())
    require(manifest.get('schema') == 1, 'Unsupported bundle schema')
    version, pkgver, channel = release_version(manifest['version'])
    require(version == manifest['version'] and channel == manifest['channel'], 'Malformed bundle version/channel')
    require(manifest['candidates'] in (sorted(LEGACY_CANDIDATES), sorted(CANDIDATES)), 'Malformed candidate inventory')
    candidates = set(manifest['candidates'])
    strict = manifest['signature_policy'] == STRICT_POLICY
    require(strict or manifest['signature_policy'] == 'optional-existing-signatures; no signer authority asserted', 'Unknown signature policy')
    require(re.fullmatch('[0-9a-f]{64}', manifest['publisher_sha256']), 'Malformed publisher identity')
    source = manifest['source']
    require(re.fullmatch('[0-9a-f]{40}', source['commit']) and re.fullmatch('[0-9a-f]{40}', source['recipe_commit']), 'Malformed source or recipe identity')
    require(re.fullmatch('[0-9a-f]{64}', source['builder_sha256']) and re.fullmatch('[0-9a-f]{64}', source['overlay_sha256']), 'Malformed builder or overlay identity')
    require(isinstance(source['files'], dict) and 'version' in source['files'], 'Missing source file inventory')
    for name, item in source['files'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and item['mode'] in {'100644', '100755', '120000'}
                and re.fullmatch('[0-9a-f]{64}', item['sha256']), 'Malformed source file inventory')
    files = manifest['files']
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file() or p.is_symlink()}
    require(actual == set(files) | {'manifest.json'}, 'Bundle has missing or unexpected files')
    for name, expected in files.items():
        require(len(Path(name).parts) == 2 and Path(name).parts[0] in {'assets', 'rollback', 'provenance'}, 'Unsafe bundle path')
        safe_name(Path(name).name)
        path = bundle / name
        require(not path.is_symlink() and digest(path) == expected, f'Bundle changed: {name}')
    for directory in ['assets', 'rollback']:
        base = bundle / directory
        package_paths = {p.name for p in base.iterdir() if '.pkg.tar.' in p.name and not p.name.endswith('.sig')}
        data = database(base / f'{DB}.db')
        require(package_paths == {field(v, 'FILENAME') for v in data.values()}, 'Bundle DB/file inventory differs')
        require(digest(base / f'{DB}.db') == digest(base / f'{DB}.db.tar.zst'), 'Database aliases differ')
        require(digest(base / f'{DB}.files') == digest(base / f'{DB}.files.tar.zst'), 'Files aliases differ')
        files_data = database(base / f'{DB}.files')
        require(set(files_data) == set(data), 'Files database is incomplete')
        for name, metadata in data.items():
            filename = safe_name(field(metadata, 'FILENAME'))
            path = base / filename
            require(field(metadata, 'SHA256SUM') == files[f'{directory}/{filename}']
                    and int(field(metadata, 'CSIZE')) == path.stat().st_size, 'Database package bytes differ')
            info = pkginfo(path)
            require(field(info, 'pkgname') == name and field(info, 'pkgver') == field(metadata, 'VERSION')
                    and field(info, 'arch') == field(metadata, 'ARCH'), 'Database package metadata differs')
            require(field(info, 'arch') in {'any', 'aarch64'}, 'Foreign package architecture')
    require(digest(bundle / 'provenance/build-inputs.txt') == manifest['candidate_build_inputs_sha256'], 'Build provenance bytes changed')
    require(manifest['build_inputs'] == {'recipe_commit': source['recipe_commit'], 'recipe_pin': source['recipe_commit'],
                                      'custom_recipes': '0', 'source_commit': source['commit'],
                                      'source_version': pkgver, 'source_dirty': '0'}, 'Inconsistent build provenance')
    records = manifest['packages']
    require(len({x['name'] for x in records}) == len(records), 'Duplicate manifest package')
    require({x['name'] for x in records} == set(database(bundle / 'assets' / f'{DB}.db')), 'Manifest package inventory differs')
    for item in records:
        info = pkginfo(bundle / 'assets' / safe_name(item['filename']))
        require(field(info, 'pkgname') == item['name'] and field(info, 'pkgver') == item['version']
                and field(info, 'arch') == item['arch'] and info.get('depend', []) == item['depends'], 'Manifest package metadata differs')
        require(item['sha256'] == files['assets/' + item['filename']], 'Manifest package digest differs')
    pair = {x['name']: x for x in records if x['name'] in {'omarchy', 'omarchy-settings'}}
    require(len(pair) == 2 and all(x['version'] == version and x['arch'] == 'aarch64' for x in pair.values()), 'Invalid atomic pair')
    dependencies = set(pair['omarchy']['depends'])
    pkgver = version.rsplit('-', 1)[0]
    require({'omarchy-settings=' + pkgver, 'snapper', 'iwd', 'networkmanager', 'omarchy-keyring',
             'ttf-jetbrains-mono-nerd-basic'} <= dependencies, 'Incomplete candidate dependencies')
    require(not any(re.match(r'limine(?:$|[-<>=])', item) for item in dependencies), 'Unexpected Limine dependency')
    rollback = database(bundle / 'rollback' / f'{DB}.db')
    current = {x['name']: x for x in records}
    require(set(current) == set(rollback) | candidates, 'Bundle dropped or invented baseline packages')
    for name in set(rollback) - candidates:
        require(current[name]['sha256'] == field(rollback[name], 'SHA256SUM'), 'Bundle changed an unrelated baseline package')
    require(manifest['baseline_db_sha256'] == digest(bundle / ('provenance/captured-baseline.db' if strict else f'rollback/{DB}.db')), 'Rollback identity mismatch')
    if strict:
        require(candidates == CANDIDATES and 'omarchy-mac-keyring' in dependencies, 'Strict feed requires the fork keyring package and dependency')
        require(manifest['signing_policy'] == signing.policy(trust_policy), 'Signer differs from independently trusted policy')
        keyring_archive = bundle / 'assets' / next(item['filename'] for item in records if item['name'] == 'omarchy-mac-keyring')
        key_prefix = 'usr/share/pacman/keyrings/'
        require(run('bsdtar', '-xOf', keyring_archive, key_prefix + 'omarchy-mac.gpg') == (bundle / 'provenance/signing-public.gpg').read_bytes(), 'Fork keyring payload differs from trusted public key')
        require(run('bsdtar', '-xOf', keyring_archive, key_prefix + 'omarchy-mac-trusted').decode().strip() == signing.trusted_file(manifest['signing_policy']), 'Fork keyring trust fingerprint differs')
        ring = signing.Keyring(bundle / 'provenance/signing-public.gpg', trust_policy)
        try:
            for directory in ['assets', 'rollback']:
                for path in signing.packages(bundle / directory) + signing.databases(bundle / directory):
                    ring.verify(path)
                for metadata in database(bundle / directory / f'{DB}.db').values():
                    require(field(metadata, 'PGPSIG'), 'Missing embedded package signature')
        finally:
            ring.close()
    return manifest



def seal(args):
    """Derive a signed bundle; keep the qualified unsigned input unchanged."""
    original = check(args.bundle, args.trust_policy)
    require(original['signature_policy'] != STRICT_POLICY, 'Already sealed; reuse its exact signatures')
    require(set(original['candidates']) == CANDIDATES, 'Stage the fork keyring before sealing')
    require(not args.output.exists(), 'Signed output already exists')
    primary = signing.policy(args.trust_policy)
    require(digest(args.public_key) == primary['public_key_sha256'], 'Public key differs from trust policy')
    staging = Path(tempfile.mkdtemp(prefix='.signed-bundle-', dir=args.output.parent))
    try:
        for path in args.bundle.rglob('*'):
            if path.is_file():
                copy_file(path, staging / path.relative_to(args.bundle))
        copy_file(args.bundle / 'rollback' / f'{DB}.db', staging / 'provenance/captured-baseline.db')
        copy_file(args.public_key, staging / 'provenance/signing-public.gpg')
        ring = signing.Keyring(args.public_key, args.trust_policy, secret=True)
        try:
            for directory in ['assets', 'rollback']:
                base = staging / directory
                for path in signing.packages(base):
                    ring.sign(path)
                build_db(base)
                for path in signing.databases(base):
                    ring.sign(path)
        finally:
            ring.close()
        manifest = dict(original)
        manifest.update(signature_policy=STRICT_POLICY, signing_policy=primary,
                        unsigned_manifest_sha256=digest(args.bundle / 'manifest.json'),
                        publisher_sha256=digest(Path(__file__)))
        manifest['files'] = {p.relative_to(staging).as_posix(): digest(p) for p in sorted(staging.rglob('*'))
                             if p.is_file() and p.name != 'manifest.json'}
        write_json(staging / 'manifest.json', manifest)
        check(staging, args.trust_policy)
        staging.rename(args.output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    print('SIGNED', args.output, digest(args.output / 'manifest.json'))

def receipt(bundle, path):
    data = json.loads(path.read_text())
    require(data.get('manifest_sha256') == digest(bundle / 'manifest.json'), 'Validation receipt is for different bundle bytes')
    require(data.get('checks') == {name: 'pass' for name in CHECKS}, 'Required validation gates have not all passed')
    report = path.parent / data['report']
    require(report.is_file() and digest(report) == data['report_sha256'], 'Validation report missing or changed')
    return data


def remote_assets(repo, tag):
    # An absent lane must be provisioned explicitly; API/network errors are not
    # interpreted as absence and cannot trigger accidental release creation.
    value = json.loads(run('gh', 'release', 'view', tag, '--repo', repo, '--json', 'assets'))
    result = {}
    for item in value['assets']:
        name = safe_name(item['name'])
        require(name not in result, 'Duplicate remote asset')
        result[name] = item
    return result


def remote_digest(repo, tag, name, metadata, temporary):
    value = metadata.get('digest') or ''
    if re.fullmatch('sha256:[0-9a-f]{64}', value):
        return value[7:]
    output = temporary / tag / name
    output.parent.mkdir(parents=True, exist_ok=True)
    run('gh', 'release', 'download', tag, '--repo', repo, '--pattern', name, '--dir', output.parent, '--clobber')
    return digest(output)


def publish(args, allow_final_edge=False):
    manifest = check(args.bundle, args.trust_policy)
    require(manifest['signature_policy'] == STRICT_POLICY, 'Unsigned bundle publication is forbidden')
    receipt(args.bundle, args.validation)
    require(args.lane == manifest['channel'] or (allow_final_edge and args.lane == 'edge' and manifest['channel'] == 'stable'),
            'RC may only target rc; final stable/legacy-edge requires promotion')
    with tempfile.TemporaryDirectory(prefix='release-publish-') as temporary:
        temp = Path(temporary)
        existing = remote_assets(args.repo, args.lane)
        selected = existing.get(f'{DB}.db')
        target_digest = digest(args.bundle / 'assets' / f'{DB}.db')
        already_selected = False
        if selected:
            selected_digest = remote_digest(args.repo, args.lane, f'{DB}.db', selected, temp)
            already_selected = selected_digest == target_digest
            require(selected_digest in {manifest['baseline_db_sha256'], target_digest},
                    'Lane changed since baseline capture; restage without dropping newer packages')
        else:
            # An interrupted first publication is resumable only when every
            # existing byte belongs to this exact planned bundle.
            for name, metadata in existing.items():
                path = args.bundle / 'assets' / name
                require(path.is_file() and remote_digest(args.repo, args.lane, name, metadata, temp) == digest(path),
                        'Lane has unrelated partial assets but no selected database')
        uploads = []
        for path in sorted((args.bundle / 'assets').iterdir()):
            if '.pkg.tar.' not in path.name:
                continue
            old = existing.get(path.name)
            if old:
                require(remote_digest(args.repo, args.lane, path.name, old, temp) == digest(path),
                        f'Remote filename collision: {path.name}')
            else:
                uploads.append(path)
        snapshot = f'bundle-{manifest["version"]}-{digest(args.bundle / "manifest.json")[:16]}'
        # Planning intentionally has no remote mutation mode. The complete
        # local bundle and rollback inventory are retained for a separately
        # reviewed publication operation under the shared writer lock.
        plan = {
            'schema': 1, 'mode': 'plan-only', 'lane': args.lane, 'repo': args.repo,
            'bundle_manifest_sha256': digest(args.bundle / 'manifest.json'),
            'snapshot_tag': snapshot, 'already_selected': already_selected,
            'required_writer_exclusion': 'edge-publish concurrency or all other writers paused',
            'selected_db_before': remote_digest(args.repo, args.lane, f'{DB}.db', selected, temp) if selected else None,
            'selected_db_after': target_digest,
            'steps': [
                {'operation': 'retain_complete_immutable_snapshot', 'bundle': str(args.bundle.resolve()),
                 'tag': snapshot, 'include': ['manifest.json', 'assets', 'rollback', 'provenance'],
                 'validation': str(args.validation.resolve()), 'rule': 'verify all snapshot bytes before any lane mutation'},
                *[{'operation': 'upload_package_without_clobber', 'sha256': digest(path),
                   'argv': ['gh', 'release', 'upload', args.lane, str(path.resolve()), '--repo', args.repo]}
                  for path in uploads],
                {'operation': 'recheck_selected_database', 'expected_sha256':
                 remote_digest(args.repo, args.lane, f'{DB}.db', selected, temp) if selected else None},
                *[{'operation': 'replace_database_alias', 'sha256': digest(args.bundle / 'assets' / f'{DB}.{suffix}'),
                   'argv': ['gh', 'release', 'upload', args.lane,
                            str((args.bundle / 'assets' / f'{DB}.{suffix}').resolve()), '--repo', args.repo, '--clobber']}
                  for suffix in ['files.tar.zst', 'files', 'db.tar.zst', 'db'] if not already_selected],
                {'operation': 'readback_selected_database_and_all_referenced_assets', 'expected_sha256': target_digest},
            ],
            'failure_rule': 'stop on first failure; do not select a database until every referenced archive and immutable snapshot has verified bytes',
            'retention_rule': 'never delete the prior snapshot or clobber a package filename with different bytes',
        }
        if not args.mutable_alias:
            plan['steps'] = [plan['steps'][0],
                {'operation': 'upload_complete_signed_snapshot_without_clobber', 'tag': snapshot,
                 'assets': [{'path': str(path.resolve()), 'sha256': digest(path)}
                            for path in sorted((args.bundle / 'assets').iterdir())],
                 'rule': 'read existing snapshot asset hashes first; reject every different-byte collision'},
                {'operation': 'verify_public_snapshot_with_strict_pacman_trust', 'tag': snapshot},
                {'operation': 'activate_authenticated_immutable_server',
                 'server': f'https://github.com/{args.repo}/releases/download/{snapshot}',
                 'requirement': 'client must support this exact reviewed Server URL; stop if unavailable'}]
            plan['activation'] = 'immutable snapshot; no mutable lane database writes'
        else:
            plan['activation'] = 'explicit mutable alias window; clients may fail closed until matched DB/signature readback'
            replacements = []
            for step in plan['steps']:
                if step['operation'] == 'replace_database_alias':
                    path = Path(step['argv'][4])
                    signature = Path(str(path) + '.sig')
                    sigstep = dict(step, operation='replace_database_signature')
                    sigstep['sha256'] = digest(signature)
                    sigstep['argv'] = list(step['argv']); sigstep['argv'][4] = str(signature)
                    replacements.append(sigstep)
                replacements.append(step)
            plan['steps'] = replacements
        return plan


def promote(args):
    final, rc, edge = (check(path, args.trust_policy) for path in [args.bundle, args.rc_bundle, args.edge_bundle])
    receipt(args.bundle, args.validation)
    receipt(args.rc_bundle, args.rc_validation)
    receipt(args.edge_bundle, args.edge_validation)
    require(rc['channel'] == 'rc' and final['channel'] == edge['channel'] == 'stable', 'Promotion requires tested RC and separately built final bundles')
    require(re.sub(r'rc[0-9]+(?=-)', '', rc['version']).split('-')[0] == final['version'].split('-')[0], 'Final version does not graduate this RC')
    changed = {name for name in set(rc['source']['files']) | set(final['source']['files'])
               if rc['source']['files'].get(name) != final['source']['files'].get(name)}
    require(changed == {'version'}, 'Final source must differ from tested RC only in version')
    for key in ['recipe_commit', 'builder_sha256', 'overlay_sha256']:
        require(rc['source'][key] == final['source'][key], f'Promotion changed {key}')
    require(rc['publisher_sha256'] == final['publisher_sha256'] == edge['publisher_sha256'], 'Publisher changed since RC qualification')
    require(edge['source'] == final['source'] and edge['version'] == final['version'], 'Legacy edge bundle is not the same final source')
    final_candidates = {x['name']: x['sha256'] for x in final['packages'] if x['name'] in CANDIDATES}
    require(final_candidates == {x['name']: x['sha256'] for x in edge['packages'] if x['name'] in CANDIDATES}, 'Legacy edge bundle must use exactly the validated final artifacts')
    require({x['name']: x['sha256'] for x in rc['packages'] if x['name'] in {'omarchy', 'omarchy-settings'}} !=
            {x['name']: x['sha256'] for x in final['packages'] if x['name'] in {'omarchy', 'omarchy-settings'}}, 'Final pair must be rebuilt, not relabeled')
    args.lane = 'stable'
    stable_plan = publish(args)
    args.bundle, args.validation, args.lane = args.edge_bundle, args.edge_validation, 'edge'
    edge_plan = publish(args, allow_final_edge=True)
    return {'mode': 'plan-only', 'stable': stable_plan, 'legacy_edge': edge_plan,
            'warning': 'Both lane preflights passed; cross-lane publication is not atomic and must retain both prior snapshots'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    staging = commands.add_parser('stage')
    for flag in ['base-db', 'base-packages', 'candidates', 'source', 'output']:
        staging.add_argument('--' + flag, type=Path, required=True)
    staging.add_argument('--source-git', type=Path)
    staging.add_argument('--source-commit', required=True)
    staging.add_argument('--release', required=True)
    checking = commands.add_parser('check')
    checking.add_argument('bundle', type=Path)
    checking.add_argument('--trust-policy', type=Path, default=SIGNING_POLICY)
    sealing = commands.add_parser('seal')
    sealing.add_argument('--bundle', type=Path, required=True)
    sealing.add_argument('--output', type=Path, required=True)
    sealing.add_argument('--public-key', type=Path, default=signing.PUBLIC)
    sealing.add_argument('--trust-policy', type=Path, default=SIGNING_POLICY)
    for command in ['publish', 'promote']:
        entry = commands.add_parser(command)
        entry.add_argument('--bundle', type=Path, required=True)
        entry.add_argument('--validation', type=Path, required=True)
        entry.add_argument('--repo', required=True)
        entry.add_argument('--trust-policy', type=Path, default=SIGNING_POLICY)
        entry.add_argument('--mutable-alias', action='store_true', help='Explicitly accept transient DB/signature mismatch; immutable activation is default')
        if command == 'publish':
            entry.add_argument('--lane', choices=['rc'], required=True)
        else:
            for option in ['rc-bundle', 'rc-validation', 'edge-bundle', 'edge-validation']:
                entry.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'stage':
        stage(args)
    elif args.command == 'check':
        check(args.bundle, args.trust_policy)
        print('PASS', args.bundle)
    elif args.command == 'seal':
        seal(args)
    else:
        plan = publish(args) if args.command == 'publish' else promote(args)
        print(json.dumps(plan, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, UnicodeError, OSError, subprocess.CalledProcessError) as error:
        print(f'Error: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr.decode(errors='replace'), file=sys.stderr)
        sys.exit(1)
