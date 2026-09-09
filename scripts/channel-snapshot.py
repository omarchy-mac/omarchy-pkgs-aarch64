#!/usr/bin/python3
"""Prepare, verify, promote and publish complete ARM channel snapshots."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

CHANNELS = ('stable', 'rc', 'edge')
PAIRS = {'omarchy', 'omarchy-settings', 'omarchy-dev', 'omarchy-settings-dev'}
STACK = {'hyprland', 'hyprtoolkit', 'hyprland-guiutils'}
DATABASES = ('omarchy', 'omarchy-aarch64')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_info(path):
    fields = {}
    for line in run('bsdtar', '-xOf', str(path), '.PKGINFO').splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            fields.setdefault(key, []).append(value)
    return fields


def inspect_package(path):
    info = read_info(path)
    require(info['arch'][0] in ('aarch64', 'any'), f'Foreign architecture: {path.name}')
    require(re.fullmatch(r'[A-Za-z0-9@_+.-]+', path.name), f'Unsafe filename: {path.name}')
    row = dict(name=info['pkgname'][0], version=info['pkgver'][0], filename=path.name,
               sha256=sha(path), depends=info.get('depend', []), provides=info.get('provides', []))
    signature = path.with_name(path.name + '.sig')
    if signature.exists():
        row['signature_sha256'] = sha(signature)
    return row


def check_identity(manifest):
    channel = manifest['channel']
    require(channel in CHANNELS, 'Invalid package channel')
    packages = {p['name']: p for p in manifest['packages']}
    require(len(packages) == len(manifest['packages']), 'Duplicate package identity')
    wanted = ('omarchy-dev', 'omarchy-settings-dev') if channel == 'edge' else ('omarchy', 'omarchy-settings')
    require(set(wanted) <= packages.keys(), f'{channel} requires its complete package pair')
    if channel != 'edge':
        require(not {'omarchy-dev', 'omarchy-settings-dev'} & packages.keys(), 'RC/stable must not contain development packages')
    require(packages[wanted[0]]['version'] == packages[wanted[1]]['version'], 'Mismatched desktop/settings versions')
    require(STACK <= packages.keys(), 'Snapshot is missing the selected compositor stack')
    if not manifest.get('bootstrap', False):
        require('snapper' in packages[wanted[0]]['depends'], 'Desktop must depend on Snapper')
    else:
        require(channel == 'stable' and packages['omarchy']['version'] == '4.0.2-2'
                and manifest['source_sha'] == '291a6989e2021afb4394199b2d13dbe3e5ad0a55',
                'Bootstrap is only for the captured published 4.0.2-2 baseline')
    require(not any(re.split(r'[<>=]', dep)[0].startswith('limine') for dep in packages[wanted[0]]['depends']), 'ARM desktop must not depend on Limine')
    require(set(manifest['required_packages']) <= packages.keys(), 'Snapshot dropped a managed overlay/dependency package')
    if channel == 'stable':
        require('rc' not in packages[wanted[0]]['version'], 'An RC version cannot be promoted as stable')
    for row in manifest['packages']:
        require(re.fullmatch(r'[A-Za-z0-9@_+.-]+', row['filename']), 'Unsafe package filename')
        require(re.fullmatch(r'[0-9a-f]{64}', row['sha256']), 'Invalid package hash')
    for key in ('source_sha', 'recipe_sha', 'publisher_sha'):
        if key == 'recipe_sha' and manifest.get('bootstrap') and manifest[key] is None:
            continue  # Historical published baseline: never invent its recipe provenance.
        require(isinstance(manifest[key], str) and re.fullmatch(r'[0-9a-f]{40}', manifest[key]), f'{key} must be an immutable Git SHA')

    if 'desktop_build' in manifest:
        build = manifest['desktop_build']
        require(isinstance(build, dict), 'Invalid desktop build provenance')
        for key in ('source_sha', 'recipe_sha', 'publisher_sha'):
            require(isinstance(build.get(key), str) and re.fullmatch(r'[0-9a-f]{40}', build[key]), 'Invalid desktop build provenance')
        require(all(build[key] == manifest[key] for key in ('source_sha', 'recipe_sha')), 'Desktop build inputs differ from snapshot')


def write_manifest(directory, manifest):
    (directory / 'channel-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')


def verify(directory, keyring='/etc/pacman.d/gnupg/pubring.gpg'):
    manifest = json.loads((directory / 'channel-manifest.json').read_text())
    require(manifest['schema'] == 1, 'Unknown manifest schema')
    check_identity(manifest)
    for row in manifest['packages']:
        require(sha(directory / row['filename']) == row['sha256'], f'Package changed: {row["filename"]}')
        require(inspect_package(directory / row['filename']) == row, 'Package metadata differs from manifest')
        if 'signature_sha256' in row:
            require(sha(directory / (row['filename'] + '.sig')) == row['signature_sha256'], 'Signature changed')
    require(STACK <= set(manifest['signed_packages']), 'Compositor imports require upstream signatures')
    for name in manifest['signed_packages']:
        row = next(p for p in manifest['packages'] if p['name'] == name)
        require('signature_sha256' in row, f'Missing imported package signature: {name}')
        run('gpgv', '--keyring', str(keyring), str(directory / (row['filename'] + '.sig')), str(directory / row['filename']))
    for filename, checksum in manifest['databases'].items():
        require(filename in {f'{db}.{ext}' for db in DATABASES for ext in ('db', 'db.tar.zst', 'files', 'files.tar.zst')}, 'Unexpected database filename')
        require(sha(directory / filename) == checksum, f'Database changed: {filename}')
    require(len(manifest['databases']) == 8, 'Incomplete repository databases')
    for db in DATABASES:
        for kind in ('db', 'files'):
            require(manifest['databases'][f'{db}.{kind}'] == manifest['databases'][f'{db}.{kind}.tar.zst'], 'Database aliases differ')
    expected = {p['name']: (p['version'], p['filename'], p['sha256']) for p in manifest['packages']}
    for db in DATABASES:
        path = directory / (db + '.db')
        actual = {}
        for member in run('bsdtar', '-tf', str(path)).splitlines():
            if not member.endswith('/desc'):
                continue
            lines = run('bsdtar', '-xOf', str(path), member).splitlines()
            fields = {line: lines[i + 1] for i, line in enumerate(lines[:-1]) if line.startswith('%')}
            actual[fields['%NAME%']] = (fields['%VERSION%'], fields['%FILENAME%'], fields['%SHA256SUM%'])
        require(actual == expected, f'{db} database does not match the complete snapshot inventory')
    return manifest


def prepare(args):
    source = Path(args.packages).resolve()
    output = Path(args.output).resolve()
    require(not output.exists(), 'Output must not exist; snapshots are immutable')
    rows = [inspect_package(p) for p in sorted(source.glob('*.pkg.tar.*')) if not p.name.endswith('.sig')]
    # A required inventory is frozen before preparation, from the prior snapshot
    # or legacy repository plus the imported compositor dependency closure.
    required = json.loads(Path(args.inventory).read_text())
    require(isinstance(required, list) and all(isinstance(n, str) for n in required), 'Inventory must be a JSON array of required package names')
    manifest = dict(schema=1, client_protocol=0 if args.bootstrap else 1, channel=args.channel, source_sha=args.source_sha, recipe_sha=None if args.bootstrap and args.recipe_sha == 'unknown' else args.recipe_sha,
                    publisher_sha=args.publisher_sha, bootstrap=args.bootstrap, signed_packages=sorted(set(json.loads(Path(args.signed_inventory).read_text())) if args.signed_inventory else STACK), required_packages=sorted(set(required) - PAIRS), packages=rows)
    check_identity(manifest)
    provenance = source / 'input-provenance.json'
    if provenance.exists():
        manifest['inputs'] = json.loads(provenance.read_text())
    if not args.bootstrap:
        manifest['desktop_build'] = manifest.get('inputs', {}).get('desktop_build', {key: manifest[key] for key in ('source_sha', 'recipe_sha', 'publisher_sha')})
        check_identity(manifest)
        desktop = next(row for row in rows if row['name'] == ('omarchy-dev' if args.channel == 'edge' else 'omarchy'))
        paths = run('bsdtar', '-tf', str(source / desktop['filename'])).splitlines()
        require(any(p.removeprefix('./') == 'usr/share/omarchy/install/helpers/arm-channel-manifest.py' for p in paths), 'Desktop does not support isolated ARM channel switching')
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        staged = Path(temporary)
        for row in rows:
            shutil.copy2(source / row['filename'], staged / row['filename'])
            if 'signature_sha256' in row:
                shutil.copy2(source / (row['filename'] + '.sig'), staged / (row['filename'] + '.sig'))
        manifest['databases'] = {}
        for db in DATABASES:
            run('repo-add', '--quiet', str(staged / (db + '.db.tar.zst')),
                *(str(staged / row['filename']) for row in rows))
            for kind in ('db', 'files'):
                plain = staged / f'{db}.{kind}'
                plain.unlink()
                shutil.copy2(staged / f'{db}.{kind}.tar.zst', plain)
                for path in (plain, staged / f'{db}.{kind}.tar.zst'):
                    manifest['databases'][path.name] = sha(path)
        write_manifest(staged, manifest)
        verify(staged, args.signature_keyring)
        shutil.copytree(staged, output)
    print(output)


def promote(args):
    source, output = Path(args.snapshot), Path(args.output)
    manifest = verify(source, args.signature_keyring)
    require((manifest['channel'], args.channel) in (('edge', 'rc'), ('rc', 'stable')), 'Only edge→rc or rc→stable promotion is allowed')
    manifest['channel'] = args.channel
    # Edge can contain a final/RC release pair alongside its dev pair. Carry the
    # managed dependencies byte-for-byte and omit development identities for RC.
    if args.channel == 'rc':
        manifest['packages'] = [p for p in manifest['packages'] if p['name'] not in ('omarchy-dev', 'omarchy-settings-dev')]
    check_identity(manifest)
    require(not output.exists(), 'Promotion output must not exist')
    if args.channel == 'stable':
        shutil.copytree(source, output)
        write_manifest(output, manifest)
    else:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            for row in manifest['packages']:
                for filename in [row['filename']] + ([row['filename'] + '.sig'] if 'signature_sha256' in row else []):
                    shutil.copy2(source / filename, stage / filename)
            inventory = stage / 'inventory.json'
            inventory.write_text(json.dumps(manifest['required_packages']))
            signed_inventory = stage / 'signed-inventory.json'
            signed_inventory.write_text(json.dumps(manifest['signed_packages']))
            prepare(argparse.Namespace(packages=str(stage), output=str(output), channel='rc', inventory=str(inventory),
                                       bootstrap=False, signed_inventory=str(signed_inventory), signature_keyring=args.signature_keyring, **{key: manifest[key] for key in ('source_sha', 'recipe_sha', 'publisher_sha')}))
    verify(output, args.signature_keyring)


def publish(args):
    directory = Path(args.snapshot)
    manifest = verify(directory, args.signature_keyring)
    tag = 'channel-' + manifest['channel']
    # A caller must serialize all publishing workflows with channel-publish.
    # No legacy release is read, updated or garbage-collected by this command.
    existing = subprocess.run(['gh', 'release', 'view', tag, '--repo', args.repo, '--json', 'assets'], capture_output=True, text=True)
    require(existing.returncode == 0, f'Create the {tag} release explicitly before first publication')
    asset_names = {a['name'] for a in json.loads(existing.stdout)['assets']}
    packages = []
    for row in manifest['packages']:
        packages.append(row['filename'])
        if 'signature_sha256' in row:
            packages.append(row['filename'] + '.sig')
    with tempfile.TemporaryDirectory() as temporary:
        for name in packages:
            if name in asset_names:
                run('gh', 'release', 'download', tag, '--repo', args.repo, '--dir', temporary, '--pattern', name)
                require(sha(Path(temporary) / name) == sha(directory / name), f'Refusing to replace immutable archive/signature: {name}')
        # Validate everything before the first upload; archives precede databases.
        for name in packages:
            if name not in asset_names:
                run('gh', 'release', 'upload', tag, str(directory / name), '--repo', args.repo)
        for name in sorted(manifest['databases'], key=lambda n: n.endswith('.db')):
            run('gh', 'release', 'upload', tag, str(directory / name), '--repo', args.repo, '--clobber')
        run('gh', 'release', 'upload', tag, str(directory / 'channel-manifest.json'), '--repo', args.repo, '--clobber')
    print(f'Published {tag}; archives retained for prior snapshots')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare')
    for name in ('packages', 'inventory', 'output', 'source-sha', 'recipe-sha', 'publisher-sha'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--channel', choices=CHANNELS, required=True)
    p.add_argument('--signature-keyring', default='/etc/pacman.d/gnupg/pubring.gpg')
    p.add_argument('--signed-inventory', help='JSON package names from signed dependency imports; defaults to the compositor trio')
    p.add_argument('--bootstrap', action='store_true', help='Preserve the published stable baseline before new RC contracts')
    for command in ('verify', 'promote', 'publish'):
        p = commands.add_parser(command)
        p.add_argument('--snapshot', required=True)
        p.add_argument('--signature-keyring', default='/etc/pacman.d/gnupg/pubring.gpg')
        if command == 'promote':
            p.add_argument('--channel', choices=CHANNELS, required=True)
            p.add_argument('--output', required=True)
        if command == 'publish':
            p.add_argument('--repo', required=True)
    args = parser.parse_args()
    if args.command == 'verify':
        verify(Path(args.snapshot), args.signature_keyring)
        print('Snapshot verified')
    else:
        globals()[args.command](args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
