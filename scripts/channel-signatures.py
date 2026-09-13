#!/usr/bin/python3
"""Offline signing request/import and pinned flat ZIP ingestion. Never signs or publishes."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile

spec = importlib.util.spec_from_file_location('snapshot', Path(__file__).with_name('channel-snapshot.py'))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)
require, sha = snapshot.require, snapshot.sha


def signing_request(directory, expected_sha, keyring):
    require(re.fullmatch(r'[0-9a-f]{64}', expected_sha or ''), 'An exact input manifest SHA-256 is required')
    require(sha(directory / 'channel-manifest.json') == expected_sha, 'Input manifest differs from requested identity')
    manifest = snapshot.verify(directory, keyring)
    return dict(schema=1, kind='arm-package-signing-request', input_manifest_sha256=expected_sha,
                provenance={key: manifest[key] for key in ('source_sha', 'recipe_sha', 'publisher_sha', 'desktop_build', 'inputs') if key in manifest},
                unsigned_packages=[{key: row[key] for key in ('name', 'version', 'filename', 'sha256')}
                                   for row in manifest['packages'] if 'signature_sha256' not in row])


def request(args):
    value = signing_request(Path(args.snapshot), args.input_manifest_sha256, args.signature_keyring)
    with Path(args.output).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(f'Unsigned signing request: {args.output}; SHA256 {sha(Path(args.output))}')


def import_signatures(args):
    source, signatures, output = map(Path, (args.snapshot, args.signatures, args.output))
    approved = snapshot.approved_policy(args.signature_keyring, args.approved_signers)
    policy_hashes = {Path(args.signature_keyring): sha(Path(args.signature_keyring)), Path(args.approved_signers): sha(Path(args.approved_signers))}
    require(re.fullmatch(r'[0-9a-f]{40}', args.publisher_sha or ''), 'Assembly publisher must be an exact Git SHA')
    require(re.fullmatch(r'[0-9a-f]{64}', args.request_sha256 or ''), 'An exact reviewed request SHA-256 is required')
    request_path = Path(args.request)
    require(sha(request_path) == args.request_sha256, 'Signing request changed')
    asked = json.loads(request_path.read_text())
    require(asked == signing_request(source, asked['input_manifest_sha256'], args.signature_keyring), 'Request does not describe the exact unsigned input')
    manifest = snapshot.verify(source, args.signature_keyring)
    expected = {row['filename'] + '.sig' for row in asked['unsigned_packages']}
    supplied = list(signatures.iterdir())
    require(all(path.is_file() and not path.is_symlink() for path in supplied), 'Signature response must contain regular detached signature files only')
    require({path.name for path in supplied} == expected, 'Missing/extra response signatures or attempted replacement of an existing signature')
    require(not output.exists(), 'Signed output must not exist; input snapshots remain immutable')
    before = {row['filename']: row['sha256'] for row in manifest['packages']}
    before.update({row['filename'] + '.sig': row['signature_sha256'] for row in manifest['packages'] if 'signature_sha256' in row})
    accepted = {}
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        stage = Path(temporary)
        signed = copy.deepcopy(manifest)
        for row in signed['packages']:
            filename = row['filename']
            shutil.copy2(source / filename, stage / filename)
            signature_name = filename + '.sig'
            origin = source if 'signature_sha256' in row else signatures
            shutil.copy2(origin / signature_name, stage / signature_name)
            accepted[row['name']] = snapshot.verify_signature(stage / signature_name, stage / filename, args.signature_keyring, approved)
            row['signature_sha256'] = sha(stage / signature_name)
        for filename, digest in before.items():
            require(sha(source / filename) == digest and sha(stage / filename) == digest, f'Immutable input changed: {filename}')
        require(sha(source / 'channel-manifest.json') == asked['input_manifest_sha256'], 'Input manifest changed during staging')
        require(sha(request_path) == args.request_sha256, 'Signing request changed during staging')
        signed['signed_packages'] = sorted(row['name'] for row in signed['packages'])
        signed['desktop_build'] = manifest.get('desktop_build', {key: manifest[key] for key in ('source_sha', 'recipe_sha', 'publisher_sha')})
        signed['publisher_sha'] = args.publisher_sha
        signed['publication_status'] = 'signature-verified-needs-qualification'
        signed['signing_assembly'] = dict(input_manifest_sha256=asked['input_manifest_sha256'],
            request_sha256=args.request_sha256, input_publisher_sha=manifest['publisher_sha'], publisher_sha=args.publisher_sha,
            keyring_sha256=sha(Path(args.signature_keyring)), approved_policy_sha256=sha(Path(args.approved_signers)),
            added_signatures=sorted(expected), verified_signers=accepted)
        # repo-add embeds the exact detached bytes; no archive or existing
        # imported signature is rebuilt/re-signed by this operation.
        signed['databases'] = {}
        for database in snapshot.DATABASES:
            snapshot.run('repo-add', '--quiet', '--include-sigs', str(stage / f'{database}.db.tar.zst'),
                         *(str(stage / row['filename']) for row in signed['packages']))
            for kind in ('db', 'files'):
                alias = stage / f'{database}.{kind}'
                alias.unlink()
                shutil.copy2(stage / f'{database}.{kind}.tar.zst', alias)
                for path in (alias, stage / f'{database}.{kind}.tar.zst'):
                    signed['databases'][path.name] = sha(path)
        snapshot.write_manifest(stage, signed)
        snapshot.verify(stage, args.signature_keyring, args.approved_signers, require_all_signatures=True)
        # Recheck the entire source after all potentially lengthy assembly work.
        require(sha(source / 'channel-manifest.json') == asked['input_manifest_sha256'], 'Input manifest changed')
        for filename, digest in before.items():
            require(sha(source / filename) == digest, f'Input changed during assembly: {filename}')
        for path, digest in policy_hashes.items():
            require(sha(path) == digest, 'Trusted verification policy changed during assembly')
        shutil.copytree(stage, output)
    print(f'Signed snapshot: {output}; manifest SHA256 {sha(output / "channel-manifest.json")}; new qualification required')


def unpack(args):
    archive, output = Path(args.archive), Path(args.output)
    require(re.fullmatch(r'[0-9a-f]{64}', args.archive_sha256 or ''), 'An exact ZIP SHA-256 is required')
    require(re.fullmatch(r'[0-9a-f]{64}', args.manifest_sha256 or ''), 'An exact qualified signed manifest SHA-256 is required')
    require(sha(archive) == args.archive_sha256, 'Signed ZIP differs from pinned identity')
    require(not output.exists(), 'Extraction output must not exist')
    with zipfile.ZipFile(archive) as bundle:
        files = bundle.infolist()
        names = [entry.filename for entry in files]
        require(len(names) == len(set(names)), 'Duplicate ZIP filename')
        require('channel-manifest.json' in names, 'Signed ZIP lacks manifest')
        for entry in files:
            mode = entry.external_attr >> 16
            require(re.fullmatch(r'[A-Za-z0-9@_+.-]+', entry.filename) and entry.filename not in ('.', '..'), 'Signed ZIP must contain flat filenames only')
            require(not entry.is_dir() and stat.S_ISREG(mode), 'Signed ZIP must contain regular files only, never links/directories')
            require(not entry.flag_bits & 1, 'Encrypted ZIP entries are not supported')
        manifest = json.loads(bundle.read('channel-manifest.json'))
        expected = {'channel-manifest.json', *manifest['databases']}
        for row in manifest['packages']:
            expected.update((row['filename'], row['filename'] + '.sig'))
        require(set(names) == expected, 'Signed ZIP has extra or missing snapshot files')
        with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
            stage = Path(temporary)
            for entry in files:
                with bundle.open(entry) as source, (stage / entry.filename).open('xb') as destination:
                    shutil.copyfileobj(source, destination)
            require(sha(stage / 'channel-manifest.json') == args.manifest_sha256, 'Signed manifest differs from qualified identity')
            snapshot.verify(stage, args.signature_keyring, args.approved_signers, require_all_signatures=True)
            require(sha(archive) == args.archive_sha256, 'Signed ZIP changed during extraction')
            shutil.copytree(stage, output)
    print(f'Pinned signed snapshot verified: {output}; qualification must cover this exact manifest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('request')
    for name in ('snapshot', 'input-manifest-sha256', 'signature-keyring', 'output'):
        p.add_argument('--' + name, required=True)
    p = commands.add_parser('import')
    for name in ('snapshot', 'request', 'request-sha256', 'signatures', 'signature-keyring', 'approved-signers', 'publisher-sha', 'output'):
        p.add_argument('--' + name, required=True)
    p = commands.add_parser('unpack')
    for name in ('archive', 'archive-sha256', 'manifest-sha256', 'signature-keyring', 'approved-signers', 'output'):
        p.add_argument('--' + name, required=True)
    args = parser.parse_args()
    {'request': request, 'import': import_signatures, 'unpack': unpack}[args.command](args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, snapshot.subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
