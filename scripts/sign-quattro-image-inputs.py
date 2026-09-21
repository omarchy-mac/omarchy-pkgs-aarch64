#!/usr/bin/python3
"""Sign a validated candidate build output without building, installing or publishing it."""
import argparse
import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


build = module('build-quattro-image-inputs')
signing = module('package-signing')
require = build.require


def validate(root, expected_hash, source):
    require(re.fullmatch('[a-f0-9]{64}', expected_hash), 'invalid manifest checksum')
    require(re.fullmatch('[a-f0-9]{40}', source), 'invalid source revision')
    manifest = root / 'manifest.json'
    require(manifest.is_file() and not manifest.is_symlink(), 'unsafe manifest')
    require(build.digest(manifest) == expected_hash, 'manifest checksum mismatch')
    data = json.loads(manifest.read_text())
    require(data['schema'] == 1 and data['candidate_only'] is True
            and data['publication'] == 'none' and data['signing'] == 'none', 'not an unsigned candidate')
    require(data['source_repository'] == 'omacom/omarchy-mac'
            and data['source_revision'] == source, 'wrong candidate source')
    require(len(data['packages']) == 3, 'expected three packages')
    records, versions, files = {}, {}, []
    for item in data['packages']:
        name, filename = item['name'], item['filename']
        require(name in build.PACKAGES and name not in records, 'unexpected or duplicate package')
        require(re.fullmatch(r'[A-Za-z0-9+_.:-]+\.pkg\.tar\.(xz|zst)', filename), 'unsafe package filename')
        path = root / filename
        require(path.is_file() and not path.is_symlink(), 'unsafe package archive')
        require(build.digest(path) == item['sha256'], 'package checksum mismatch')
        records[name] = build.inspect_package(path)
        require(records[name][0].get('depend', []) == item['dependencies'], 'dependency metadata mismatch')
        versions[name] = item['version']
        files.append(path)
    build.verify_packages(records, source, versions)
    require({p.name for p in root.glob('*.pkg.tar.*')} == {p.name for p in files}, 'unexpected package or signature')
    runtime = next(root / p['filename'] for p in data['packages'] if p['name'] == 'omarchy')
    # These lists are authoritative image inputs: compare them to the archive,
    # not merely to an unsigned checksum file alongside the artifact.
    for name in ('omarchy-base.packages', 'omarchy-apple.packages'):
        path = root / name
        require(path.is_file() and not path.is_symlink(), 'unsafe package list')
        embedded = subprocess.check_output(['bsdtar', '-xOf', str(runtime), 'usr/share/omarchy/install/' + name])
        require(path.read_bytes() == embedded, 'package list differs from runtime')
        files.append(path)
    return data, [manifest, *files]


def seal(root, destination, expected_hash, source):
    _, files = validate(root, expected_hash, source)
    destination.mkdir(mode=0o700)  # Never reuse or overwrite another candidate.
    for path in files:
        shutil.copyfile(path, destination / path.name)
    # Recheck the private copies before loading any signing credentials.
    validate(destination, expected_hash, source)
    ring = signing.Keyring(secret=True)
    try:
        for path in files:
            ring.sign(destination / path.name)
        envelope = {
            'schema': 1, 'candidate_only': True, 'publication': 'none',
            'source_revision': source, 'input_manifest_sha256': expected_hash,
            'primary_fingerprint': ring.policy['primary_fingerprint'],
            'signing_subkey_fingerprint': ring.policy['signing_subkey_fingerprint'],
            'files': [{'filename': p.name, 'sha256': build.digest(destination / p.name)} for p in files],
        }
        receipt = destination / 'signing.json'
        receipt.write_text(json.dumps(envelope, indent=2) + '\n')
        ring.sign(receipt)
    finally:
        ring.close()
    (destination / 'SHA256SUMS').write_text(''.join(
        f'{build.digest(p)}  {p.name}\n' for p in sorted(destination.iterdir())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    seal(args.input, args.output, args.manifest_sha256, args.source_revision)


if __name__ == '__main__':
    main()
