#!/usr/bin/python3
"""Collect a complete baseline plus exact resolved compositor imports and a new desktop pair."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def entries(db):
    result = {}
    for member in run('bsdtar', '-tf', str(db)).splitlines():
        if member.endswith('/desc'):
            lines = run('bsdtar', '-xOf', str(db), member).splitlines()
            fields = {line: lines[i + 1] for i, line in enumerate(lines[:-1]) if line.startswith('%')}
            result[fields['%NAME%']] = fields
    return result


def download(url, target, checksum):
    subprocess.run(['curl', '--fail', '--location', '--retry', '3', '--output', str(target), url], check=True)
    if sha(target) != checksum:
        raise ValueError(f'Download digest differs from captured database: {url}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base-url', 'base-db', 'import-plan', 'sync-db-dir', 'overlay', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--channel', choices=('stable', 'rc', 'edge'), required=True)
    parser.add_argument('--signature-keyring', default='/etc/pacman.d/gnupg/pubring.gpg')
    args = parser.parse_args()
    output, overlay = Path(args.output), Path(args.overlay)
    output.mkdir(parents=True, exist_ok=False)
    baseline = entries(Path(args.base_db))
    pair_names = {'omarchy', 'omarchy-settings', 'omarchy-dev', 'omarchy-settings-dev'}
    files = {}
    signed = []
    for name, row in baseline.items():
        if name in pair_names:
            continue  # The new build supplies the selected pair; never carry a stale opposite flavor.
        filename = row['%FILENAME%']
        if Path(filename).name != filename:
            raise ValueError('Unsafe baseline filename')
        download(args.base_url + '/' + filename, output / filename, row['%SHA256SUM%'])
        files[name] = filename
        if '%PGPSIG%' in row:
            (output / (filename + '.sig')).write_bytes(base64.b64decode(row['%PGPSIG%'], validate=True))
            run('gpgv', '--keyring', args.signature_keyring, str(output / (filename + '.sig')), str(output / filename))
            signed.append(name)
    db_hashes = {}
    for line in Path(args.import_plan).read_text().splitlines():
        if line.count('|') != 3:
            continue
        repo, name, version, url = line.split('|')
        if not re.fullmatch(r'[A-Za-z0-9@_+.-]+', repo):
            raise ValueError('Unsafe source repository')
        db = Path(args.sync_db_dir) / (repo + '.db')
        row = entries(db)[name]
        if row['%VERSION%'] != version:
            raise ValueError('Resolved package version differs from captured database')
        filename = row['%FILENAME%'].replace(':', '.')
        if Path(filename).name != filename:
            raise ValueError('Unsafe imported filename')
        if name in files:
            (output / files[name]).unlink()
            (output / (files[name] + '.sig')).unlink(missing_ok=True)
        download(url, output / filename, row['%SHA256SUM%'])
        subprocess.run(['curl', '--fail', '--location', '--retry', '3', '--output', str(output / (filename + '.sig')), url + '.sig'], check=True)
        run('gpgv', '--keyring', args.signature_keyring, str(output / (filename + '.sig')), str(output / filename))
        files[name] = filename
        signed.append(name)
        db_hashes[repo] = sha(db)
    if not {'hyprland', 'hyprtoolkit', 'hyprland-guiutils'} <= set(signed):
        raise ValueError('Resolution did not import the complete signed compositor stack')
    for package in overlay.glob('*.pkg.tar.*'):
        if package.name.endswith('.sig'):
            continue
        info = run('bsdtar', '-xOf', str(package), '.PKGINFO')
        name = next(line.split(' = ', 1)[1] for line in info.splitlines() if line.startswith('pkgname = '))
        version = next(line.split(' = ', 1)[1] for line in info.splitlines() if line.startswith('pkgver = '))
        # Rebuilt ancillary packages include fresh timestamps. Preserve the
        # qualified baseline bytes unless their package version actually changed.
        if name not in pair_names and name in files and name in baseline and version == baseline[name]['%VERSION%']:
            continue
        if name in files:
            (output / files[name]).unlink()
            (output / (files[name] + '.sig')).unlink(missing_ok=True)
        shutil.copy2(package, output / package.name)
        if package.with_name(package.name + '.sig').exists():
            shutil.copy2(package.with_name(package.name + '.sig'), output / (package.name + '.sig'))
        files[name] = package.name
    (output / 'inventory.json').write_text(json.dumps(sorted((set(baseline) - pair_names) | set(signed))))
    (output / 'signed-inventory.json').write_text(json.dumps(sorted(set(signed))))
    (output / 'input-provenance.json').write_text(json.dumps(dict(base_url=args.base_url, base_database_sha256=sha(Path(args.base_db)),
                                                               import_database_sha256=db_hashes, resolution=Path(args.import_plan).read_text()), indent=2))


if __name__ == '__main__':
    main()
