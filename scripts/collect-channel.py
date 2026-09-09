#!/usr/bin/python3
"""Collect a complete baseline plus exact resolved compositor imports and a new desktop pair."""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def entries(db, selected=None):
    """Read full managed inventories, or exact resolved upstream name/version records.

    Upstream databases can contain unrelated damaged records. Only packages in
    the captured transaction are inputs to this snapshot; those records remain
    mandatory and strictly validated. Baseline/overlay inventories are exhaustive.
    """
    wanted = {f'{name}-{version}/desc': name for name, version in selected.items()} if selected is not None else None
    # bsdtar handles zstd even where Python tarfile does not. One conversion per
    # database avoids decompressing the entire ALARM extra DB for every record.
    # Ustar materializes sparse NUL records without Python/PAX sparse extensions.
    data = subprocess.run(['bsdtar', '-cf', '-', '--format=ustar', '@' + str(db)], check=True, capture_output=True).stdout
    result = {}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for member in archive:
            path = member.name.removeprefix('./')
            if not path.endswith('/desc') or wanted is not None and path not in wanted:
                continue
            if not member.isfile() or path in seen:
                raise ValueError(f'Invalid or duplicate database record: {db}: {path}')
            seen.add(path)
            content = archive.extractfile(member).read().decode('utf-8')
            if '\0' in content:
                raise ValueError(f'Malformed database record: {db}: {path}')
            lines = content.splitlines()
            fields = {}
            for index, line in enumerate(lines):
                if re.fullmatch(r'%[A-Z0-9_]+%', line):
                    if line in fields or index + 1 >= len(lines):
                        raise ValueError(f'Malformed database field: {db}: {path}: {line}')
                    fields[line] = lines[index + 1]
            required = ('%NAME%', '%VERSION%', '%FILENAME%', '%SHA256SUM%')
            if any(not fields.get(key) for key in required):
                raise ValueError(f'Incomplete database record: {db}: {path}')
            name = fields['%NAME%']
            if not re.fullmatch(r'[A-Za-z0-9@_+.-]+', name) or not re.fullmatch(r'[A-Za-z0-9.+_:-]+', fields['%VERSION%']):
                raise ValueError(f'Invalid database package identity: {db}: {path}')
            if not re.fullmatch(r'[A-Za-z0-9@_+.:-]+', fields['%FILENAME%']):
                raise ValueError(f'Unsafe database package filename: {db}: {path}')
            if name in result or path != f"{name}-{fields['%VERSION%']}/desc":
                raise ValueError(f'Database package identity differs or is duplicated: {db}: {path}')
            if not re.fullmatch(r'[0-9a-f]{64}', fields['%SHA256SUM%']):
                raise ValueError(f'Invalid database package hash: {db}: {path}')
            result[name] = fields
    if selected is not None and set(result) != set(selected):
        raise ValueError(f'Resolved packages missing from captured database {db}: {sorted(set(selected) - set(result))}')
    return result


def download(url, target, checksum):
    subprocess.run(['curl', '--fail', '--location', '--retry', '3', '--output', str(target), url], check=True)
    if sha(target) != checksum:
        raise ValueError(f'Download digest differs from captured database: {url}')


def reuse_pair(manifest_path, source_sha, recipe_sha, baseline, database):
    spec = importlib.util.spec_from_file_location('edge_plan', Path(__file__).with_name('edge-plan.py'))
    planner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(planner)
    captured = Path(manifest_path).read_bytes()
    manifest = json.loads(captured)
    planner.require(isinstance(manifest, dict) and manifest.get('schema') == 1, 'Unknown reuse manifest schema')
    planner.require(manifest.get('channel') == 'edge' and manifest.get('client_protocol') == 1
                    and not manifest.get('bootstrap'), 'Reuse requires a channel-capable edge baseline')
    build = planner.provenance(manifest.get('desktop_build', manifest))
    for key, requested in (('source_sha', source_sha), ('recipe_sha', recipe_sha)):
        planner.require(requested == build[key] == manifest.get(key), 'Reuse requires identical source and recipe commits')
    planner.require(manifest.get('databases', {}).get('omarchy-aarch64.db.tar.zst') == sha(database), 'Baseline database differs from reuse manifest')
    packages = planner.rows(manifest.get('packages'))
    planner.require(set(packages) == set(baseline), 'Baseline inventory differs from reuse manifest')
    for name, row in packages.items():
        metadata = baseline[name]
        for field, key in (('version', '%VERSION%'), ('filename', '%FILENAME%'), ('sha256', '%SHA256SUM%')):
            planner.require(row.get(field) == metadata.get(key), 'Baseline package differs from reuse manifest')
        signature = metadata.get('%PGPSIG%')
        digest = hashlib.sha256(base64.b64decode(signature, validate=True)).hexdigest() if signature else None
        planner.require(digest == row.get('signature_sha256'), 'Baseline signature differs from reuse manifest')
    planner.require(set(planner.PAIR) <= packages.keys(), 'Reuse baseline is missing the development pair')
    planner.require(packages[planner.PAIR[0]]['version'] == packages[planner.PAIR[1]]['version'], 'Reuse desktop pair versions differ')
    return dict(desktop_build=build, reused_from_manifest_sha256=hashlib.sha256(captured).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base-url', 'base-db', 'import-plan', 'sync-db-dir', 'overlay', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--channel', choices=('stable', 'rc', 'edge'), required=True)
    parser.add_argument('--signature-keyring', default='/etc/pacman.d/gnupg/pubring.gpg')
    parser.add_argument('--overlay-db', help='Captured legacy overlay feed, excluding all desktop flavors')
    parser.add_argument('--overlay-url')
    parser.add_argument('--reuse-edge-manifest')
    parser.add_argument('--source-sha')
    parser.add_argument('--recipe-sha')
    args = parser.parse_args()
    output, overlay = Path(args.output), Path(args.overlay)
    output.mkdir(parents=True, exist_ok=False)
    baseline = entries(Path(args.base_db))
    pair_names = {'omarchy', 'omarchy-settings', 'omarchy-dev', 'omarchy-settings-dev'}
    reuse = {}
    if args.reuse_edge_manifest:
        if args.channel != 'edge':
            raise ValueError('Desktop reuse is only supported for edge')
        reuse = reuse_pair(args.reuse_edge_manifest, args.source_sha, args.recipe_sha, baseline, Path(args.base_db))
    files = {}
    signed = []
    for name, row in baseline.items():
        if name in pair_names and not (reuse and name in {'omarchy-dev', 'omarchy-settings-dev'}):
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
    if bool(args.overlay_db) != bool(args.overlay_url):
        raise ValueError('Overlay database and URL must be supplied together')
    if args.overlay_db:
        for name, row in entries(Path(args.overlay_db)).items():
            if name in pair_names:
                continue
            # These are built from the pinned recipe checkout as well as the
            # legacy feed. A lagging feed must not undo a newer qualified recipe
            # version on the next tick; other dependency downgrades still fail.
            if name in {'omarchy-keyring', 'ttf-jetbrains-mono-nerd-basic'} and name in baseline:
                if int(run('vercmp', row['%VERSION%'], baseline[name]['%VERSION%']).strip()) < 0:
                    continue
            filename = row['%FILENAME%']
            if Path(filename).name != filename:
                raise ValueError('Unsafe overlay filename')
            if name in files:
                (output / files[name]).unlink()
                (output / (files[name] + '.sig')).unlink(missing_ok=True)
            download(args.overlay_url + '/' + filename, output / filename, row['%SHA256SUM%'])
            files[name] = filename
            signed = [item for item in signed if item != name]
            if '%PGPSIG%' in row:
                (output / (filename + '.sig')).write_bytes(base64.b64decode(row['%PGPSIG%'], validate=True))
                run('gpgv', '--keyring', args.signature_keyring, str(output / (filename + '.sig')), str(output / filename))
                signed.append(name)
    db_hashes = {}
    imports = []
    selections = {}
    for line in Path(args.import_plan).read_text().splitlines():
        if not line.strip():
            continue
        if line.count('|') != 3:
            raise ValueError('Malformed captured import transaction')
        repo, name, version, url = line.split('|')
        if not re.fullmatch(r'[A-Za-z0-9@_+.-]+', repo):
            raise ValueError('Unsafe source repository')
        selected = selections.setdefault(repo, {})
        if name in selected:
            raise ValueError('Duplicate package in captured import transaction')
        selected[name] = version
        imports.append((repo, name, version, url))
    databases = {repo: entries(Path(args.sync_db_dir) / (repo + '.db'), selected) for repo, selected in selections.items()}
    db_hashes = {repo: sha(Path(args.sync_db_dir) / (repo + '.db')) for repo in selections}
    for repo, name, version, url in imports:
        if reuse and name in pair_names:
            raise ValueError('Reuse cannot replace the desktop pair through imports')
        if not re.fullmatch(r'[A-Za-z0-9@_+.-]+', repo):
            raise ValueError('Unsafe source repository')
        row = databases[repo][name]
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
    if not {'hyprland', 'hyprtoolkit', 'hyprland-guiutils'} <= set(signed):
        raise ValueError('Resolution did not import the complete signed compositor stack')
    for package in overlay.glob('*.pkg.tar.*'):
        if package.name.endswith('.sig'):
            continue
        info = run('bsdtar', '-xOf', str(package), '.PKGINFO')
        name = next(line.split(' = ', 1)[1] for line in info.splitlines() if line.startswith('pkgname = '))
        if reuse and name in pair_names:
            raise ValueError('Reuse cannot accept a new desktop overlay pair')
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
    (output / 'inventory.json').write_text(json.dumps(sorted(set(files) - pair_names)))
    (output / 'signed-inventory.json').write_text(json.dumps(sorted(set(signed))))
    (output / 'input-provenance.json').write_text(json.dumps(dict(base_url=args.base_url, base_database_sha256=sha(Path(args.base_db)),
                                                               overlay_database_sha256=sha(Path(args.overlay_db)) if args.overlay_db else None,
                                                               import_database_sha256=db_hashes, resolution=Path(args.import_plan).read_text(), **reuse), indent=2))


if __name__ == '__main__':
    main()
