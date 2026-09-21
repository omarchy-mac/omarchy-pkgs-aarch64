#!/usr/bin/python3
"""Capture and sign existing edge dependencies as artifacts; never publish or rebuild."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('bootstrap', Path(__file__).with_name('bootstrap-rc.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
bundle = boot.bundle
require = bundle.require
# These names must come from the separately verified quattro candidate set.
EXCLUDED = {'omarchy', 'omarchy-settings', 'omarchy-mac', 'avd-fw', 'libva-v4l2_request-avd'}


def capture(output, database_hash):
    require(re.fullmatch('[a-f0-9]{64}', database_hash), 'Exact edge database SHA256 required')
    boot.guard(output.parent)
    with tempfile.TemporaryDirectory(prefix='image-catalog-', dir=output.parent) as tmp:
        root = Path(tmp)
        remote = boot.GitHub(root)
        release = remote.release('edge', require_prerelease=False)
        require(release and not release['draft'], 'Published edge is missing')
        database = root / 'edge.db'
        remote.read(release, boot.DB + '.db', destination=database)
        require(bundle.digest(database) == database_hash, 'Edge changed before capture')
        records = bundle.database(database)
        # Capture all published DB members, including extras such as steam-fex.
        # This is a separate image inventory, not a change to packages.json.
        catalog = root / 'catalog.json'
        bundle.write_json(catalog, {'packages': [{'name': n} for n in sorted(records)]})
        boot.capture(SimpleNamespace(output=output, database_sha256=database_hash,
            lane='edge', catalog=catalog, catalog_sha256=bundle.digest(catalog),
            overlay_lane=None, overlay_database_sha256=None))


def validate_capture(root, capture_hash, database_hash):
    boot.check_capture(root, capture_hash)
    require(re.fullmatch('[a-f0-9]{64}', database_hash), 'Invalid origin database hash')
    evidence = json.loads((root / 'capture.json').read_text())
    require(evidence['lane'] == 'edge' and evidence['overlay_lane'] is None,
            'Image dependencies require an edge-only capture')
    require(bundle.digest(root / 'sources/edge.db') == database_hash,
            'Capture does not match selected edge database')
    all_packages = bundle.archives(root / 'packages')
    # No catalog filtering: the signed dependency inventory derives from the
    # complete frozen DB, minus only the five explicit candidate overrides.
    bundle.validate_inventory(bundle.database(root / 'sources/edge.db'), all_packages)
    packages = {n: p for n, p in all_packages.items() if n not in EXCLUDED}
    require(packages and 'omarchy-nvim' in packages, 'Image dependency set is incomplete')
    return packages


def seal(root, destination, capture_hash, database_hash):
    packages = validate_capture(root, capture_hash, database_hash)
    require(not destination.exists(), 'Snapshot destination already exists')
    destination.mkdir(mode=0o700)
    for path, record in packages.values():
        bundle.copy_file(path, destination / record['filename'])
    origin = destination / 'origin.db'
    bundle.copy_file(root / 'sources/edge.db', origin)
    records = [r for _, r in packages.values()]
    manifest = {
        'schema': 1, 'kind': 'omarchy-image-dependencies', 'publication': 'none',
        'source_repository': boot.REPO, 'source_lane': 'edge',
        'source_database_sha256': database_hash, 'capture_manifest_sha256': capture_hash,
        'excluded_names': sorted(EXCLUDED), 'packages': sorted(records, key=lambda r:r['name']),
        'provenance': 'Exact published bytes; signatures do not establish reproducible builds or boot qualification.',
    }
    # Recheck private package copies and the complete origin before credentials.
    require(bundle.digest(origin) == database_hash, 'Copied origin database differs')
    copied = {n: (destination / r['filename'], r) for n, (_, r) in packages.items()}
    for path, expected in copied.values():
        require(bundle.package_record(path) == expected, 'Copied package differs')
    bundle.validate_inventory({n:r for n,r in bundle.database(origin).items() if n not in EXCLUDED}, copied)
    metadata = destination / 'manifest.json'
    bundle.write_json(metadata, manifest)
    ring = bundle.signing.Keyring(secret=True)
    try:
        for path in [origin, metadata, *[p for p, _ in copied.values()]]:
            ring.sign(path)
            ring.verify(path)
    finally:
        ring.close()
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    p = sub.add_parser('capture')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--database-sha256', required=True)
    p = sub.add_parser('seal')
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--capture-sha256', required=True)
    p.add_argument('--database-sha256', required=True)
    args = parser.parse_args()
    if args.operation == 'capture':
        capture(args.output, args.database_sha256)
    else:
        seal(args.input, args.output, args.capture_sha256, args.database_sha256)
        print('Signed image dependency snapshot; publication: none')


if __name__ == '__main__':
    main()
