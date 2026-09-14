#!/usr/bin/env python3
"""Select changed/local smoke inputs, or a smallest-package sample; full download is opt-in."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

spec = importlib.util.spec_from_file_location('bundle', Path(__file__).with_name('release-bundle.py'))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def select(database, cache, package_directory=None, requested='', full=False):
    records = bundle.database(database)
    cache.mkdir(parents=True, exist_ok=True)
    selected = []
    local = {}
    if package_directory:
        for path in sorted(Path(package_directory).glob('*.pkg.tar.*')):
            if path.name.endswith('.sig'):
                continue
            package = bundle.package_record(path)
            name = package['name']
            bundle.require(name in records and package['sha256'] == bundle.field(records[name], 'SHA256SUM'),
                           'Local smoke archive differs from published database')
            filename = bundle.safe_name(bundle.field(records[name], 'FILENAME'))
            local[name] = (path, filename)
            selected.append(name)
        bundle.require(selected, 'No local smoke archives')
    if full:
        selected = sorted(records)
    elif requested:
        selected = requested.split(',')
    elif not selected:
        selected = [min(records, key=lambda name: int(bundle.field(records[name], 'CSIZE')))]
    bundle.require(selected and len(selected) == len(set(selected)) and set(selected) <= set(records), 'Unknown/duplicate smoke targets')
    for name in selected:
        if name in local:
            path, filename = local[name]
            bundle.copy_file(path, cache / filename)
    return [(name, bundle.field(records[name], 'FILENAME')) for name in selected]


if __name__ == '__main__':
    try:
        rows = select(Path(sys.argv[1]), Path(sys.argv[2]), os.environ.get('PKGDIR'),
                      os.environ.get('SMOKE_PACKAGES', ''), os.environ.get('SMOKE_FULL') == '1')
        for row in rows:
            print('\t'.join(row))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'Smoke input selection failed: {error}')
