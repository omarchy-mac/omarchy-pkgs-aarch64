#!/usr/bin/env python3
"""Select compatibility only for an entirely unsigned current edge baseline."""
import argparse
import importlib.util
from pathlib import Path
import subprocess

spec = importlib.util.spec_from_file_location('bundle', Path(__file__).with_name('release-bundle.py'))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def mode(database, asset_names):
    names = set(Path(asset_names).read_text().splitlines())
    bundle.require(names and f'{bundle.DB}.db' in names, 'Selected edge database asset is missing')
    records = bundle.database(database)
    signed = ('edge-signing.json' in names or any(name.endswith('.sig') for name in names)
              or any('PGPSIG' in record for record in records.values()))
    return 'strict' if signed else 'legacy'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--assets', type=Path, required=True)
    args = parser.parse_args()
    print(mode(args.database, args.assets))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'Cannot establish edge signing state: {error}')
