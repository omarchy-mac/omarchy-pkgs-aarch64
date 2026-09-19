#!/usr/bin/env python3
"""Protected exact-inventory edge conversion; no package/version changes or unsigned fallback."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('bootstrap', Path(__file__).with_name('bootstrap-rc.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare')
    prepare.add_argument('--input', type=Path, required=True)
    prepare.add_argument('--output', type=Path, required=True)
    prepare.add_argument('--public-key', type=Path, default=boot.bundle.signing.PUBLIC)
    publish = commands.add_parser('publish')
    publish.add_argument('--bundle', type=Path, required=True)
    publish.add_argument('--publisher-commit', required=True)
    publish.add_argument('--expected-edge-db', dest='expected_rc_db', required=True)
    publish.add_argument('--execute', action='store_true')
    publish.add_argument('--accept-mutable-alias-window', action='store_true')
    publish.add_argument('--accept-client-trust-bootstrap', action='store_true')
    for sub in (prepare, publish):
        sub.add_argument('--manifest-sha256', required=True)
        sub.add_argument('--source-commit', required=True)
        sub.add_argument('--trust-policy', type=Path, default=boot.bundle.SIGNING_POLICY)
    args = parser.parse_args()
    args.channel = 'stable'
    args.lane = 'edge'
    if args.command == 'prepare':
        boot.prepare(args)
    else:
        manifest = boot.validate(args.bundle, args.manifest_sha256, args.source_commit,
                                 args.trust_policy, channel='stable')
        with tempfile.TemporaryDirectory(prefix='edge-conversion-', dir=boot.temporary_root()) as temporary:
            args.scratch = Path(temporary)
            boot.guard(args.scratch)
            print(json.dumps(boot.publish_checked(args, manifest, boot.GitHub(args.scratch), edge_conversion=True), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'Edge conversion stopped: {error}')
