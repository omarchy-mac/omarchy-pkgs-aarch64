#!/usr/bin/env python3
"""Explicit final unsigned RC4 trust-anchor delivery; never a general unsigned publisher."""
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


def validate(args, trust_policy=boot.bundle.SIGNING_POLICY):
    manifest = boot.validate(args.bundle, args.manifest_sha256, args.source_commit, trust_policy, signed=False)
    boot.require(len(manifest['packages']) == 52, 'The one-shot RC4 transition requires its exact 52-package inventory')
    boot.require(boot.re.fullmatch(r'4\.0\.3rc4-[1-9][0-9]*', manifest['version']), 'Only the prepared 4.0.3rc4 bundle is permitted')
    boot.require(manifest['signature_policy'] == 'optional-existing-signatures; no signer authority asserted',
                 'Strict/signed manifests must use the signed bootstrap')
    boot.require(not any(name.startswith('assets/') and name.endswith('.sig') for name in manifest['files']),
                 'The final old-trust candidate must be entirely unsigned')
    omarchy = next(package for package in manifest['packages'] if package['name'] == 'omarchy')
    boot.require(any(boot.re.fullmatch(r'omarchy-mac-keyring(?:>=20260914-2)?', dependency)
                     for dependency in omarchy['depends']),
                 'RC4 must install the fork trust anchor as a hard dependency')
    records = boot.bundle.database(args.bundle / 'assets' / f'{boot.DB}.db')
    boot.require(all('PGPSIG' not in record for record in records.values()), 'Embedded package signatures are forbidden in the old-trust candidate')
    keyring_record = next(package for package in manifest['packages'] if package['name'] == 'omarchy-mac-keyring')
    boot.verify_initial_keyring(args.bundle / 'assets' / keyring_record['filename'], trust_policy)
    boot.require(args.accept_final_old_trust_publication, 'Explicit acceptance of final old-trust publication required, including dry-run')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--publisher-commit', required=True)
    parser.add_argument('--expected-rc-db', required=True)
    parser.add_argument('--lane', choices=['rc'], default='rc')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--accept-final-old-trust-publication', action='store_true')
    parser.add_argument('--accept-mutable-alias-window', action='store_true')
    args = parser.parse_args()
    manifest = validate(args)
    with tempfile.TemporaryDirectory(prefix='rc4-old-trust-', dir=boot.temporary_root()) as temporary:
        args.scratch = Path(temporary)
        boot.guard(args.scratch)
        print(json.dumps(boot.publish_checked(args, manifest, boot.GitHub(args.scratch), old_trust_transition=True), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'RC4 old-trust transition stopped: {error}')
