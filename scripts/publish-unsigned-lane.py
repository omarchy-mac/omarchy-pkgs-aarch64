#!/usr/bin/env python3
"""Publish qualified unsigned edge, RC, or stable from retained exact bytes."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('bootstrap', Path(__file__).with_name('bootstrap-rc.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def require_final_evidence(args, manifest, receipt):
    boot.require(all(getattr(args, name) is not None for name in
                     ('rc_bundle', 'rc_validation', 'rc_manifest_sha256', 'rc_source_commit')),
                 'Final publication requires the exact qualified RC bundle and receipt')
    rc = boot.validate(args.rc_bundle, args.rc_manifest_sha256, args.rc_source_commit,
                       args.trust_policy, signed=False, channel='rc')
    boot.bundle.receipt(args.rc_bundle, args.rc_validation)
    boot.verify_final_lineage(rc, manifest)
    boot.require(receipt.get('hardware_checks') == {'m1_reboot_runtime': 'pass',
                                                     'm2_reboot_runtime': 'pass'},
                 'Final qualification requires physical M1 and M2 reboot/runtime passes')
    boot.require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-[1-9][0-9]*',
                              receipt.get('released_upgrade_from', '')),
                 'Final qualification must name the released upgrade baseline')
    if manifest['version'].startswith('4.0.3-'):
        boot.require(receipt['released_upgrade_from'] == '4.0.2-2',
                     '4.0.3 requires a real 4.0.2-2 upgrade')


def publish_edge(args, manifest, transport):
    boot.require(args.expected_db != 'absent' and re.fullmatch(r'[a-f0-9]{64}', args.expected_db),
                 'Edge requires its approved current database SHA256')
    boot.require(not args.execute or args.accept_mutable_alias_window,
                 'Execution requires explicit mutable database window acceptance')
    current = boot.lane_release(transport, 'edge')
    boot.require(current is not None and not current['draft'], 'Published edge release required')
    boot.require(not any(name in current['asset_map'] for name in
                         (f'{boot.DB}.db.sig', f'{boot.DB}.db.tar.zst.sig', 'edge-signing.json')),
                 'Unsigned publication cannot replace signed edge')
    previous = args.scratch / 'previous-edge.db'
    boot.require(transport.read(current, f'{boot.DB}.db', public=True, destination=previous) == args.expected_db
                 and boot.bundle.digest(previous) == args.expected_db,
                 'Public edge database differs from approved selection')
    evidence_dir = getattr(args, 'evidence_dir', None)
    if evidence_dir is not None:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        boot.guard(evidence_dir)
        shutil.copy2(previous, evidence_dir / 'previous-edge.db')
        boot.require(boot.bundle.digest(evidence_dir / 'previous-edge.db') == args.expected_db,
                     'Retained previous edge database differs')
    rows = boot.bundle.database(previous)
    packages = {p['name']: p for p in manifest['packages']}
    for name, package in packages.items():
        if name in rows:
            boot.require(int(boot.bundle.run('vercmp', boot.bundle.field(rows[name], 'VERSION'),
                                                 package['version']).strip()) <= 0,
                         f'Edge has a newer {name} version')
    for name in ('omarchy', 'omarchy-settings'):
        boot.require(name in rows, f'Edge lacks {name}')
        boot.require(not rows[name].get('PGPSIG'), 'Unsigned edge cannot replace signed packages')
        filename = packages[name]['filename']
        if filename in current['asset_map']:
            boot.require(transport.read(current, filename, public=True) == packages[name]['sha256'],
                         f'Edge filename collision would change final {name} archive bytes')
    staging = args.scratch / 'edge-staging'
    staging.mkdir()
    for name in sorted(boot.bundle.CANDIDATES):
        package = packages[name]
        source = args.bundle / 'assets' / package['filename']
        destination = staging / package['filename']
        shutil.copy2(source, destination)
        boot.require(boot.bundle.digest(destination) == package['sha256'],
                     f'Edge staging changed {name} archive bytes')
    plan = {'mode': 'execute' if args.execute else 'dry-run', 'lane': 'edge',
            'manifest_sha256': args.manifest_sha256, 'previous_edge_db': args.expected_db,
            'desktop_archive_sha256': {name: packages[name]['sha256']
                                       for name in ('omarchy', 'omarchy-settings')},
            'retry': 'Stop for review after a partial upload; reuse the same retained bundle bytes'}
    environment = os.environ.copy()
    environment.update(GH_REPO=boot.REPO, REPO_TAG='edge', PKGDIR=str(staging),
                       DB_OUT=str(args.scratch / 'edge-output'),
                       DRY_RUN='0' if args.execute else '1')
    subprocess.run(['bash', str(boot.ROOT / 'scripts/publish.sh')], cwd=boot.ROOT,
                   env=environment, check=True)
    if args.execute:
        selected = boot.selected(boot.lane_release(transport, 'edge'), transport)
        plan.update(boot.verify_edge_final(manifest, transport, selected, args.scratch))
        if evidence_dir is not None:
            shutil.copy2(args.scratch / 'selected-edge.db', evidence_dir / 'final-edge.db')
            boot.require(boot.bundle.digest(evidence_dir / 'final-edge.db') == selected,
                         'Retained final edge database differs')
        plan['result'] = 'PASS public edge database and exact final desktop archive readback'
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--validation', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--publisher-commit', required=True)
    parser.add_argument('--expected-db', required=True, help='Approved current lane database SHA256, or absent')
    parser.add_argument('--expected-edge-db', help='Approved public edge DB after final edge publication')
    parser.add_argument('--rc-bundle', type=Path)
    parser.add_argument('--rc-validation', type=Path)
    parser.add_argument('--rc-manifest-sha256')
    parser.add_argument('--rc-source-commit')
    parser.add_argument('--lane', choices=['edge', 'rc', 'stable'], required=True)
    parser.add_argument('--trust-policy', type=Path, default=boot.bundle.SIGNING_POLICY)
    parser.add_argument('--evidence-dir', type=Path, help='Retain previous and final edge DBs outside temporary scratch')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--accept-unsigned-publication', action='store_true')
    parser.add_argument('--accept-mutable-alias-window', action='store_true')
    args = parser.parse_args()
    boot.require(args.accept_unsigned_publication, 'Explicit unsigned publication acceptance required')
    boot.require(re.fullmatch(r'[a-f0-9]{40}', args.publisher_commit), 'Exact publisher commit required')
    receipt = boot.bundle.receipt(args.bundle, args.validation)
    channel = 'rc' if args.lane == 'rc' else 'stable'
    manifest = boot.validate(args.bundle, args.manifest_sha256, args.source_commit,
                             args.trust_policy, signed=False, channel=channel)
    if args.lane != 'rc':
        require_final_evidence(args, manifest, receipt)
    with tempfile.TemporaryDirectory(prefix=f'{args.lane}-unsigned-', dir=boot.temporary_root()) as temporary:
        args.scratch = Path(temporary)
        boot.guard(args.scratch)
        transport = boot.GitHub(args.scratch)
        if args.lane == 'edge':
            result = publish_edge(args, manifest, transport)
        else:
            if args.lane == 'stable':
                boot.require(args.expected_edge_db is not None,
                             'Stable requires the approved public edge database SHA256')
            args.expected_rc_db = args.expected_db
            result = boot.publish_checked(args, manifest, transport, unsigned_publication=True)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'Unsigned lane publication stopped: {error}')
