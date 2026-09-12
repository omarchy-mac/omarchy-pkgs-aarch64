#!/usr/bin/python3
"""Plan an edge update from pinned inputs and a complete captured baseline; never publish."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

PAIR = ('omarchy-dev', 'omarchy-settings-dev')
ALL_PAIRS = {*PAIR, 'omarchy', 'omarchy-settings'}
STACK = {'hyprland', 'hyprtoolkit', 'hyprland-guiutils'}
PROVENANCE_KEYS = ('source_sha', 'recipe_sha', 'publisher_sha')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def provenance(value):
    require(isinstance(value, dict), 'Desktop provenance must be an object')
    result = {key: value.get(key) for key in PROVENANCE_KEYS}
    for key, commit in result.items():
        require(isinstance(commit, str) and re.fullmatch(r'[0-9a-f]{40}', commit), f'{key} must be a full immutable Git SHA')
    return result


def rows(packages):
    require(isinstance(packages, list), 'Package inventory must be an array')
    result = {}
    for row in packages:
        require(isinstance(row, dict), 'Malformed package inventory row')
        name, version, digest = (row.get(key) for key in ('name', 'version', 'sha256'))
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9@_+.-]+', name), 'Invalid package name')
        require(isinstance(version, str) and re.fullmatch(r'[A-Za-z0-9.+_:\-]+', version), f'Invalid version for {name}')
        require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest), f'Invalid hash for {name}')
        require(name not in result, f'Duplicate package identity: {name}')
        result[name] = row
    return result


def dependencies(packages):
    result = {}
    for name, row in rows(packages).items():
        if name in ALL_PAIRS:
            continue
        signature = row.get('signature_sha256')
        require(signature is None or isinstance(signature, str) and re.fullmatch(r'[0-9a-f]{64}', signature), f'Invalid signature hash for {name}')
        result[name] = {'version': row['version'], 'sha256': row['sha256'], 'signature_sha256': signature}
    require(STACK <= result.keys(), 'Inventory must include the complete compositor stack')
    return result


def plan(baseline, desired, bootstrap=False):
    require(isinstance(baseline, dict) and baseline.get('schema') == 1, 'A captured channel manifest is required')
    require(baseline.get('client_protocol') == 1 and not baseline.get('bootstrap'), 'Historical or incomplete baseline cannot seed automatic edge')
    require(baseline.get('channel') == ('stable' if bootstrap else 'edge'), 'Use edge baseline, or explicitly bootstrap from qualified stable')
    require(isinstance(desired, dict), 'Desired input must be an object')
    inputs = provenance(desired)
    previous_build = provenance(baseline.get('desktop_build', baseline))
    for key in ('source_sha', 'recipe_sha'):
        require(previous_build[key] == baseline.get(key), 'Baseline desktop provenance differs from snapshot inputs')
    published = rows(baseline.get('packages'))
    pair = ('omarchy', 'omarchy-settings') if bootstrap else PAIR
    require(set(pair) <= published.keys(), 'Baseline is missing its complete desktop pair')
    require(published[pair[0]]['version'] == published[pair[1]]['version'], 'Baseline desktop pair versions differ')
    version = published[pair[0]]['version']
    old_pkgver, separator, old_pkgrel = version.rpartition('-')
    require(separator and re.fullmatch(r'[1-9][0-9]*', old_pkgrel), 'Baseline requires an integer package release')
    pkgver = desired.get('pkgver')
    require(isinstance(pkgver, str) and re.fullmatch(r'[A-Za-z0-9.+_:]+', pkgver), 'Calculated pkgver is required, without pkgrel')
    comparison = int(subprocess.run(['vercmp', pkgver, old_pkgver], check=True, text=True, capture_output=True).stdout.strip())
    require(comparison >= 0, 'Refusing package version regression')
    before, after = dependencies(baseline['packages']), dependencies(desired.get('packages'))
    require(before.keys() <= after.keys(), 'Desired inventory cannot silently remove managed packages')
    for name in before.keys() & after.keys():
        ordering = int(subprocess.run(['vercmp', after[name]['version'], before[name]['version']], check=True, text=True, capture_output=True).stdout.strip())
        require(ordering >= 0, f'Automatic dependency downgrade requires manual review: {name}')
        require(before[name]['version'] != after[name]['version'] or (before[name]['sha256'], before[name]['signature_sha256']) == (after[name]['sha256'], after[name]['signature_sha256']),
                f'Immutable package version was repacked: {name}')
    reasons = [key.removesuffix('_sha') for key in PROVENANCE_KEYS if inputs[key] != previous_build[key]]
    if bootstrap:
        reasons.insert(0, 'bootstrap')
    rebuild = bool(reasons)
    if not rebuild:
        require(pkgver == old_pkgver, 'Calculated pkgver changed without a source, recipe or publisher change')
    if before != after:
        reasons.append('dependencies')
    action = 'build' if rebuild else 'reuse' if reasons else 'skip'
    pkgrel = 1 if comparison > 0 or bootstrap else int(old_pkgrel) + 1 if rebuild else int(old_pkgrel)
    return dict(schema=1, channel='edge', action=action, reasons=reasons, pkgver=pkgver, pkgrel=pkgrel,
                package_version=f'{pkgver}-{pkgrel}', inputs=inputs,
                desktop_build=inputs if rebuild else previous_build,
                dependencies=after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--desired', required=True, type=Path)
    parser.add_argument('--bootstrap', action='store_true')
    args = parser.parse_args()
    captured = args.baseline.read_bytes()
    result = plan(json.loads(captured), json.loads(args.desired.read_bytes()), args.bootstrap)
    result['baseline_manifest_sha256'] = hashlib.sha256(captured).hexdigest()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
