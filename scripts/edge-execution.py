#!/usr/bin/python3
"""Bind an executed edge snapshot to its captured plan before qualification/publication."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('planner', Path(__file__).with_name('edge-plan.py'))
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


def validate(plan, baseline, manifest):
    require = planner.require
    require(plan.get('schema') == 1 and plan.get('action') in ('build', 'reuse'), 'No executable edge plan')
    require(hashlib.sha256(baseline).hexdigest() == plan.get('baseline_manifest_sha256'), 'Baseline changed after planning')
    require(manifest.get('channel') == 'edge' and manifest.get('client_protocol') == 1 and not manifest.get('bootstrap'), 'Expected a channel-capable edge snapshot')
    require(planner.provenance(manifest) == planner.provenance(plan.get('inputs')), 'Executed source inputs differ from plan')
    require(planner.provenance(manifest.get('desktop_build')) == planner.provenance(plan.get('desktop_build')), 'Desktop build provenance differs from plan')
    packages = planner.rows(manifest.get('packages'))
    require(set(planner.PAIR) <= packages.keys() and not {'omarchy', 'omarchy-settings'} & packages.keys(), 'Wrong executed desktop pair')
    require(all(packages[name]['version'] == plan.get('package_version') for name in planner.PAIR), 'Built package version differs from plan')
    require(planner.dependencies(manifest['packages']) == plan.get('dependencies'), 'Executed dependency inventory differs from plan')
    if plan['action'] == 'reuse':
        original = planner.rows(json.loads(baseline)['packages'])
        require(all(packages[name] == original[name] for name in planner.PAIR), 'Reused desktop bytes/metadata differ from baseline')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--snapshot', required=True, type=Path)
    args = parser.parse_args()
    validate(json.loads(args.plan.read_bytes()), args.baseline.read_bytes(), json.loads((args.snapshot / 'channel-manifest.json').read_bytes()))


if __name__ == '__main__':
    main()
