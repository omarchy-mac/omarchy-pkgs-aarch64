#!/usr/bin/python3
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('execution', Path(__file__).with_name('edge-execution.py'))
execution = importlib.util.module_from_spec(spec); spec.loader.exec_module(execution)
planner = execution.planner

class Execution(unittest.TestCase):
    def setUp(self):
        inputs = dict(source_sha='a' * 40, recipe_sha='b' * 40, publisher_sha='c' * 40)
        packages = [dict(name=n, version='1-1', sha256='d' * 64) for n in (*planner.PAIR, *planner.STACK)]
        baseline = dict(schema=1, client_protocol=1, channel='edge', packages=packages, **inputs)
        self.baseline = json.dumps(baseline).encode()
        desired = dict(inputs, pkgver='1', packages=copy.deepcopy(packages))
        desired['packages'][-1].update(version='2-1', sha256='e' * 64)
        self.plan = planner.plan(baseline, desired)
        self.plan['baseline_manifest_sha256'] = hashlib.sha256(self.baseline).hexdigest()
        self.manifest = dict(baseline, packages=desired['packages'], desktop_build=inputs)
    def test_bound_reuse(self):
        self.assertTrue(execution.validate(self.plan, self.baseline, self.manifest))
    def test_changed_output_rejected(self):
        for field, value in [('version', '9-1'), ('sha256', 'f' * 64)]:
            candidate = copy.deepcopy(self.manifest)
            candidate['packages'][0][field] = value
            with self.assertRaises(ValueError): execution.validate(self.plan, self.baseline, candidate)
        candidate = copy.deepcopy(self.manifest)
        candidate['packages'][-1]['version'] = '99-1'
        with self.assertRaises(ValueError): execution.validate(self.plan, self.baseline, candidate)
    def test_changed_baseline_or_source_rejected(self):
        with self.assertRaises(ValueError): execution.validate(self.plan, self.baseline + b' ', self.manifest)
        self.manifest['source_sha'] = 'f' * 40
        with self.assertRaises(ValueError): execution.validate(self.plan, self.baseline, self.manifest)
    def test_dependency_downgrade_rejected(self):
        desired = dict(self.plan['inputs'], pkgver='1', packages=copy.deepcopy(self.manifest['packages']))
        desired['packages'][-1]['version'] = '0.9-1'
        with self.assertRaisesRegex(ValueError, 'downgrade'):
            planner.plan(json.loads(self.baseline), desired)
    def test_recipe_version_functions_and_pair_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'source'; source.mkdir()
            (source / 'version').write_text('4.0.3\n')
            recipes = root / 'recipes'
            for name in planner.PAIR:
                recipe = recipes / 'pkgbuilds' / name; recipe.mkdir(parents=True)
                (recipe / 'PKGBUILD').write_text('[[ $CARCH == aarch64 ]] || exit 1\n_pkgver_base=old\npkgver() { cd "$srcdir/omarchy"; printf "%s.r10.gabcdef0" "$_pkgver_base"; }\n')
            command = ['bash', str(Path(__file__).with_name('edge-version.sh')), str(source), str(recipes)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.strip(), '4.0.3.r10.gabcdef0')
            (recipes / 'pkgbuilds/omarchy-settings-dev/PKGBUILD').write_text('pkgver() { echo mismatch; }')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            (recipes / 'pkgbuilds/omarchy-settings-dev/PKGBUILD').write_text('return 7\npkgver() { echo masked; }')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

if __name__ == '__main__': unittest.main()
