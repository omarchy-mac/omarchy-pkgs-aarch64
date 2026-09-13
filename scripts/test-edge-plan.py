#!/usr/bin/python3
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('planner', Path(__file__).with_name('edge-plan.py'))
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)

class Planning(unittest.TestCase):
    def setUp(self):
        self.inputs = dict(source_sha='a' * 40, recipe_sha='b' * 40, publisher_sha='c' * 40)
        packages = [dict(name=name, version='4.0.2.r1-2' if name in planner.PAIR else '1-1', sha256='d' * 64)
                    for name in (*planner.PAIR, *sorted(planner.STACK))]
        self.base = dict(schema=1, client_protocol=1, channel='edge', packages=packages, **self.inputs)
        self.desired = dict(pkgver='4.0.2.r1', packages=copy.deepcopy(packages), **self.inputs)
    def test_unchanged(self):
        self.assertEqual(planner.plan(self.base, self.desired)['action'], 'skip')
    def test_source_recipe_and_publisher_changes(self):
        for key in self.inputs:
            wanted = dict(self.desired, **{key: 'e' * 40})
            result = planner.plan(self.base, wanted)
            self.assertEqual((result['action'], result['pkgrel']), ('build', 3))
    def test_new_version_and_regression_use_arch_order(self):
        self.desired.update(source_sha='e' * 40, pkgver='4.0.2.r10')
        self.assertEqual(planner.plan(self.base, self.desired)['pkgrel'], 1)
        self.desired['pkgver'] = '4.0.2.r0'
        with self.assertRaisesRegex(ValueError, 'regression'):
            planner.plan(self.base, self.desired)
    def test_dependency_reuse(self):
        self.desired['packages'][-1].update(version='2-1', sha256='e' * 64)
        result = planner.plan(self.base, self.desired)
        self.assertEqual((result['action'], result['pkgrel'], result['desktop_build']), ('reuse', 2, self.inputs))
    def test_repacked_same_version(self):
        self.desired['packages'][-1]['sha256'] = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'repacked'):
            planner.plan(self.base, self.desired)
    def test_malformed_baselines(self):
        for mutation in ({'packages': []}, {'client_protocol': 0}, {'source_sha': 'main'}, {'channel': 'rc'}, {'packages': self.base['packages'] * 2}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                planner.plan(dict(self.base, **mutation), self.desired)
    def test_provenance_mismatch(self):
        self.base['desktop_build'] = dict(self.inputs, source_sha='e' * 40)
        with self.assertRaisesRegex(ValueError, 'provenance'):
            planner.plan(self.base, self.desired)
    def test_missing_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['python3', str(Path(planner.__file__)), '--baseline', directory + '/missing', '--desired', directory + '/missing'], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
    def test_bootstrap_requires_explicit_capable_stable(self):
        self.base['channel'] = 'stable'
        for row in self.base['packages']:
            row['name'] = row['name'].removesuffix('-dev')
        self.assertEqual(planner.plan(self.base, self.desired, True)['action'], 'build')
        self.base['bootstrap'] = True
        with self.assertRaises(ValueError):
            planner.plan(self.base, self.desired, True)

if __name__ == '__main__':
    unittest.main()
