#!/usr/bin/python3
"""Candidate provenance, ownership and delivery-boundary regression tests."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('builder', ROOT / 'scripts/build-quattro-image-inputs.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
COMMIT = 'a' * 40
VERSION = '4.0.0.alpha.quattro.r1790000000.gaaaaaaaaaaaa'


class PackageSetTest(unittest.TestCase):
    def setUp(self):
        self.versions = {'omarchy': VERSION + '-1.10001', 'omarchy-settings': VERSION + '-1.10001',
                         'omarchy-mac': '0.1.0-4.10001'}
        self.records = {}
        for name, version in self.versions.items():
            self.records[name] = ({'pkgname': [name], 'pkgver': [version], 'arch': ['aarch64']}, set(), COMMIT)
        self.records['omarchy'][0]['depend'] = ['omarchy-settings=' + VERSION, 'snapper']
        self.records['omarchy'][1].add('usr/bin/omarchy-hw-apple')
        self.records['omarchy-mac'][0]['depend'] = ['omarchy', 'iwd']
        self.records['omarchy-mac'][1].update(builder.TRANSFERRED)

    def verify(self):
        return builder.verify_packages(self.records, COMMIT, self.versions)

    def test_complete_same_source_set_has_one_owner_per_transferred_file(self):
        owners = self.verify()
        for path in builder.TRANSFERRED:
            self.assertEqual(owners[path], 'omarchy-mac')

    def test_old_desktop_still_owning_mapper_is_rejected(self):
        self.records['omarchy'][1].add(builder.TRANSFERRED[1])
        with self.assertRaisesRegex(ValueError, 'duplicate file owner'):
            self.verify()

    def test_partial_and_mixed_revision_sets_are_rejected(self):
        saved = copy.deepcopy(self.records)
        del self.records['omarchy-settings']
        with self.assertRaisesRegex(ValueError, 'exactly three'):
            self.verify()
        self.records = saved
        fields, paths, _ = self.records['omarchy-settings']
        self.records['omarchy-settings'] = (fields, paths, 'b' * 40)
        with self.assertRaisesRegex(ValueError, 'mixed source revisions'):
            self.verify()

    def test_wrong_architecture_version_and_settings_dependency_are_rejected(self):
        for key, value in [('arch', ['x86_64']), ('pkgver', ['4.0.4-1']),
                           ('depend', ['omarchy-settings', 'snapper'])]:
            with self.subTest(key=key):
                original = copy.deepcopy(self.records['omarchy'][0])
                self.records['omarchy'][0][key] = value
                with self.assertRaises(ValueError):
                    self.verify()
                self.records['omarchy'][0].clear()
                self.records['omarchy'][0].update(original)

    def test_addon_cannot_take_administrator_files_or_select_a_kernel(self):
        self.records['omarchy-mac'][1].add('etc/NetworkManager/conf.d/wifi.conf')
        with self.assertRaisesRegex(ValueError, 'administrator files'):
            self.verify()
        self.records['omarchy-mac'][1].remove('etc/NetworkManager/conf.d/wifi.conf')
        self.records['omarchy-mac'][0]['depend'].append('linux-asahi')
        with self.assertRaisesRegex(ValueError, 'selects a kernel'):
            self.verify()


class RecipeTest(unittest.TestCase):
    def test_desktop_tests_use_the_recorded_checkouts_and_neutral_terminal_environment(self):
        original = {'LC_ALL': 'C', 'NO_COLOR': '1', 'WAYLAND_DISPLAY': 'wayland-1', 'OMARCHY_PATH': '/active/desktop'}
        env = builder.test_environment(original, Path('/candidate/source'), Path('/candidate/recipes'), Path('/candidate/iso'))
        self.assertEqual(env['OMARCHY_PATH'], '/candidate/source')
        self.assertEqual(env['OMARCHY_PKGS_PATH'], '/candidate/recipes')
        self.assertEqual(env['OMARCHY_ISO_PATH'], '/candidate/iso')
        self.assertNotIn('NO_COLOR', env)
        self.assertNotIn('LC_ALL', env)
        self.assertNotIn('WAYLAND_DISPLAY', env)
        self.assertEqual(original['NO_COLOR'], '1')

    def test_prepared_desktop_recipe_records_the_source_and_clears_old_tag(self):
        recipe = "pkgver=4.0.2\npkgrel=1\n_commit=old\n_tag=v4.0.2\npackage() {\n  cd \"$srcdir/omarchy\"\n}\n"
        result = builder.prepare_recipe(recipe, 'omarchy', COMMIT, VERSION, '1.10001')
        self.assertIn('pkgver=' + VERSION + '\n', result)
        self.assertIn("_tag=''\n", result)
        self.assertIn('usr/share/doc/omarchy/source-revision', result)
        self.assertIn('\n' + COMMIT + '\nREVISION\n', result)
        subprocess.run(['bash', '-n'], input=result, text=True, check=True)

    def test_changed_recipe_shape_fails_instead_of_silently_misbuilding(self):
        with self.assertRaises(ValueError):
            builder.prepare_recipe('pkgver=4.0.2\n', 'omarchy', COMMIT, VERSION, '1.10001')
        with self.assertRaisesRegex(ValueError, 'unsafe package version'):
            builder.prepare_recipe('', 'omarchy', COMMIT, '$(false)', '1.10001')


class DeliveryBoundaryTest(unittest.TestCase):
    def test_workflow_is_manual_artifact_only_and_has_no_credentials(self):
        text = (ROOT / '.github/workflows/build-quattro-image-inputs.yml').read_text()
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow['on']), {'workflow_dispatch'})
        self.assertEqual(set(workflow['on']['workflow_dispatch']['inputs']), {'source_ref'})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertNotIn('secrets.', text)
        self.assertNotIn('GH_TOKEN', text)
        self.assertNotIn('GITHUB_TOKEN', text)
        self.assertEqual(set(workflow['jobs']), {'build'})
        job = workflow['jobs']['build']
        self.assertNotIn('environment', job)
        self.assertNotIn('permissions', job)
        allowed_actions = ('actions/checkout@', 'actions/upload-artifact@')
        for step in job['steps']:
            if 'uses' in step:
                self.assertTrue(step['uses'].startswith(allowed_actions))
            for prohibited in ('publish.sh', 'repo-add', 'gh release', 'build-mac-candidate-pair.sh'):
                self.assertNotIn(prohibited, step.get('run', ''))
            if step.get('uses', '').startswith('actions/checkout@'):
                self.assertEqual(step['with']['persist-credentials'], 'false')

    def test_existing_updaters_do_not_consume_the_candidate_artifacts(self):
        for name in ('update-omarchy-mac.yml', 'update-packages.yml'):
            text = (ROOT / '.github/workflows' / name).read_text()
            self.assertNotIn('quattro-image-inputs', text)


if __name__ == '__main__':
    unittest.main()
