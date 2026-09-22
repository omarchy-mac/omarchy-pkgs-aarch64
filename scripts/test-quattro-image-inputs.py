#!/usr/bin/python3
"""Candidate provenance, ownership and delivery-boundary regression tests."""
import copy
import fnmatch
import importlib.util
from pathlib import Path
import subprocess
import tempfile
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
                         'omarchy-mac': '0.1.0-4.10001', 'libva-v4l2_request-avd': '1.3-1.10001'}
        self.versions.update({n: '1.0-1.10001' for n in ('asdcontrol', 'tobi-try', 'qemu-user-static', 'qemu-user-static-binfmt')})
        self.records = {}
        for name, version in self.versions.items():
            self.records[name] = ({'pkgname': [name], 'pkgver': [version], 'arch': ['any' if name in builder.ANY_PACKAGES else 'aarch64']}, set(), COMMIT)
        self.records['omarchy'][0]['depend'] = ['omarchy-settings=' + VERSION, 'snapper']
        self.records['omarchy'][1].add('usr/bin/omarchy-hw-apple')
        self.records['omarchy-mac'][0]['depend'] = ['omarchy', 'iwd']
        self.records['omarchy-mac'][1].update(builder.TRANSFERRED)

    def verify(self):
        return builder.verify_packages(self.records, COMMIT, self.versions, COMMIT)

    def test_complete_same_source_set_has_one_owner_per_transferred_file(self):
        owners = self.verify()
        for path in builder.TRANSFERRED:
            self.assertEqual(owners[path], 'omarchy-mac')

    def test_video_revision_and_architecture_are_checked(self):
        fields, paths, _ = self.records['libva-v4l2_request-avd']
        self.records['libva-v4l2_request-avd'] = (fields, paths, 'b' * 40)
        with self.assertRaisesRegex(ValueError, 'mixed source revisions'):
            self.verify()
        self.records['libva-v4l2_request-avd'] = (fields, paths, COMMIT)
        fields['arch'] = ['any']
        with self.assertRaisesRegex(ValueError, 'wrong architecture'):
            self.verify()

    def test_firmware_from_asahi_alarm_is_not_a_candidate(self):
        self.records['avd-fw'] = ({'pkgname': ['avd-fw'], 'pkgver': ['0.1-1'],
                                   'arch': ['any']}, set(), COMMIT)
        with self.assertRaisesRegex(ValueError, 'exactly eight'):
            self.verify()

    def test_old_desktop_still_owning_mapper_is_rejected(self):
        self.records['omarchy'][1].add(builder.TRANSFERRED[1])
        with self.assertRaisesRegex(ValueError, 'duplicate file owner'):
            self.verify()

    def test_partial_and_mixed_revision_sets_are_rejected(self):
        saved = copy.deepcopy(self.records)
        del self.records['omarchy-settings']
        with self.assertRaisesRegex(ValueError, 'exactly eight'):
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
    def test_portable_archive_names_preserve_bytes_and_reject_collisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'asdcontrol-1:0.6.0-2-aarch64.pkg.tar.xz'
            source.write_bytes(b'unchanged archive')
            builder.normalize_archive_names(root)
            target = root / 'asdcontrol-1.0.6.0-2-aarch64.pkg.tar.xz'
            self.assertEqual(target.read_bytes(), b'unchanged archive')
            source.write_bytes(b'another archive')
            with self.assertRaisesRegex(ValueError, 'collision'):
                builder.normalize_archive_names(root)
            self.assertEqual(target.read_bytes(), b'unchanged archive')

    def test_desktop_tests_use_the_recorded_checkouts_and_neutral_terminal_environment(self):
        original = {'LC_ALL': 'C', 'NO_COLOR': '1', 'WAYLAND_DISPLAY': 'wayland-1', 'OMARCHY_PATH': '/active/desktop'}
        env = builder.test_environment(original, Path('/candidate/source'), Path('/candidate/recipes'), Path('/candidate/iso'), Path('/candidate/test-tools'))
        self.assertEqual(env['OMARCHY_PATH'], '/candidate/source')
        self.assertEqual(env['OMARCHY_PKGS_PATH'], '/candidate/recipes')
        self.assertEqual(env['OMARCHY_ISO_PATH'], '/candidate/iso')
        self.assertNotIn('NO_COLOR', env)
        self.assertNotIn('LC_ALL', env)
        self.assertTrue(env['PATH'].startswith('/candidate/source/bin:/candidate/test-tools:'))
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

    def test_video_recipes_keep_source_pins_and_record_recipe_revision(self):
        for name in builder.EXTRA_BASES:
            recipe = (ROOT / 'pkgbuilds' / name / 'PKGBUILD').read_text()
            prepared = builder.prepare_extra_recipe(recipe, name, COMMIT, '1.90001')
            self.assertIn('pkgrel=1.90001', prepared)
            self.assertIn('usr/share/doc/$pkgname/source-revision', prepared)
            self.assertIn('\n' + COMMIT + '\nREVISION\n', prepared)
            for line in recipe.splitlines():
                if line.startswith(('source=', 'sha256sums=')):
                    self.assertIn(line, prepared)
            subprocess.run(['bash', '-n'], input=prepared, text=True, check=True)

    def test_changed_recipe_shape_fails_instead_of_silently_misbuilding(self):
        with self.assertRaises(ValueError):
            builder.prepare_recipe('pkgver=4.0.2\n', 'omarchy', COMMIT, VERSION, '1.10001')
        with self.assertRaisesRegex(ValueError, 'unsafe package version'):
            builder.prepare_recipe('', 'omarchy', COMMIT, '$(false)', '1.10001')


class DeliveryBoundaryTest(unittest.TestCase):
    def test_scheduled_candidate_workflow_has_no_publishing_credentials(self):
        text = (ROOT / '.github/workflows/build-quattro-image-inputs.yml').read_text()
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow['on']), {'schedule', 'push', 'workflow_dispatch', 'pull_request'})
        self.assertIn('scripts/build-quattro-image-inputs.py', workflow['on']['pull_request']['paths'])
        self.assertEqual(set(workflow['on']['workflow_dispatch']['inputs']), {'source_ref', 'force'})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertNotIn('secrets.', str(workflow['jobs']['build']))
        self.assertNotIn('GITHUB_TOKEN', text)
        self.assertEqual(set(workflow['jobs']), {'detect', 'build', 'sign'})
        self.assertEqual(workflow['jobs']['detect']['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(workflow['on']['push']['branches'], ['main'])
        self.assertEqual(workflow['concurrency']['cancel-in-progress'], 'false')
        job = workflow['jobs']['build']
        self.assertNotIn('GH_TOKEN', str(job))
        self.assertNotIn('github.token', str(job))
        self.assertEqual(job['needs'], 'detect')
        self.assertEqual(job['if'], "needs.detect.outputs.needs_build == 'true'")
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

    def test_triggers_cover_every_cached_build_input_and_pin_detected_revisions(self):
        spec = importlib.util.spec_from_file_location('detector', ROOT / 'scripts/detect-quattro-image-inputs.py')
        detector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(detector)
        workflow = yaml.load((ROOT / '.github/workflows/build-quattro-image-inputs.yml').read_text(), Loader=yaml.BaseLoader)
        for event in ('push', 'pull_request'):
            patterns = workflow['on'][event]['paths']
            for path in detector.BUILD_INPUTS:
                probe = path + '/PKGBUILD' if path.startswith('pkgbuilds/') and '.' not in path.rsplit('/', 1)[-1] and path != 'pkgbuilds/omarchy-steam-fex/omarchy-launch-steam' else path
                self.assertTrue(any(fnmatch.fnmatchcase(probe, pattern) for pattern in patterns), probe)
        steps = workflow['jobs']['build']['steps']
        self.assertEqual(steps[0]['with']['ref'], '${{ needs.detect.outputs.recipe_sha }}')
        desktop = next(step for step in steps if step.get('with', {}).get('repository') == 'omacom/omarchy-mac')
        self.assertEqual(desktop['with']['ref'], '${{ needs.detect.outputs.source_sha }}')
        artifact = steps[-1]
        self.assertEqual(artifact['with']['name'], '${{ needs.detect.outputs.artifact_name }}')
        self.assertEqual(artifact['with']['overwrite'], 'true')

    def test_existing_updaters_do_not_consume_the_candidate_artifacts(self):
        for name in ('update-omarchy-mac.yml', 'update-packages.yml'):
            text = (ROOT / '.github/workflows' / name).read_text()
            self.assertNotIn('quattro-image-inputs', text)
            self.assertNotIn('addon-candidate:', text)
        for name in ('build-mac-addon-candidate.yml',):
            self.assertFalse((ROOT / '.github/workflows' / name).exists())


if __name__ == '__main__':
    unittest.main()
