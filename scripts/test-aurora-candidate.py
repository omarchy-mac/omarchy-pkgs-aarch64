#!/usr/bin/python3
"""Pure candidate rejection tests; no build, package installation, or keys."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('aurora-candidate.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CandidateTest(unittest.TestCase):
    def setUp(self):
        self.lock = c.inputs()
        self.prefix = 'usr/lib/modules/7.1.12-aurora'
        self.records = {}
        for name in c.NAMES:
            recipe = 'm1n1-aurora' if name == 'm1n1-aurora' else 'linux-aurora'
            info = {'pkgname': [name], 'pkgver': [self.lock['packages'][name]], 'arch': ['aarch64']}
            build = {'pkgbuild_sha256sum': [self.lock['files'][f'pkgbuilds/{recipe}/PKGBUILD']],
                     'installed': ['compiler-1.0-1']}
            self.records[name] = info, build, set()
        kernel, headers, boot = [self.records[n] for n in ('linux-aurora', 'linux-aurora-headers', 'm1n1-aurora')]
        kernel[0]['conflict'] = ['linux-asahi']
        kernel[2].update(self.prefix + '/' + n for n in ('vmlinuz', 'pkgbase', 'dtbs/t8122-j613.dtb'))
        headers[0]['conflict'] = ['linux-asahi-headers']
        headers[2].add(self.prefix + '/build/Makefile')
        boot[0].update(conflict=['m1n1'], provides=['m1n1=1.6.1'], depend=['asahi-scripts>=20260127.1'])
        boot[2].add('usr/lib/asahi-boot/m1n1.bin')

    def verify(self):
        return c.validate_records(self.records, self.lock, ['compiler-1.0-1'])

    def test_complete_set(self):
        self.assertEqual(self.verify(), '7.1.12-aurora')

    def test_missing_or_unexpected_package(self):
        self.records.pop('m1n1-aurora')
        with self.assertRaisesRegex(ValueError, 'package set'):
            self.verify()

    def test_wrong_version_architecture_or_recipe(self):
        for table, field in ((0, 'pkgver'), (0, 'arch'), (1, 'pkgbuild_sha256sum')):
            with self.subTest(field=field):
                value = self.records['linux-aurora'][table][field]
                self.records['linux-aurora'][table][field] = ['wrong']
                with self.assertRaises(ValueError):
                    self.verify()
                self.records['linux-aurora'][table][field] = value

    def test_build_dependencies_must_match(self):
        self.records['linux-aurora'][1]['installed'].append('unrecorded-2.0-1')
        with self.assertRaisesRegex(ValueError, 'inventory differs'):
            self.verify()

    def test_mixed_kernel_and_headers(self):
        self.records['linux-aurora-headers'][2].clear()
        self.records['linux-aurora-headers'][2].add('usr/lib/modules/old/build/Makefile')
        with self.assertRaisesRegex(ValueError, 'Headers do not match'):
            self.verify()

    def test_missing_dtb_or_bootloader(self):
        for name, member in [('linux-aurora', self.prefix + '/dtbs/t8122-j613.dtb'),
                             ('m1n1-aurora', 'usr/lib/asahi-boot/m1n1.bin')]:
            with self.subTest(name=name):
                self.records[name][2].remove(member)
                with self.assertRaises(ValueError):
                    self.verify()
                self.records[name][2].add(member)

    def test_conflicting_ownership(self):
        self.records['linux-aurora-headers'][2].add(self.prefix + '/vmlinuz')
        with self.assertRaisesRegex(ValueError, 'Conflicting file ownership'):
            self.verify()

    def test_missing_replacement_dependency(self):
        self.records['m1n1-aurora'][0]['depend'] = []
        with self.assertRaisesRegex(ValueError, 'boot-script dependency'):
            self.verify()

    def test_omarchy_dependency_rejected(self):
        self.records['linux-aurora'][0]['depend'] = ['omarchy-mac-boot']
        with self.assertRaisesRegex(ValueError, 'Desktop dependency'):
            self.verify()

    def test_changed_recipe_or_config_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lock = copy.deepcopy(self.lock)
            for name in lock['files']:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((c.ROOT / name).read_bytes())
            (root / 'scripts').mkdir()
            (root / 'scripts/aurora-candidate-inputs.json').write_text(json.dumps(lock))
            self.assertEqual(c.inputs(root), lock)
            (root / 'pkgbuilds/linux-aurora/config').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'Input changed'):
                c.inputs(root)


if __name__ == '__main__':
    unittest.main()
