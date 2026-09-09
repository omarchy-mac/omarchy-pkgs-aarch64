#!/usr/bin/python3
import argparse
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('snapshot', Path(__file__).with_name('channel-snapshot.py'))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        real_run = snapshot.run
        def run(*args, **kwargs):
            if args[0] == 'gpgv':
                return ''  # Cryptographic key trust is exercised against imported upstream archives.
            return real_run(*args, **kwargs)
        patch = mock.patch.object(snapshot, 'run', side_effect=run)
        patch.start()
        self.addCleanup(patch.stop)
        self.packages = self.root / 'packages'
        self.packages.mkdir()
        for name in ['omarchy', 'omarchy-settings', *sorted(snapshot.STACK), 'overlay-tool']:
            self.package(name)
        self.inventory = self.root / 'inventory.json'
        self.inventory.write_text(json.dumps(['overlay-tool', *snapshot.STACK]))

    def package(self, name, version='4.0.3-1'):
        data = f'pkgname = {name}\npkgver = {version}\narch = aarch64\ndepend = snapper\n'.encode()
        path = self.packages / f'{name}-{version}-aarch64.pkg.tar.xz'
        with tarfile.open(path, 'w:xz') as archive:
            info = tarfile.TarInfo('.PKGINFO')
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            if name in ('omarchy', 'omarchy-dev'):
                entry = tarfile.TarInfo('usr/share/omarchy/install/helpers/arm-channel-manifest.py')
                archive.addfile(entry, io.BytesIO(b''))
        if name in snapshot.STACK:
            path.with_name(path.name + ".sig").write_bytes(b"detached signature fixture")
        return path

    def prepare(self, channel='rc'):
        output = self.root / channel
        snapshot.prepare(argparse.Namespace(packages=str(self.packages), output=str(output), channel=channel,
                         inventory=str(self.inventory), source_sha='a' * 40, recipe_sha='b' * 40,
                         publisher_sha='c' * 40, bootstrap=False, signed_inventory=None, signature_keyring='/unused-test-keyring'))
        return output

    def test_reused_desktop_provenance_survives_snapshot(self):
        build = dict(source_sha='a' * 40, recipe_sha='b' * 40, publisher_sha='d' * 40)
        (self.packages / 'input-provenance.json').write_text(json.dumps(dict(desktop_build=build)))
        manifest = snapshot.verify(self.prepare())
        self.assertEqual(manifest['desktop_build'], build)
        self.assertEqual(manifest['publisher_sha'], 'c' * 40)
        build['source_sha'] = 'e' * 40
        manifest['desktop_build'] = build
        with self.assertRaises(ValueError):
            snapshot.check_identity(manifest)

    def test_final_rc_promotes_same_bytes(self):
        source = self.prepare()
        target = self.root / 'stable'
        snapshot.promote(argparse.Namespace(snapshot=str(source), output=str(target), channel='stable', signature_keyring='/unused-test-keyring'))
        before, after = snapshot.verify(source), snapshot.verify(target)
        self.assertEqual(before['packages'], after['packages'])
        self.assertEqual(before['databases'], after['databases'])
        self.assertEqual(after['channel'], 'stable')

    def test_mutated_archive_rejected(self):
        output = self.prepare()
        next(output.glob('*.pkg.tar.xz')).write_bytes(b'changed')
        with self.assertRaises(ValueError):
            snapshot.verify(output)

    def test_incomplete_inventory_rejected(self):
        next(self.packages.glob('overlay-tool-*')).unlink()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_rc_rejects_dev_pair(self):
        self.package('omarchy-dev')
        self.package('omarchy-settings-dev')
        with self.assertRaises(ValueError):
            self.prepare()

    def test_edge_requires_dev_identity(self):
        with self.assertRaises(ValueError):
            self.prepare('edge')
        self.package('omarchy-dev')
        self.package('omarchy-settings-dev')
        source = self.prepare('edge')
        target = self.root / 'rc'
        snapshot.promote(argparse.Namespace(snapshot=str(source), output=str(target), channel='rc', signature_keyring='/unused-test-keyring'))
        self.assertFalse({'omarchy-dev', 'omarchy-settings-dev'} & {p['name'] for p in snapshot.verify(target)['packages']})
        self.assertEqual((target / 'omarchy-4.0.3-1-aarch64.pkg.tar.xz').read_bytes(), (source / 'omarchy-4.0.3-1-aarch64.pkg.tar.xz').read_bytes())

    def test_stable_rejects_rc_version(self):
        for path in self.packages.glob('omarchy-*'):
            path.unlink()
        self.package('omarchy', '4.0.3rc1-1')
        self.package('omarchy-settings', '4.0.3rc1-1')
        with self.assertRaises(ValueError):
            self.prepare('stable')

    def test_sha_must_be_immutable(self):
        output = self.prepare()
        manifest = snapshot.verify(output)
        manifest['source_sha'] = 'quattro'
        snapshot.write_manifest(output, manifest)
        with self.assertRaises(ValueError):
            snapshot.verify(output)


if __name__ == '__main__':
    unittest.main()
