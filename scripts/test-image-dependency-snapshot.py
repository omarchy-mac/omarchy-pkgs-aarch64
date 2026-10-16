#!/usr/bin/python3
"""Exact-byte snapshot fixtures and nonpublishing workflow boundaries."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import yaml


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


s = module('image-dependency-snapshot')
Remote = module('test-bootstrap-rc').Remote


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        base = self.root / 'base'
        base.mkdir()
        for name in ['omarchy-nvim', 'omarchy-steam-fex', *sorted(s.LIMINE_EXCLUDED)]:
            path = base / f'{name}-1-1-any.pkg.tar.xz'
            with tarfile.open(path, 'w:xz') as tar:
                data = f'pkgname = {name}\npkgver = 1-1\narch = any\npkgdesc = fixture\n'.encode()
                info = tarfile.TarInfo('.PKGINFO'); info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        s.bundle.build_db(base)
        self.remote = Remote()
        self.remote.releases['edge'] = {'draft': False, 'commit': 'a'*40,
            'assets': {p.name:p.read_bytes() for p in base.iterdir() if p.is_file()}}
        self.database_hash = s.bundle.digest(base / (s.boot.DB + '.db'))
        self.capture = self.root / 'capture'
        with patch.object(s.boot, 'GitHub', return_value=self.remote), patch.object(s.boot, 'guard'):
            s.capture(self.capture, self.database_hash)
        self.capture_hash = s.bundle.digest(self.capture / 'capture-manifest.json')

    def test_exact_capture_includes_extra_packages_and_excludes_candidates_only_at_sealing(self):
        packages = s.validate_capture(self.capture, self.capture_hash, self.database_hash)
        self.assertEqual(set(packages), {'omarchy-nvim', 'omarchy-steam-fex'} | (s.LIMINE_EXCLUDED - s.EXCLUDED))
        self.assertTrue(all(event[0] in ('view','read') for event in self.remote.events))

    def test_limine_excludes_complete_candidate_set_and_replaced_boot_packages(self):
        packages = s.validate_capture(self.capture, self.capture_hash, self.database_hash, 'limine')
        self.assertEqual(set(packages), {'omarchy-nvim', 'omarchy-steam-fex'})
        candidate = module('build-quattro-image-inputs')
        self.assertEqual(s.LIMINE_EXCLUDED, set(candidate.candidate_packages(4)) |
                         {'omarchy-apple-boot', 'omarchy-first-boot'})

    def test_unknown_profile_rejected_before_credentials(self):
        with patch.object(s.bundle.signing, 'Keyring') as key:
            with self.assertRaisesRegex(ValueError, 'Unknown dependency'):
                s.seal(self.capture, self.root/'unknown', self.capture_hash, self.database_hash, 'unknown')
            key.assert_not_called()

    def test_profile_contract_cannot_widen_exclusions(self):
        data = s.contract('limine')
        data['excluded_names'].append('omarchy-nvim')
        with self.assertRaisesRegex(ValueError, 'snapshot contract'):
            s.check_contract(data, 'limine')
        with self.assertRaisesRegex(ValueError, 'snapshot contract'):
            s.check_contract(s.contract('grub'), 'limine')

    def test_wrong_database_and_tampered_package_rejected_before_key_loading(self):
        with patch.object(s.bundle.signing, 'Keyring') as key:
            with self.assertRaises(ValueError):
                s.seal(self.capture, self.root/'wrong', self.capture_hash, 'f'*64)
            next((self.capture/'packages').glob('omarchy-nvim-*')).write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                s.seal(self.capture, self.root/'tampered', self.capture_hash, self.database_hash)
            key.assert_not_called()

    def test_real_signatures_keep_package_bytes_unchanged(self):
        fixture = module('test-package-signing').SigningTests
        fixture.setUpClass()
        try:
            key_type = s.bundle.signing.Keyring
            with patch.object(s.bundle.signing, 'Keyring', side_effect=lambda **kw:key_type(fixture.public, fixture.policy, **kw)):
                output = self.root/'signed'
                manifest = s.seal(self.capture, output, self.capture_hash, self.database_hash)
                self.assertEqual(s.verify(output, s.bundle.digest(output/'manifest.json')), manifest)
                with self.assertRaises(ValueError):
                    s.verify(output, 'f'*64)
                limine = self.root/'signed-limine'
                limine_manifest = s.seal(self.capture, limine, self.capture_hash, self.database_hash, 'limine')
                digest = s.bundle.digest(limine/'manifest.json')
                self.assertEqual(s.verify(limine, digest, 'limine'), limine_manifest)
                self.assertEqual({r['name'] for r in limine_manifest['packages']},
                                 {'omarchy-nvim', 'omarchy-steam-fex'})
                self.assertEqual(limine_manifest['candidate_schema'], 4)
                with self.assertRaisesRegex(ValueError, 'snapshot contract'):
                    s.verify(limine, digest)
                with self.assertRaisesRegex(ValueError, 'snapshot contract'):
                    s.verify(output, s.bundle.digest(output/'manifest.json'), 'limine')
            verifier = key_type(fixture.public, fixture.policy)
            try:
                for p in output.glob('*.sig'):
                    verifier.verify(Path(str(p)[:-4]))
                self.assertEqual(manifest['publication'], 'none')
                for record in manifest['packages']:
                    self.assertEqual((output/record['filename']).read_bytes(), (self.capture/'packages'/record['filename']).read_bytes())
                self.assertFalse(any((output/r).exists() for r in ['omarchy-1-1-any.pkg.tar.xz']))
            finally:
                verifier.close()
        finally:
            fixture.tearDownClass()


class WorkflowTest(unittest.TestCase):
    def test_artifact_only_main_only_offline_signing(self):
        path = Path(__file__).resolve().parents[1]/'.github/workflows/image-dependency-snapshot.yml'
        text = path.read_text(); data = yaml.load(text, Loader=yaml.BaseLoader)
        self.assertEqual(set(data['on']), {'workflow_dispatch'})
        self.assertEqual(data['permissions'], {'contents':'read'})
        self.assertNotIn('secrets.', str(data['jobs']['capture']))
        for job in data['jobs'].values():
            self.assertIn("github.ref == 'refs/heads/main'", job['if'])
        secret_steps = [x for x in data['jobs']['sign']['steps'] if 'secrets.' in str(x)]
        self.assertEqual(len(secret_steps),1)
        self.assertIn('--network none', secret_steps[0]['run'])
        for forbidden in ('contents: write', 'gh release', '--execute', 'publish.sh', 'edge-publish'):
            self.assertNotIn(forbidden,text)


if __name__ == '__main__':
    unittest.main()
