#!/usr/bin/python3
"""Exercise exact candidate admission and signing with synthetic packages/test keys."""
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fixtures = module('test-aurora-candidate')
c = fixtures.c
signing_fixture = module('test-package-signing')


class ReleaseFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture = fixtures.CandidateTest('test_complete_set')
        fixture.setUp()
        for name, (info, build, members) in fixture.records.items():
            payload = {member: b'fixture, never installed' for member in members}
            for member, data in (('.PKGINFO', info), ('.BUILDINFO', build)):
                payload[member] = ''.join(f'{key} = {value}\n' for key, values in data.items()
                                          for value in values).encode()
            with tarfile.open(self.root / f'{name}.pkg.tar.xz', 'w:xz') as archive:
                for path, data in payload.items():
                    member = tarfile.TarInfo(path)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
        provenance = {'installed_dependencies': ['compiler-1.0-1-aarch64']}
        data = c.audit(self.root, fixture.lock, provenance)
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps(data))
        self.expected = c.digest(self.manifest)

    def test_real_archive_admission_and_tampering(self):
        data = c.verify_candidate(self.root, self.expected)
        self.assertEqual(len(data['packages']), 3)
        with self.assertRaisesRegex(ValueError, 'checksum'):
            c.verify_candidate(self.root, '0' * 64)
        extra = self.root / 'extra.pkg.tar.xz'
        extra.write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'exactly three'):
            c.verify_candidate(self.root, self.expected)
        extra.unlink()
        self.manifest.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            c.verify_candidate(self.root, self.expected)

    def test_disposable_signatures_bind_exact_approved_set(self):
        # Verification completes before any secret is made available. This is
        # a fixture of the future release boundary, not a production signer.
        data = c.verify_candidate(self.root, self.expected)
        fixture = signing_fixture.SigningTests
        fixture.setUpClass()
        try:
            ring = signing_fixture.s.Keyring(fixture.public, fixture.policy, secret=True)
            signed = self.root / 'signed'
            signed.mkdir()
            try:
                names = ['manifest.json', *[p['filename'] for p in data['packages']]]
                for name in names:
                    target = signed / name
                    shutil.copyfile(self.root / name, target)
                    ring.sign(target)
                    ring.verify(target)
                target = signed / data['packages'][0]['filename']
                target.write_bytes(b'replaced archive')
                with self.assertRaises(ValueError):
                    ring.verify(target)
                target = signed / 'manifest.json'
                target.write_text('{}')
                with self.assertRaises(ValueError):
                    ring.verify(target)
            finally:
                ring.close()
        finally:
            fixture.tearDownClass()


if __name__ == '__main__':
    unittest.main()
