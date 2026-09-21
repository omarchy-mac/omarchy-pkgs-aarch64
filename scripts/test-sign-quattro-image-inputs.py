#!/usr/bin/python3
"""Candidate integrity and artifact-only signing boundaries."""
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import yaml

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('sign-quattro-image-inputs.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class CandidateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = 'a' * 40
        packages = []
        for name in s.build.PACKAGES:
            deps = {'omarchy': ['omarchy-settings=1.0', 'snapper'], 'omarchy-settings': [], 'omarchy-mac': ['omarchy'], 'avd-fw': [], 'libva-v4l2_request-avd': ['glibc', 'libva']}[name]
            payload = {'.PKGINFO': '\n'.join([f'pkgname = {name}', 'pkgver = 1.0-1', 'arch = any' if name == 'avd-fw' else 'arch = aarch64', *[f'depend = {d}' for d in deps]])}
            revision = 'usr/share/omarchy-mac/source-revision' if name == 'omarchy-mac' else f'usr/share/doc/{name}/source-revision'
            payload[revision] = self.source + '\n'
            if name == 'omarchy-mac':
                payload.update({p: 'fixture' for p in s.build.TRANSFERRED})
            if name == 'omarchy':
                payload['usr/bin/omarchy-hw-apple'] = 'fixture'
                for manifest in ('omarchy-base.packages', 'omarchy-apple.packages'):
                    payload['usr/share/omarchy/install/' + manifest] = 'omarchy-mac\n'
                    (self.root / manifest).write_text('omarchy-mac\n')
            filename = name + '-1.0-1-aarch64.pkg.tar.xz'
            with tarfile.open(self.root / filename, 'w:xz') as archive:
                for path, text in payload.items():
                    content = text.encode()
                    member = tarfile.TarInfo(path)
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
            packages.append(dict(name=name, version='1.0-1', filename=filename,
                                 sha256=s.build.digest(self.root / filename), dependencies=deps))
        self.data = dict(schema=2, package_repository_revision=self.source, candidate_only=True, publication='none', signing='none',
                         source_repository='omacom/omarchy-mac', source_revision=self.source, packages=packages)
        self.save()

    def save(self):
        (self.root / 'manifest.json').write_text(json.dumps(self.data))
        self.digest = s.build.digest(self.root / 'manifest.json')

    def validate(self):
        return s.validate(self.root, self.digest, self.source)

    def test_real_archives_and_embedded_manifests(self):
        self.assertEqual(len(self.validate()[1]), 8)

    def test_tampering_wrong_source_and_extra_packages(self):
        with self.assertRaises(ValueError):
            s.validate(self.root, '0' * 64, self.source)
        with self.assertRaises(ValueError):
            s.validate(self.root, self.digest, 'b' * 40)
        extra = self.root / 'extra.pkg.tar.xz'
        extra.write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'unexpected package'):
            self.validate()
        extra.unlink()
        (self.root / self.data['packages'][0]['filename']).write_bytes(b'changed')
        with patch.object(s.signing, 'Keyring') as ring:
            with self.assertRaisesRegex(ValueError, 'checksum'):
                s.seal(self.root, self.root / 'output', self.digest, self.source)
            ring.assert_not_called()

    def test_unsafe_and_duplicate_records(self):
        self.data['packages'][0]['filename'] = '../outside.pkg.tar.xz'
        self.save()
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.validate()

    def test_modified_lists_rejected(self):
        (self.root / 'omarchy-apple.packages').write_text('wrong\n')
        with self.assertRaisesRegex(ValueError, 'differs from runtime'):
            self.validate()

    def test_signature_envelope_and_unchanged_package_bytes(self):
        class Ring:
            policy = {'primary_fingerprint': 'A' * 40, 'signing_subkey_fingerprint': 'B' * 40}
            def __init__(self, **kwargs): pass
            def sign(self, path): Path(str(path) + '.sig').write_bytes(b'fixture signature')
            def close(self): pass
        dest = self.root / 'signed'
        with patch.object(s.signing, 'Keyring', Ring):
            s.seal(self.root, dest, self.digest, self.source)
        envelope = json.loads((dest / 'signing.json').read_text())
        self.assertEqual(envelope['input_manifest_sha256'], self.digest)
        self.assertEqual(envelope['publication'], 'none')
        for item in envelope['files']:
            self.assertEqual(s.build.digest(dest / item['filename']), item['sha256'])
            self.assertTrue((dest / (item['filename'] + '.sig')).is_file())
        self.assertTrue((dest / 'signing.json.sig').is_file())


class RealSigningTest(unittest.TestCase):
    setUp = CandidateTest.setUp
    save = CandidateTest.save
    def test_real_signatures_with_disposable_fixture_key(self):
        fixture = s.module('test-package-signing').SigningTests
        fixture.setUpClass()
        try:
            ring_type = s.signing.Keyring
            def ring(**kwargs):
                return ring_type(fixture.public, fixture.policy, **kwargs)
            dest = self.root / 'real-signed'
            with patch.object(s.signing, 'Keyring', side_effect=ring):
                s.seal(self.root, dest, self.digest, self.source)
            verifier = ring_type(fixture.public, fixture.policy)
            try:
                for signature in dest.glob('*.sig'):
                    verifier.verify(Path(str(signature)[:-4]))
                receipt = dest / 'signing.json'
                receipt.write_text('{}')
                with self.assertRaises(ValueError):
                    verifier.verify(receipt)
            finally:
                verifier.close()
        finally:
            fixture.tearDownClass()


class WorkflowTest(unittest.TestCase):
    def test_secrets_only_in_approved_offline_job_no_publishing(self):
        path = Path(__file__).resolve().parents[1] / '.github/workflows/build-quattro-image-inputs.yml'
        text = path.read_text()
        wf = yaml.load(text, Loader=yaml.BaseLoader)
        self.assertEqual(set(wf['on']), {'workflow_dispatch', 'schedule', 'push', 'pull_request'})
        self.assertEqual(wf['permissions'], {'contents': 'read'})
        job = wf['jobs']['sign']
        self.assertEqual(job['environment'], 'package-signing-edge')
        self.assertEqual(job['needs'], ['detect', 'build'])
        self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertIn("github.event_name != 'pull_request'", job['if'])
        self.assertIn("github.ref == 'refs/heads/main'", job['if'])
        self.assertIn("(inputs.source_ref == '' || inputs.source_ref == 'quattro-upstream')", job['if'])
        self.assertNotIn('inputs.force', job['if'])
        for forbidden in ('publish.sh', 'gh release', 'repo-add', 'contents: write', 'makepkg'):
            self.assertNotIn(forbidden, text)
        secret_steps = [step for step in job['steps'] if 'secrets.' in str(step)]
        self.assertEqual(len(secret_steps), 1)
        self.assertIn('--network none', secret_steps[0]['run'])
        self.assertIn('${{ needs.build.outputs.manifest_sha256 }}', str(job))
        self.assertIn('${{ needs.detect.outputs.source_sha }}', str(job))
        self.assertNotIn('github.token', str(job))
        self.assertFalse((path.parent / 'sign-quattro-image-inputs.yml').exists())


if __name__ == '__main__':
    unittest.main()
