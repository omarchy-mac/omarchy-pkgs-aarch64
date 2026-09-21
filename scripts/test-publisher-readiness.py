#!/usr/bin/env python3
"""No-secret hosted recipe readiness, not a production signing workflow.

Default: portable workflow contracts. --prepare: generate disposable inputs.
--native: real preflight and private-pipe seal/check with read-only fixture inputs.
"""
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent


class ReadinessContractTests(unittest.TestCase):
    def test_manual_hardened_job_reuses_publisher_without_publication(self):
        import yaml
        document = yaml.safe_load((ROOT / '.github/workflows/test.yml').read_text())
        trigger = document.get('on', document.get(True))
        self.assertIn('publisher_readiness', trigger['workflow_dispatch']['inputs'],
                      'No manual publisher readiness input')
        self.assertIs(trigger['workflow_dispatch']['inputs']['publisher_readiness']['default'], False)
        job = document['jobs']['publisher-readiness']
        self.assertIn("github.event_name == 'workflow_dispatch'", job['if'])
        self.assertIn('inputs.publisher_readiness', job['if'])
        self.assertEqual(job['runs-on'], 'ubuntu-24.04-arm')
        self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertNotIn('environment', job)
        text = str(job)
        self.assertNotIn('secrets.', text)
        self.assertNotIn('docker push', text)
        self.assertNotIn('sign-and-retain-rc4', text)
        commands = '\n'.join(step.get('run', '') for step in job['steps'])
        self.assertIn('-f .github/publisher.Dockerfile', commands)
        self.assertRegex(commands, r'menci/archlinuxarm@sha256:[a-f0-9]{64}')
        self.assertIn('docker image inspect', commands)
        self.assertIn('--iidfile', commands)
        for flag in ('--network none', '--pull never', '--read-only', '--cap-drop ALL',
                     '--security-opt no-new-privileges', '--user "$(id -u):$(id -g)"'):
            self.assertIn(flag, commands)
        self.assertIn('target=/inputs,readonly', commands)
        self.assertIn('--prepare', commands)
        self.assertIn('--native', commands)
        self.assertIn('"$image"', commands)
        self.assertIn('test-publisher-readiness.py -v',
                      '\n'.join(s.get('run', '') for s in document['jobs']['self-tests']['steps']))


class NativePublisherReadiness(unittest.TestCase):
    """Runs only in the opt-in hosted isolated container, never with mocks."""
    def test_public_preflight_and_private_pipe_seal_check(self):
        fixture = load_bundle_fixture()
        bundle = fixture.bundle
        self.assertNotEqual(os.getuid(), 0)
        self.assertEqual(os.uname().machine, 'aarch64')
        status = Path('/proc/self/status').read_text()
        self.assertRegex(status, r'CapEff:\s+0+\n')
        self.assertRegex(status, r'NoNewPrivs:\s+1\n')
        self.assertEqual({p.name for p in Path('/sys/class/net').iterdir()}, {'lo'})
        for directory in ('/', '/w', '/inputs'):
            self.assertTrue(os.statvfs(directory).f_flag & os.ST_RDONLY, directory)
        self.assertFalse(bundle.signing.SECRET_ENV & set(os.environ))
        # Call the real public preflight, including tools, disk scratch and GnuPG import.
        signing = bundle.signing
        policy = signing.policy()
        signing.preflight(signing.PUBLIC, signing.POLICY,
                          signing.digest(signing.PUBLIC), signing.digest(signing.POLICY),
                          policy['primary_fingerprint'], policy['signing_subkey_fingerprint'])
        for command in ('repo-add', 'vercmp', 'cp', 'gzip', 'xz', 'zstd'):
            self.assertIsNotNone(shutil.which(command), command)
        inputs, output = Path('/inputs'), Path('/output/signed')
        unsigned = inputs / 'unsigned'
        before = {p.relative_to(inputs): bundle.digest(p)
                  for p in inputs.rglob('*') if p.is_file()}
        bundle.check(unsigned)  # Real archive/database eligibility before reading fixture secrets.
        key = bytearray(Path('/fixture-secrets/subkey').read_bytes())
        password = bytearray(Path('/fixture-secrets/passphrase').read_bytes())
        Path('/fixture-secrets/subkey').unlink()
        Path('/fixture-secrets/passphrase').unlink()
        fixture.launch_fixture_signer([
            sys.executable, '-B', str(ROOT / 'scripts/test-release-bundle.py'),
            '--private-fixture-child', str(unsigned), str(output),
            str(inputs / 'public.gpg'), str(inputs / 'policy.json'), '/tmp'], (key, password))
        self.assertFalse(any(key))
        self.assertFalse(any(password))
        manifest = bundle.check(output, inputs / 'policy.json')  # Separate public-only keyring.
        self.assertEqual(manifest['signature_policy'], bundle.STRICT_POLICY)
        self.assertEqual(manifest['unsigned_manifest_sha256'], bundle.digest(unsigned / 'manifest.json'))
        self.assertEqual(before, {p.relative_to(inputs): bundle.digest(p)
                                  for p in inputs.rglob('*') if p.is_file()})
        # A changed output must fail independent validation, not merely return a signed manifest.
        package = signing.packages(output / 'assets')[0]
        with package.open('ab') as stream:
            stream.write(b'deliberate fixture corruption')
        with self.assertRaises(ValueError):
            bundle.check(output, inputs / 'policy.json')


def load_bundle_fixture():
    spec = importlib.util.spec_from_file_location('readiness_bundle', ROOT / 'scripts/test-release-bundle.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_disposable_fixture():
    import base64
    fixture = load_bundle_fixture().ReleaseBundleTests
    fixture.setUpClass()
    try:
        shutil.copytree(str(fixture.rc) + '.unsigned', '/inputs/unsigned')
        shutil.copyfile(fixture.keys.public, '/inputs/public.gpg')
        shutil.copyfile(fixture.keys.policy, '/inputs/policy.json')
        # Disposable test subkey only; never saved to a CI artifact or logged.
        for name, data in [('subkey', base64.b64decode(os.environ['PACMAN_SIGNING_SUBKEY_B64'])),
                           ('passphrase', os.environ['PACMAN_SIGNING_PASSPHRASE'].encode())]:
            path = Path('/fixture-secrets') / name
            with path.open('xb') as stream:
                path.chmod(0o600)
                stream.write(data)
    finally:
        fixture.tearDownClass()  # Remove the disposable primary before the signing container starts.


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare']:
        prepare_disposable_fixture()
    elif sys.argv[1:] == ['--native']:
        unittest.main(argv=[sys.argv[0], 'NativePublisherReadiness', '-v'])
    else:
        unittest.main(argv=[sys.argv[0], 'ReadinessContractTests', *sys.argv[1:]])
