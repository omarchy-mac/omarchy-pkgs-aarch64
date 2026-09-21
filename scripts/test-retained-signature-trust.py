#!/usr/bin/env python3
"""Lightweight retained trust regressions; no native qualification claim."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]

class RetainedTests(unittest.TestCase):
    def test_cli_help_is_safe_and_fixture_default_remains(self):
        result = subprocess.run([sys.executable, str(ROOT/'scripts/test-signature-trust.py'), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--retained-candidate', result.stdout)
        self.assertIn('--acquire-retained', result.stdout)

    def test_exact_transport_and_receipt_reject_drift(self):
        spec = importlib.util.spec_from_file_location('trust', ROOT/'scripts/test-signature-trust.py')
        trust = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(trust)
        self.assertTrue(hasattr(trust, 'validate_retained_metadata'), 'retained metadata validation missing')
        import copy
        expected = trust.EXPECTED
        candidate = dict(id=expected['artifact_id'], name=expected['artifact_name'],
                         digest='sha256:'+expected['artifact_zip_sha256'], size_in_bytes=expected['size_in_bytes'],
                         created_at=expected['created_at'], expired=False,
                         workflow_run={'id':expected['workflow_run_id'], 'head_sha':expected['head_sha'], 'repository_id':expected['repository_id']})
        receipt_meta = dict(candidate, id=trust.RECEIPT_ID, name=trust.RECEIPT_NAME,
                            size_in_bytes=581, digest='sha256:'+trust.RECEIPT_SHA)
        run = dict(id=expected['workflow_run_id'], run_attempt=1, head_sha=expected['head_sha'],
                   path=expected['workflow_path'], event='workflow_dispatch', status='completed', conclusion='success',
                   repository={'id':expected['repository_id'], 'full_name':expected['repository']})
        trust.validate_retained_metadata(candidate, receipt_meta, run, dict(expected), expected['workflow_blob_sha'])
        for field, value in [('id', 9), ('digest', 'sha256:'+'0'*64), ('size_in_bytes', 1), ('expired', True), ('name','wrong')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                trust.validate_retained_metadata(dict(candidate, **{field:value}), receipt_meta, run, dict(expected), expected['workflow_blob_sha'])
        for field in expected:
            bad = dict(expected); bad[field] = 'wrong'
            with self.subTest(receipt=field), self.assertRaises(ValueError):
                trust.validate_retained_metadata(candidate, receipt_meta, run, bad, expected['workflow_blob_sha'])
        with self.assertRaises(ValueError):
            trust.validate_retained_metadata(candidate, receipt_meta, dict(run, run_attempt=2), dict(expected), expected['workflow_blob_sha'])
        with self.assertRaises(ValueError):
            trust.validate_retained_metadata(dict(candidate, workflow_run={'id':1}), receipt_meta, run, dict(expected), expected['workflow_blob_sha'])

    def test_zip_digest_and_safe_extraction(self):
        import tempfile, zipfile, hashlib
        spec = importlib.util.spec_from_file_location('trust', ROOT/'scripts/test-signature-trust.py')
        trust = importlib.util.module_from_spec(spec); spec.loader.exec_module(trust)
        self.assertTrue(hasattr(trust, 'extract_checked'), 'checked ZIP extraction missing')
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp); archive = tmp/'input.zip'
            with zipfile.ZipFile(archive, 'w') as z: z.writestr('repository/example', b'bytes')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaises(ValueError): trust.extract_checked(archive, tmp/'bad', '0'*64, archive.stat().st_size)
            trust.extract_checked(archive, tmp/'ok', digest, archive.stat().st_size)
            self.assertEqual((tmp/'ok/repository/example').read_bytes(), b'bytes')
            for name in ['../escape', '/absolute', 'repository/../../escape', './escape', '.', 'repository//escape']:
                with zipfile.ZipFile(archive, 'w') as z: z.writestr(name, b'bad')
                with self.assertRaises(ValueError):
                    trust.extract_checked(archive, tmp/'escape', hashlib.sha256(archive.read_bytes()).hexdigest(), archive.stat().st_size)

    def test_native_case_contract_and_signature_errors(self):
        spec = importlib.util.spec_from_file_location('trust', ROOT/'scripts/test-signature-trust.py')
        trust = importlib.util.module_from_spec(spec); spec.loader.exec_module(trust)
        self.assertTrue(hasattr(trust, 'signature_result'), 'signature-specific assertions missing')
        trust.signature_result('valid', subprocess.CompletedProcess([], 0, b'ok'), True)
        for text in [b'invalid or corrupted package (PGP signature)', b'required key missing from keyring', b'missing required signature', b'signature from x is unknown trust']:
            trust.signature_result('negative', subprocess.CompletedProcess([], 1, text), False)
        for text in [b'could not resolve host', b'failed to commit transaction (conflicting files)', b'error loading package', b'checking PGP signatures\nerror: disk full']:
            with self.assertRaises(RuntimeError):
                trust.signature_result('negative', subprocess.CompletedProcess([], 1, text), False)
        source = (ROOT/'scripts/test-signature-trust.py').read_text()
        for case in ['valid-package-install', 'modified-package', 'missing-package-signature', 'unrelated-package-trust',
                     'valid-database-download', 'modified-database', 'missing-database-signature', 'unrelated-database-trust',
                     'untrusted-before-bootstrap', 'populated-keyring-install']:
            self.assertIn(case, source)
        self.assertIn('LocalFileSigLevel = Required TrustedOnly', source)
        self.assertNotIn('--noscriptlet', source)
        self.assertIn("'--populate', 'omarchy-mac'", source)

    def test_workflow_is_opt_in_read_only_native(self):
        import yaml
        workflow = yaml.safe_load((ROOT/'.github/workflows/test.yml').read_text())
        self.assertIn('retained-rc4-trust', workflow['jobs'], 'dispatch-only retained job missing')
        job = workflow['jobs']['retained-rc4-trust']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04-arm')
        self.assertEqual(job['permissions'], {'contents':'read', 'actions':'read'})
        self.assertNotIn('environment', job)
        self.assertIn("github.event_name == 'workflow_dispatch'", job['if'])
        self.assertIn('inputs.retained_rc4_trust', job['if'])
        text = '\n'.join(step.get('run','') for step in job['steps'])
        for required in ['--acquire-retained', '--retained-candidate', ':/candidate:ro', ':/w:ro',
                         'BASE_IMAGE=menci/archlinuxarm:base-devel', 'uname -m', 'pacman-conf Architecture']:
            self.assertIn(required, text)
        self.assertNotIn('secrets.', text)
        self.assertNotIn('--privileged', text)
        self.assertNotIn('sign-candidate', text)
        fixture = '\n'.join(step.get('run','') for step in workflow['jobs']['self-tests']['steps'])
        self.assertIn('python3 scripts/test-signature-trust.py\n', fixture)
        self.assertIn('python3 scripts/test-retained-signature-trust.py -v', fixture)

    def test_runnable_roots_preserve_package_ownership_and_log_path(self):
        source = (ROOT/'scripts/test-signature-trust.py').read_text()
        self.assertIn("'/var/lib/pacman/local', db/'local'", source)
        self.assertIn("'--logfile', task/'pacman.log'", source)
        self.assertIn("(task/'pacman.log').read_text()", source)

    def test_database_negatives_stop_at_sync_and_scriptlet_failure_rejected(self):
        spec = importlib.util.spec_from_file_location('trust', ROOT/'scripts/test-signature-trust.py')
        trust = importlib.util.module_from_spec(spec); spec.loader.exec_module(trust)
        with self.assertRaises(RuntimeError):
            trust.signature_result('scriptlet-failure', subprocess.CompletedProcess([], 0, b'error: command failed to execute correctly'), True)
        source = (ROOT/'scripts/test-signature-trust.py').read_text()
        self.assertIn('if success and result.returncode == 0:', source)
        self.assertIn("shutil.rmtree(root/'etc/pacman.d/gnupg'", source)

    def test_default_cli_routes_only_to_fixture(self):
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('trust', ROOT/'scripts/test-signature-trust.py')
        trust = importlib.util.module_from_spec(spec); spec.loader.exec_module(trust)
        with patch.object(sys, 'argv', ['test-signature-trust.py']), patch.object(trust, 'fixture') as fixture:
            trust.main()
            fixture.assert_called_once_with()
        with patch.dict('os.environ', {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'hosted dispatch'):
                trust.acquire_retained(Path('/must-not-be-created'))

    def test_bootstrap_observes_same_ring_before_adding_public_trust(self):
        source = (ROOT/'scripts/test-signature-trust.py').read_text()
        before = source.index("attempt('untrusted-before-bootstrap', False, ring=trusted)") if "attempt('untrusted-before-bootstrap', False, ring=trusted)" in source else -1
        imported = source.index("command('pacman-key', '--gpgdir', trusted, '--add', signing.PUBLIC)")
        self.assertGreater(before, 0, 'same-ring untrusted observation missing')
        self.assertLess(before, imported, 'public trust was added before untrusted observation')

    def test_download_failure_does_not_expose_token(self):
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('trust', ROOT/'scripts/test-signature-trust.py')
        trust = importlib.util.module_from_spec(spec); spec.loader.exec_module(trust)
        self.assertTrue(hasattr(trust, 'download_zip'), 'safe ZIP download missing')
        def failed(args, **kwargs):
            self.assertNotIn('test-token', ' '.join(map(str,args)))
            self.assertIn(b'test-token', kwargs['input'])
            return subprocess.CompletedProcess(args, 22, b'', b'secret-bearing redirect')
        with patch.dict('os.environ', {'GH_TOKEN':'test-token'}), patch.object(trust.subprocess, 'run', failed):
            with self.assertRaisesRegex(ValueError, '^Artifact ZIP download failed$'):
                trust.download_zip(trust.RECEIPT_ID, Path('unused.zip'))

if __name__ == '__main__':
    unittest.main()
