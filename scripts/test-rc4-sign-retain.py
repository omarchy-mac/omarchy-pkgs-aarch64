#!/usr/bin/env python3
"""Tiny synthetic tests for the nonpublishing signed RC4 fixture only."""
import copy
from contextlib import ExitStack, contextmanager
from email.message import Message
import hashlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import tarfile
import tempfile
import traceback
import unittest
from unittest.mock import patch
import urllib.error
import yaml

ROOT = Path(__file__).resolve().parent.parent
CLASSIFICATION = 'nonpublishing signed RC4 exact-byte qualification fixture only'
EXPECTED_SOURCE_EVIDENCE = {
    'report_39_sha256': '1632ad43ba98c749cd22a9385870619e8b6580663eb798bb3a15a15e5c270363',
    'report_40_sha256': '64e6f1ee61943ed2cb10945bb285386c3d70a8e9fd80afe026a68b58d7451aee',
    'report_41_sha256': '5ebd851bc4918312af897cf3c659c1b683a902add3937825d1357202f4dcaa32',
    'rc_inventory_sha256': '54a6c94314b2050134a70bcaac701f149ab039eb03f54f4b10060f35c0092912',
    'retained_capture_manifest_sha256': 'a1a8cf9bb2b75fd4b76377d229118d2333e7cbf4efa75f9b99422ffa7506fa14',
    'retained_expected_identity_sha256': '5fd6cec66052ee0005ee59f5c2d3f1ea701f7a0ee1da6afb588c342d896179c5',
}


def load_helper(test):
    path = ROOT / 'scripts/rc4-sign-retain.py'
    test.assertTrue(path.is_file(), 'Missing RC4 exact-byte fixture helper')
    spec = importlib.util.spec_from_file_location('rc4_sign_retain', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive(path, entries):
    with tarfile.open(path, 'w:gz') as output:
        for name, value in entries.items():
            raw = value.encode()
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            output.addfile(member, io.BytesIO(raw))


def db_desc(packages):
    entries = {}
    for package in packages:
        values = {
            'NAME': package['package_name'],
            'VERSION': package['version'],
            'FILENAME': package['filename'],
            'CSIZE': str(package['size']),
            'SHA256SUM': package['sha256'],
        }
        entries[package['package_name'] + '-' + package['version'] + '/desc'] = ''.join(
            f'%{key}%\n{value}\n\n' for key, value in values.items())
    return entries


def fixture(root):
    inputs = root / 'inputs'
    inputs.mkdir()
    package_rows = []
    for name, architecture in (('alpha', 'aarch64'), ('beta', 'any')):
        filename = f'{name}-4.0.3rc4-2-{architecture}.pkg.tar.xz'
        path = inputs / filename
        archive(path, {'.PKGINFO': f'pkgname = {name}\npkgver = 4.0.3rc4-2\narch = {architecture}\n'})
        package_rows.append({'asset_id': 100 + len(package_rows), 'filename': filename,
                             'size': path.stat().st_size, 'sha256': sha(path), 'kind': 'package',
                             'package_name': name, 'version': '4.0.3rc4-2',
                             'architecture': architecture})
    db_path = inputs / 'omarchy-aarch64.db'
    archive(db_path, db_desc(package_rows))
    database_rows = []
    for index, filename in enumerate(('omarchy-aarch64.db', 'omarchy-aarch64.db.tar.zst',
                                      'omarchy-aarch64.files', 'omarchy-aarch64.files.tar.zst')):
        path = inputs / filename
        if filename != 'omarchy-aarch64.db':
            path.write_bytes(db_path.read_bytes())
        database_rows.append({'asset_id': 200 + index, 'filename': filename,
                              'size': path.stat().st_size, 'sha256': sha(path),
                              'kind': 'database' if '.db' in filename else 'files'})
    provenance = inputs / 'build-inputs.txt'
    provenance.write_text('fixture-only\n')
    provenance_row = {'asset_id': 300, 'filename': provenance.name, 'size': provenance.stat().st_size,
                      'sha256': sha(provenance), 'kind': 'evidence'}
    identity = {
        'schema': 1,
        'classification': CLASSIFICATION,
        'repository': 'omarchy-mac/omarchy-pkgs-aarch64',
        'repository_id': 1327386148,
        'release_id': 390634001,
        'inputs': package_rows + database_rows + [provenance_row],
        'expected_counts': {'packages': 2, 'database_and_files': 4, 'evidence': 1},
    }
    identity_path = root / 'identity.json'
    identity_path.write_text(json.dumps(identity, indent=2, sort_keys=True) + '\n')
    metadata = {'repository': identity['repository'], 'repository_id': identity['repository_id'],
                'release_id': identity['release_id'], 'assets': [
                    {'id': row['asset_id'], 'name': row['filename'], 'size': row['size'],
                     'digest': 'sha256:' + row['sha256'], 'state': 'uploaded'} for row in identity['inputs']]}
    metadata_path = root / 'metadata.json'
    metadata_path.write_text(json.dumps(metadata))
    return identity, identity_path, metadata_path, inputs


@contextmanager
def synthetic_production(module, identity_path, identity):
    packages = {row['package_name']: row for row in identity['inputs'] if row['kind'] == 'package'}
    core = {name: {field: row[field] for field in ('asset_id', 'filename', 'version', 'sha256')}
            for name, row in packages.items()}
    with ExitStack() as stack:
        stack.enter_context(patch.object(module, 'FROZEN_IDENTITY_SHA256', sha(identity_path)))
        stack.enter_context(patch.object(module, 'PRODUCTION_COUNTS', identity['expected_counts']))
        stack.enter_context(patch.object(module, 'PRODUCTION_CORE', core))
        stack.enter_context(patch.object(module, 'PRIMARY_FINGERPRINT', 'A' * 40))
        stack.enter_context(patch.object(module, 'SIGNING_SUBKEY_FINGERPRINT', 'B' * 40))
        stack.enter_context(patch.object(module, 'PUBLIC_KEY_SHA256', 'C' * 64))
        stack.enter_context(patch.object(module, 'SIGNING_POLICY_SHA256', 'd' * 64))
        yield


def execution_identity(run_id=700, attempt=1):
    return {
        'repository': 'omarchy-mac/omarchy-pkgs-aarch64', 'workflow_run_id': run_id,
        'workflow_run_attempt': attempt, 'workflow_head_sha': '1' * 40,
        'workflow_path': '.github/workflows/sign-and-retain-rc4-fixture.yml',
        'workflow_blob_sha': '2' * 40,
        'helper_blob_shas': {
            'scripts/rc4-sign-retain.py': '3' * 40,
            'scripts/package-signing.py': '4' * 40,
            'scripts/rc4-signing-secret-feeder.py': '7' * 40,
            'pkgbuilds/omarchy-mac-keyring/signing-policy.json': '8' * 40,
            'pkgbuilds/omarchy-mac-keyring/omarchy-mac.gpg': '9' * 40,
        },
        'dockerfile_blob_sha': 'a' * 40,
        'base_image_digest': 'sha256:' + 'b' * 64,
        'signer_image_digest': 'sha256:' + '6' * 64,
    }


class ImmutableInputTests(unittest.TestCase):
    def test_github_request_error_exposes_safe_endpoint_and_status(self):
        module = load_helper(self)
        path = '/repos/omarchy-mac/omarchy-pkgs-aarch64/releases/assets/123'
        markers = ('token-value-must-not-appear', 'server-reason-must-not-appear',
                   'body-marker-must-not-appear', 'https://secret.example/')
        headers = Message()
        headers['X-Secret'] = markers[2]
        error = urllib.error.HTTPError(
            'https://secret.example/' + markers[0], 403, markers[1], headers,
            io.BytesIO(markers[2].encode()))
        with patch.object(module.urllib.request, 'urlopen', side_effect=error):
            with self.assertRaisesRegex(ValueError,
                                         r'^GitHub API request failed: ' +
                                         r'/repos/omarchy-mac/omarchy-pkgs-aarch64/releases/assets/123 '
                                         r'\(HTTPError status=403\)$') as raised:
                module.github_request(path, markers[0])
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        traceback_text = ''.join(traceback.format_exception(raised.exception))
        for marker in markers:
            self.assertNotIn(marker, traceback_text)

    def test_production_identity_is_fixed_rc4_set_not_operator_defined(self):
        module = load_helper(self)
        path = ROOT / 'scripts/rc4-sign-retain-inputs.json'
        identity = module.validate_identity(path, sha(path), production=True)
        self.assertEqual(identity['expected_counts'],
                         {'packages': 52, 'database_and_files': 4, 'evidence': 1})
        core = {row['package_name']: row for row in identity['inputs'] if row['kind'] == 'package'
                and row['package_name'] in ('omarchy', 'omarchy-settings')}
        self.assertEqual(core['omarchy']['asset_id'], 576676265)
        self.assertEqual(core['omarchy']['version'], '4.0.3rc4-2')
        self.assertEqual(core['omarchy-settings']['asset_id'], 576675640)
        self.assertEqual(core['omarchy-settings']['version'], '4.0.3rc4-2')
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            changed = json.loads(path.read_text())
            changed['expected_counts']['packages'] = 1
            changed_path = Path(directory) / 'synthetic-mutated-identity.json'
            changed_path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'production RC4'):
                module.validate_identity(changed_path, sha(changed_path), production=True)

    def test_architecture_is_exact_for_aarch64_and_any_packages(self):
        module = load_helper(self)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            identity, identity_path, metadata_path, inputs = fixture(root)
            module.validate_inputs(identity_path, sha(identity_path), metadata_path, inputs,
                                   root / 'unsigned-input-manifest.json')
            beta = next(row for row in identity['inputs'] if row.get('package_name') == 'beta')
            self.assertEqual(beta['architecture'], 'any')
            beta['architecture'] = 'aarch64'
            identity_path.write_text(json.dumps(identity, indent=2, sort_keys=True) + '\n')
            with self.assertRaisesRegex(ValueError, 'package identity'):
                module.validate_identity(identity_path, sha(identity_path))

    def test_frozen_57_asset_identity_is_exact_and_epoch_versions_are_valid(self):
        module = load_helper(self)
        path = ROOT / 'scripts/rc4-sign-retain-inputs.json'
        identity = module.validate_identity(path, sha(path))
        self.assertEqual(identity['expected_counts'],
                         {'packages': 52, 'database_and_files': 4, 'evidence': 1})
        self.assertEqual(len(identity['inputs']), 57)
        self.assertIn('1:1.95.104-1', {row.get('version') for row in identity['inputs']})
        self.assertEqual(len(module.serving_contract(identity)['served_paths']), 112)

    def test_exact_identity_metadata_bytes_packages_and_database_are_required(self):
        module = load_helper(self)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            identity, identity_path, metadata_path, inputs = fixture(root)
            output = root / 'unsigned-input-manifest.json'
            result = module.validate_inputs(identity_path, sha(identity_path), metadata_path, inputs, output)
            self.assertEqual(result['classification'], CLASSIFICATION)
            self.assertEqual(result['validated_counts'], {'packages': 2, 'database_and_files': 4, 'evidence': 1})
            self.assertEqual(result['served_input_paths'], sorted(
                row['filename'] for row in identity['inputs'] if row['kind'] != 'evidence'))
            self.assertEqual(sha(identity_path), result['immutable_identity_sha256'])
            self.assertNotIn('manifest_sha256', result)
            self.assertEqual(result['cannot_prove'], module.CANNOT_PROVE)
            self.assertEqual(result['provenance_limitations'], module.PROVENANCE_LIMITATIONS)
            expected_evidence = {
                'report_39_sha256': '1632ad43ba98c749cd22a9385870619e8b6580663eb798bb3a15a15e5c270363',
                'report_40_sha256': '64e6f1ee61943ed2cb10945bb285386c3d70a8e9fd80afe026a68b58d7451aee',
                'report_41_sha256': '5ebd851bc4918312af897cf3c659c1b683a902add3937825d1357202f4dcaa32',
                'rc_inventory_sha256': '54a6c94314b2050134a70bcaac701f149ab039eb03f54f4b10060f35c0092912',
                'retained_capture_manifest_sha256': 'a1a8cf9bb2b75fd4b76377d229118d2333e7cbf4efa75f9b99422ffa7506fa14',
                'retained_expected_identity_sha256': '5fd6cec66052ee0005ee59f5c2d3f1ea701f7a0ee1da6afb588c342d896179c5',
            }
            self.assertEqual(module.SOURCE_EVIDENCE_HASHES, expected_evidence)

            # Metadata substitution must fail before trusting downloaded bytes.
            changed = json.loads(metadata_path.read_text())
            changed['assets'][0]['id'] += 1
            metadata_path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'metadata'):
                module.validate_inputs(identity_path, sha(identity_path), metadata_path, inputs, root / 'bad.json')
            metadata_path.write_text(json.dumps({'repository': identity['repository'],
                'repository_id': identity['repository_id'], 'release_id': identity['release_id'],
                'assets': [{'id': row['asset_id'], 'name': row['filename'], 'size': row['size'],
                            'digest': 'sha256:' + row['sha256'], 'state': 'uploaded'}
                           for row in identity['inputs']]}))

            # Extra paths, byte substitution, package metadata drift and DB drift all fail closed.
            (inputs / 'unexpected').write_text('x')
            with self.assertRaisesRegex(ValueError, 'inventory'):
                module.validate_inputs(identity_path, sha(identity_path), metadata_path, inputs, root / 'bad.json')
            (inputs / 'unexpected').unlink()
            package = inputs / identity['inputs'][0]['filename']
            original = package.read_bytes(); package.write_bytes(original + b'x')
            with self.assertRaisesRegex(ValueError, 'bytes'):
                module.validate_inputs(identity_path, sha(identity_path), metadata_path, inputs, root / 'bad.json')
            package.write_bytes(original)
            database = inputs / 'omarchy-aarch64.db'
            original_db = database.read_bytes(); archive(database, {})
            identity['inputs'][2]['size'] = database.stat().st_size
            identity['inputs'][2]['sha256'] = sha(database)
            identity_path.write_text(json.dumps(identity, indent=2, sort_keys=True) + '\n')
            changed = json.loads(metadata_path.read_text())
            changed['assets'][2]['size'] = database.stat().st_size
            changed['assets'][2]['digest'] = 'sha256:' + sha(database)
            metadata_path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'database'):
                module.validate_inputs(identity_path, sha(identity_path), metadata_path, inputs, root / 'bad.json')
            database.write_bytes(original_db)

    def test_acquisition_uses_only_exact_numeric_ids_and_digests(self):
        module = load_helper(self)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            identity, identity_path, _, source = fixture(root)
            payloads = {row['asset_id']: (source / row['filename']).read_bytes() for row in identity['inputs']}
            metadata = [{'id': row['asset_id'], 'name': row['filename'], 'size': row['size'],
                         'digest': 'sha256:' + row['sha256'], 'state': 'uploaded'}
                        for row in identity['inputs']]
            requested = []
            def fetch(asset_id):
                requested.append(asset_id)
                return payloads[asset_id]
            output, metadata_path = root / 'acquired', root / 'acquired-metadata.json'
            module.acquire_assets(identity_path, sha(identity_path), metadata, fetch, output, metadata_path)
            self.assertEqual(requested, [row['asset_id'] for row in identity['inputs']])
            self.assertEqual({path.name for path in output.iterdir()},
                             {row['filename'] for row in identity['inputs']})
            self.assertEqual(json.loads(metadata_path.read_text())['release_id'], 390634001)
            bad = dict(payloads); bad[identity['inputs'][0]['asset_id']] += b'tamper'
            with self.assertRaisesRegex(ValueError, 'downloaded bytes'):
                module.acquire_assets(identity_path, sha(identity_path), metadata,
                                      lambda asset_id: bad[asset_id], root / 'bad', root / 'bad-metadata.json')
            self.assertFalse((root / 'bad').exists())
            changed = list(metadata); changed[0] = dict(changed[0], id=999)
            with self.assertRaisesRegex(ValueError, 'metadata'):
                module.acquire_assets(identity_path, sha(identity_path), changed, fetch,
                                      root / 'never', root / 'never.json')
            self.assertFalse((root / 'never').exists())

    def test_package_zstd_native_boundary_is_faked_and_paths_fail_closed(self):
        module = load_helper(self)
        pkginfo = 'pkgname = alpha\npkgver = 4.0.3rc4-2\narch = any\n'
        class Result:
            returncode = 0
            stderr = b''
            def __init__(self, stdout): self.stdout = stdout
        def fake_run(command, stdout=None, stderr=None, check=False, **kwargs):
            if command[1] == '-tf': return Result(b'.PKGINFO\nusr/\n')
            if command[1] == '-xOf': return Result(pkginfo.encode())
            raise AssertionError(command)
        with patch.object(module.tarfile, 'open', side_effect=tarfile.ReadError('zstd')), \
                patch.object(module.subprocess, 'run', side_effect=fake_run):
            info = module.read_package_info(Path('/fixture/alpha-4.0.3rc4-2-any.pkg.tar.zst'))
        self.assertEqual(info, {'pkgname': ['alpha'], 'pkgver': ['4.0.3rc4-2'], 'arch': ['any']})
        with patch.object(module.tarfile, 'open', side_effect=tarfile.ReadError('zstd')), \
                patch.object(module.subprocess, 'run', return_value=Result(b'../.PKGINFO\n')):
            with self.assertRaisesRegex(ValueError, 'member path'):
                module.read_package_info(Path('/fixture/alpha.pkg.tar.zst'))

    def test_database_zstd_native_boundary_is_faked_and_paths_fail_closed(self):
        from unittest.mock import patch
        module = load_helper(self)
        desc = ('%NAME%\nalpha\n\n%VERSION%\n4.0.3rc4-2\n\n'
                '%FILENAME%\nalpha.pkg.tar.xz\n\n%CSIZE%\n10\n\n%SHA256SUM%\n' + 'a' * 64 + '\n\n')
        class Result:
            returncode = 0
            stderr = b''
            def __init__(self, stdout): self.stdout = stdout
        def fake_run(command, stdout=None, stderr=None, check=False, **kwargs):
            if command[1] == '-tf': return Result(b'alpha-4.0.3rc4-2/desc\n')
            if command[1] == '-xOf': return Result(desc.encode())
            raise AssertionError(command)
        with patch.object(module.tarfile, 'open', side_effect=tarfile.ReadError('zstd')), \
                patch.object(module.subprocess, 'run', side_effect=fake_run):
            records = module.read_database(Path('/fixture/omarchy-aarch64.db'))
        self.assertEqual(records['alpha']['SHA256SUM'], 'a' * 64)
        with patch.object(module.tarfile, 'open', side_effect=tarfile.ReadError('zstd')), \
                patch.object(module.subprocess, 'run', return_value=Result(b'../desc\n')):
            with self.assertRaisesRegex(ValueError, 'member path'):
                module.read_database(Path('/fixture/omarchy-aarch64.db'))


class CandidateBoundaryTests(unittest.TestCase):
    def test_transport_digest_formats_are_normalized_and_mismatches_fail(self):
        module = load_helper(self)
        metadata = {'id': 900, 'name': 'fixture', 'size_in_bytes': 1234,
                    'digest': 'sha256:' + 'a' * 64, 'expired': False,
                    'created_at': '2026-09-21T00:00:00Z'}
        result = module.validate_artifact_transport(metadata, 900, 'a' * 64)
        self.assertEqual(result['artifact_zip_sha256'], 'a' * 64)
        self.assertEqual(result['size_in_bytes'], 1234)
        self.assertEqual(result['artifact_name'], 'fixture')
        self.assertEqual(result['created_at'], '2026-09-21T00:00:00Z')
        changed = dict(metadata, name='other')
        with self.assertRaisesRegex(ValueError, 'name'):
            module.validate_artifact_transport(changed, 900, 'a' * 64, expected_name='fixture')
        for field, value in [('id', True), ('id', 900.0), ('size_in_bytes', True),
                             ('created_at', None), ('created_at', '2026-02-30T00:00:00Z'),
                             ('created_at', '2026-09-21T00:00:00+02:00')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                module.validate_artifact_transport(dict(metadata, **{field: value}), 900, 'a' * 64)
        changed = dict(metadata, expired=True)
        with self.assertRaisesRegex(ValueError, 'identity'):
            module.validate_artifact_transport(changed, 900, 'a' * 64)
        with self.assertRaisesRegex(ValueError, 'digest'):
            module.validate_artifact_transport(metadata, 900, 'b' * 64)
        with self.assertRaisesRegex(ValueError, 'identity'):
            module.validate_artifact_transport(metadata, 901, 'a' * 64)

    def test_allowlist_signatures_manifest_and_receipt_are_non_circular(self):
        module = load_helper(self)
        production_path = ROOT / 'scripts/rc4-sign-retain-inputs.json'
        self.assertTrue(production_path.is_file(), 'Missing frozen RC4 immutable-input identity')
        production = json.loads(production_path.read_text())
        production_contract = module.serving_contract(production)
        self.assertEqual(production['expected_counts'], {'packages': 52, 'database_and_files': 4, 'evidence': 1})
        self.assertEqual(len(production_contract['served_paths']), 112)
        self.assertEqual(len(production_contract['signature_paths']), 56)
        self.assertNotIn('build-inputs.txt', production_contract['served_paths'])
        self.assertTrue(all(path.endswith('.sig') for path in production_contract['signature_paths']))

        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            identity, identity_path, metadata_path, inputs = fixture(root)
            unsigned = root / 'unsigned-input-manifest.json'
            module.validate_inputs(identity_path, sha(identity_path), metadata_path, inputs, unsigned)
            candidate = root / 'candidate'
            repository = candidate / 'repository'; repository.mkdir(parents=True)
            evidence = candidate / 'evidence'; evidence.mkdir()
            contract = module.serving_contract(identity)
            for name in contract['input_paths']:
                (repository / name).write_bytes((inputs / name).read_bytes())
                (repository / (name + '.sig')).write_bytes(('fixture-signature:' + name).encode())
            (evidence / 'build-inputs.txt').write_bytes((inputs / 'build-inputs.txt').read_bytes())
            (evidence / unsigned.name).write_bytes(unsigned.read_bytes())
            verified = []
            def fake_verify(path, signature):
                verified.append((path.name, signature.name))
                self.assertEqual(signature.name, path.name + '.sig')
                return {'primary_fingerprint': 'A' * 40, 'signing_subkey_fingerprint': 'B' * 40}
            execution = execution_identity()
            manifest_path = candidate / 'candidate-manifest.json'
            with synthetic_production(module, identity_path, identity):
                manifest = module.write_candidate_manifest(identity_path, sha(identity_path), unsigned,
                                                             candidate, execution, fake_verify, manifest_path)
            self.assertEqual(len(verified), 6)
            self.assertEqual(len(manifest['served_path_allowlist']), 12)
            self.assertEqual(len(manifest['signature_outputs']), 6)
            self.assertEqual(manifest['classification'], CLASSIFICATION)
            self.assertEqual(set(manifest), {
                'schema', 'classification', 'repository', 'workflow_run_id',
                'workflow_run_attempt', 'workflow_head_sha', 'workflow_path',
                'workflow_blob_sha', 'helper_blob_shas', 'dockerfile_blob_sha',
                'base_image_digest', 'source_evidence_hashes', 'input_release_id',
                'input_assets', 'input_manifest_sha256', 'signing_policy',
                'signature_outputs', 'served_path_allowlist', 'evidence_only_paths',
                'output_inventory', 'qualification_approved', 'publication_approved',
            })
            self.assertEqual(manifest['workflow_run_id'], execution['workflow_run_id'])
            self.assertEqual(manifest['source_evidence_hashes'], module.SOURCE_EVIDENCE_HASHES)
            self.assertEqual(manifest['source_evidence_hashes'], EXPECTED_SOURCE_EVIDENCE)
            self.assertEqual(manifest['base_image_digest'], execution['base_image_digest'])
            self.assertEqual(manifest['input_manifest_sha256'], sha(unsigned))
            self.assertEqual(manifest['signing_policy']['signer_image_digest'],
                             execution['signer_image_digest'])
            self.assertFalse(manifest['qualification_approved'])
            self.assertFalse(manifest['publication_approved'])
            for forbidden in ('manifest_sha256', 'candidate_manifest_sha256', 'artifact_id',
                              'artifact_url', 'artifact_size', 'artifact_zip_sha256'):
                self.assertNotIn(forbidden, manifest)
            self.assertNotIn('candidate-manifest.json', manifest['output_inventory'])
            self.assertEqual(manifest['evidence_only_paths'],
                             ['evidence/build-inputs.txt', 'evidence/unsigned-input-manifest.json'])

            receipt_path = root / 'transport-receipt.json'
            with synthetic_production(module, identity_path, identity):
                receipt = module.write_transport_receipt(manifest_path, {
                    'repository_id': 1327386148, 'repository': 'omarchy-mac/omarchy-pkgs-aarch64',
                    'workflow_run_id': 700, 'workflow_run_attempt': 1, 'head_sha': '1' * 40,
                    'workflow_path': execution['workflow_path'], 'workflow_blob_sha': '2' * 40,
                    'artifact_id': 900, 'artifact_name': 'signed-rc4-exact-byte-qualification-fixture-700-1',
                    'size_in_bytes': 1234, 'artifact_zip_sha256': '7' * 64,
                    'created_at': '2026-09-21T00:00:00Z',
                }, receipt_path)
            self.assertEqual(receipt['candidate_manifest_sha256'], sha(manifest_path))
            self.assertEqual(set(receipt), {
                'schema', 'repository_id', 'repository', 'workflow_run_id',
                'workflow_run_attempt', 'head_sha', 'workflow_path', 'workflow_blob_sha',
                'artifact_id', 'artifact_name', 'size_in_bytes', 'artifact_zip_sha256',
                'candidate_manifest_sha256', 'created_at',
            })
            self.assertEqual(receipt['created_at'], '2026-09-21T00:00:00Z')
            self.assertNotIn('classification', receipt)
            self.assertNotIn('transport_receipt_sha256', receipt)
            self.assertNotIn('receipt_sha256', receipt)
            self.assertNotIn('transport-receipt.json', manifest['output_inventory'])

            # The retained candidate must be revalidated from disk, not only from its manifest.
            with synthetic_production(module, identity_path, identity):
                checked = module.validate_candidate_directory(candidate, manifest_path, fake_verify)
            self.assertEqual(checked['classification'], CLASSIFICATION)
            first_input = candidate / next(iter(manifest['output_inventory']))
            original = first_input.read_bytes()
            first_input.write_bytes(original + b'tamper')
            with synthetic_production(module, identity_path, identity):
                with self.assertRaisesRegex(ValueError, 'Candidate output bytes differ'):
                    module.validate_candidate_directory(candidate, manifest_path, fake_verify)
            first_input.write_bytes(original)

            mutations = []
            changed = copy.deepcopy(manifest); changed['input_assets'][0]['size'] += 1
            mutations.append(changed)
            changed = copy.deepcopy(manifest); changed['served_path_allowlist'].pop()
            mutations.append(changed)
            changed = copy.deepcopy(manifest); changed['signature_outputs'][0]['primary_fingerprint'] = 'E' * 40
            mutations.append(changed)
            changed = copy.deepcopy(manifest)
            changed['output_inventory']['repository/' + changed['signature_outputs'][0]['filename']]['sha256'] = 'f' * 64
            mutations.append(changed)
            changed = copy.deepcopy(manifest); changed['signing_policy']['public_key_sha256'] = 'e' * 64
            mutations.append(changed)
            changed = copy.deepcopy(manifest); changed['source_evidence_hashes']['report_39_sha256'] = '0' * 64
            mutations.append(changed)
            for evidence_name in EXPECTED_SOURCE_EVIDENCE:
                changed = copy.deepcopy(manifest)
                changed['source_evidence_hashes'].pop(evidence_name)
                mutations.append(changed)
                changed = copy.deepcopy(manifest)
                changed['source_evidence_hashes'][evidence_name] = '0' * 64
                mutations.append(changed)
            with synthetic_production(module, identity_path, identity):
                for changed in mutations:
                    with self.subTest(field=set(manifest) - set(changed)):
                        with self.assertRaises(ValueError):
                            module.validate_candidate_manifest(changed)

            # Extra repository content and circular/post-upload fields fail closed.
            (repository / 'extra').write_text('x')
            with synthetic_production(module, identity_path, identity):
                with self.assertRaisesRegex(ValueError, 'repository inventory'):
                    module.write_candidate_manifest(identity_path, sha(identity_path), unsigned,
                                                    candidate, execution, fake_verify, root / 'bad.json')
            (repository / 'extra').unlink()
            changed = json.loads(manifest_path.read_text()); changed['artifact_id'] = 900
            manifest_path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'candidate manifest'):
                module.write_transport_receipt(manifest_path, {
                    'repository_id': 1327386148, 'repository': 'omarchy-mac/omarchy-pkgs-aarch64',
                    'workflow_run_id': 700, 'workflow_run_attempt': 1, 'head_sha': '1' * 40,
                    'workflow_path': execution['workflow_path'], 'workflow_blob_sha': '2' * 40,
                    'artifact_id': 901, 'artifact_name': 'signed-rc4-exact-byte-qualification-fixture-700-1',
                    'size_in_bytes': 1234, 'artifact_zip_sha256': '7' * 64,
                    'created_at': '2026-09-21T00:00:00Z',
                }, root / 'bad-receipt.json')


class WorkflowContractTests(unittest.TestCase):
    def test_cli_exposes_only_nonpublishing_commands(self):
        import subprocess
        import sys
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/rc4-sign-retain.py'), '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        for command in ('acquire', 'validate-inputs', 'preflight-signing', 'validate-candidate',
                        'validate-artifact-transport', 'sign-candidate', 'write-receipt'):
            self.assertIn(command, result.stdout)
        for forbidden in ('publish', 'promote', 'release-write'):
            self.assertNotRegex(result.stdout, rf'(?m)^\s+{re.escape(forbidden)}\s')

    def test_nonpublishing_protected_workflow_contract_is_fail_closed(self):
        import subprocess
        path = ROOT / '.github/workflows/sign-and-retain-rc4-fixture.yml'
        self.assertTrue(path.is_file(), 'Missing nonpublishing RC4 sign-and-retain workflow')
        text = path.read_text()
        workflow = yaml.safe_load(text)
        trigger = workflow.get('on', workflow.get(True))
        self.assertEqual(set(trigger), {'workflow_dispatch'})
        inputs = trigger['workflow_dispatch']['inputs']
        self.assertEqual(set(inputs), {'immutable_inputs_sha256', 'reviewed_head_sha',
                                      'workflow_blob_sha', 'helper_blob_sha', 'signer_blob_sha',
                                      'feeder_blob_sha', 'policy_blob_sha', 'public_key_blob_sha',
                                      'image_provenance', 'signer_image_digest'})
        self.assertLessEqual(len(inputs), 10)
        self.assertTrue(all(value.get('required') is True and value.get('type') == 'string' and
                            'default' not in value for value in inputs.values()))
        readonly = {'contents': 'read', 'actions': 'read'}
        signer_readonly = {**readonly, 'packages': 'read'}
        self.assertEqual(workflow['permissions'], readonly)
        self.assertEqual(workflow['concurrency'], {'group': 'rc4-sign-and-retain-fixture',
                                                   'cancel-in-progress': False})
        self.assertEqual(set(workflow['jobs']), {'verify-inputs', 'sign-and-retain'})
        verify, sign = workflow['jobs']['verify-inputs'], workflow['jobs']['sign-and-retain']
        self.assertNotIn('environment', verify)
        self.assertEqual(sign['environment'], 'package-signing')
        self.assertEqual(verify['permissions'], readonly)
        self.assertEqual(sign['permissions'], signer_readonly)
        self.assertEqual(sign['needs'], 'verify-inputs')
        self.assertEqual(verify['if'], "github.repository == 'omarchy-mac/omarchy-pkgs-aarch64'")
        self.assertEqual(sign['if'], "github.repository == 'omarchy-mac/omarchy-pkgs-aarch64'")
        for job in (verify, sign):
            checkout = next(step for step in job['steps'] if str(step.get('uses', '')).startswith('actions/checkout@'))
            self.assertEqual(checkout['with']['ref'], '${{ inputs.reviewed_head_sha }}')
            self.assertFalse(checkout['with']['persist-credentials'])
        for forbidden in ('contents: write', 'actions: write', 'id-token: write', 'packages: write',
                          'gh release', 'release upload', 'releases/assets', 'softprops/action-gh-release'):
            self.assertNotIn(forbidden, text)
        self.assertIn(CLASSIFICATION, text)
        self.assertNotIn('RC5', text)
        self.assertNotIn('docker build', text)
        self.assertNotIn('publisher.Dockerfile', text)
        self.assertNotIn('pacman -', text)
        dockerfile = (ROOT / '.github/rc4-fixture-signer.Dockerfile').read_text()
        self.assertIn('FROM ${BASE_IMAGE}', dockerfile)
        self.assertIn('org.omarchy.rc4.dockerfile-blob-sha', dockerfile)
        self.assertIn('org.omarchy.rc4.base-image-digest', dockerfile)
        self.assertIn('apt-get install -y --no-install-recommends libarchive-tools', dockerfile)
        self.assertNotIn('pacman', dockerfile)
        self.assertNotIn('curl', dockerfile)
        feeder_text = (ROOT / 'scripts/rc4-signing-secret-feeder.py').read_text()
        self.assertIn("str(docker_path), 'run', '-i', '--rm', '--network', 'none'", feeder_text)
        self.assertIn('ghcr.io/omarchy-mac/omarchy-pkgs-aarch64/rc4-fixture-signer@', feeder_text)
        self.assertIn('[[ "$GITHUB_SHA" == "$INPUT_REVIEWED_HEAD_SHA" ]]', text)
        self.assertIn('[[ "$(git rev-parse HEAD)" == "$INPUT_REVIEWED_HEAD_SHA" ]]', text)
        self.assertNotIn('-e PACMAN_SIGNING_SUBKEY', text)
        self.assertNotIn('-e PACMAN_SIGNING_PASSPHRASE', text)
        self.assertNotIn('-e RC4_SIGNING_SUBKEY', text)
        self.assertNotIn('-e RC4_SIGNING_PASSPHRASE', text)
        self.assertNotIn('rc4-signing-secret-feeder.py |', text)
        self.assertNotIn('env -u RC4_SIGNING_SUBKEY_B64', text)
        self.assertIn('runpy.run_path', text)
        self.assertIn("'scripts/rc4-sign-retain.py', 'sign-candidate'", feeder_text)

        initial_identity = next(step for step in verify['steps']
                                if step.get('name') == 'Validate reviewed executable and immutable identities')
        self.assertEqual(initial_identity['env']['OBSERVED_REPOSITORY_ID'], '${{ github.repository_id }}')
        repository_name_guard = ('[[ "$GITHUB_REPOSITORY" == '
                                 'omarchy-mac/omarchy-pkgs-aarch64 ]] || exit 1')
        repository_id_guard = '[[ "$OBSERVED_REPOSITORY_ID" == 1327386148 ]] || exit 1'
        run_attempt_guard = '[[ "$GITHUB_RUN_ATTEMPT" == 1 ]] || exit 1'
        self.assertIn(repository_name_guard, initial_identity['run'])
        self.assertIn(repository_id_guard, initial_identity['run'])
        self.assertIn(run_attempt_guard, initial_identity['run'])
        initial_lines = initial_identity['run'].splitlines()
        initial_guard = '\n'.join(initial_lines[:initial_lines.index(run_attempt_guard) + 1]) + \
            '\nprintf GUARD_CALLBACK'
        base_guard_environment = dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch',
                                      GITHUB_REPOSITORY='omarchy-mac/omarchy-pkgs-aarch64',
                                      OBSERVED_REPOSITORY_ID='1327386148', GITHUB_RUN_ATTEMPT='1')
        for changed in ({}, {'GITHUB_REPOSITORY': 'wrong/repository'},
                        {'OBSERVED_REPOSITORY_ID': '0'}, {'GITHUB_RUN_ATTEMPT': '2'}):
            result = subprocess.run(
                ['/bin/bash', '--noprofile', '--norc', '-e', '-u', '-o', 'pipefail', '-c',
                 initial_guard],
                capture_output=True, text=True, env=dict(base_guard_environment, **changed))
            self.assertEqual('GUARD_CALLBACK' in result.stdout, not changed)

        verify_names = [step.get('name') for step in verify['steps']]
        tools = next((step for step in verify['steps']
                      if step.get('name') == 'Install input validation tools'), None)
        self.assertIsNotNone(tools, 'Input validation requires bsdtar')
        assert tools is not None
        self.assertIn('sudo apt-get install -y --no-install-recommends libarchive-tools', tools['run'])
        self.assertIn('bsdtar --version', tools['run'])
        self.assertLess(verify_names.index('Install input validation tools'),
                        verify_names.index('Validate exact immutable inputs without credentials'))
        sign_names = [step.get('name') for step in sign['steps']]
        protected_tools = next((step for step in sign['steps']
                                if step.get('name') == 'Install input validation tools'), None)
        self.assertIsNotNone(protected_tools, 'Protected revalidation also requires bsdtar')
        assert protected_tools is not None
        self.assertEqual(protected_tools['run'], tools['run'])
        self.assertLess(sign_names.index('Install input validation tools'),
                        sign_names.index('Revalidate exact eligibility before protected secrets'))
        self.assertIn('Authenticate private GHCR pull', sign_names)
        self.assertIn('Remove private GHCR credentials before protected secrets', sign_names)
        login_step = next(step for step in sign['steps'] if step.get('name') == 'Authenticate private GHCR pull')
        self.assertEqual(login_step['env']['GHCR_TOKEN'], '${{ github.token }}')
        self.assertEqual(login_step['env']['GHCR_USERNAME'], '${{ github.actor }}')
        self.assertIn('docker login ghcr.io', login_step['run'])
        self.assertIn('--password-stdin', login_step['run'])
        logout_step = next(step for step in sign['steps']
                           if step.get('name') == 'Remove private GHCR credentials before protected secrets')
        self.assertEqual(logout_step['if'], '${{ always() }}')
        self.assertEqual(logout_step['run'].strip(), 'docker logout ghcr.io')
        self.assertLess(sign_names.index('Authenticate private GHCR pull'),
                        sign_names.index('Revalidate exact eligibility before protected secrets'))
        self.assertLess(sign_names.index('Revalidate exact eligibility before protected secrets'),
                        sign_names.index('Remove private GHCR credentials before protected secrets'))
        self.assertLess(sign_names.index('Remove private GHCR credentials before protected secrets'),
                        sign_names.index('Isolated signing process receives secret only on stdin'))
        self.assertLess(verify_names.index('Acquire exact numeric release assets'),
                        verify_names.index('Validate exact immutable inputs without credentials'))
        self.assertLess(sign_names.index('Recover exact verified unsigned inputs'),
                        sign_names.index('Verify exact retained-input artifact transport before protected secrets'))
        self.assertLess(sign_names.index('Verify exact retained-input artifact transport before protected secrets'),
                        sign_names.index('Revalidate exact eligibility before protected secrets'))
        self.assertLess(sign_names.index('Revalidate exact eligibility before protected secrets'),
                        sign_names.index('Isolated signing process receives secret only on stdin'))
        self.assertLess(sign_names.index('Isolated signing process receives secret only on stdin'),
                        sign_names.index('Freeze candidate manifest SHA-256 before upload'))
        self.assertLess(sign_names.index('Freeze candidate manifest SHA-256 before upload'),
                        sign_names.index('Retain frozen candidate without publication capability'))
        self.assertLess(sign_names.index('Retain frozen candidate without publication capability'),
                        sign_names.index('Revalidate frozen candidate after upload'))
        self.assertLess(sign_names.index('Revalidate frozen candidate after upload'),
                        sign_names.index('Write separate post-upload transport receipt'))
        self.assertLess(sign_names.index('Write separate post-upload transport receipt'),
                        sign_names.index('Retain separate transport receipt'))
        secret_steps = [step for step in sign['steps'] if 'secrets.' in str(step)]
        self.assertEqual(len(secret_steps), 1)
        secret_step = secret_steps[0]
        self.assertEqual(secret_step['name'], 'Isolated signing process receives secret only on stdin')
        secret_env = {key: value for key, value in secret_step['env'].items() if 'secrets.' in value}
        self.assertEqual(set(secret_env), {'RC4_SIGNING_SUBKEY_B64', 'RC4_SIGNING_PASSPHRASE'})
        self.assertNotIn('secrets.', secret_step['run'])
        self.assertNotIn('upload-artifact', str(secret_step))
        self.assertNotIn('download-artifact', str(secret_step))
        self.assertEqual(secret_step['shell'], 'python {0}')
        self.assertNotIn('sudo', secret_step['run'])
        self.assertNotIn('secrets.', secret_step['run'])
        self.assertNotIn('docker run', secret_step['run'])
        self.assertIn('runpy.run_path', secret_step['run'])
        self.assertEqual(secret_step['env']['OBSERVED_REPOSITORY_ID'], '${{ github.repository_id }}')
        self.assertEqual(secret_step['env']['EXPECTED_REPOSITORY_ID'], '1327386148')
        input_transport = next(step for step in sign['steps']
                               if step.get('name') ==
                               'Verify exact retained-input artifact transport before protected secrets')
        self.assertEqual(input_transport['env']['INPUT_ARTIFACT_ID'],
                         '${{ needs.verify-inputs.outputs.artifact-id }}')
        self.assertEqual(input_transport['env']['EXPECTED_INPUT_ARTIFACT_DIGEST'],
                         '${{ needs.verify-inputs.outputs.artifact-digest }}')
        self.assertEqual(input_transport['env']['GH_TOKEN'], '${{ github.token }}')
        self.assertIn('validate-artifact-transport', input_transport['run'])
        preflight = next(step for step in sign['steps']
                         if step.get('name') == 'Revalidate exact eligibility before protected secrets')
        self.assertIn('signing-policy.json', preflight['run'])
        self.assertIn('omarchy-mac.gpg', preflight['run'])
        self.assertEqual(preflight['env']['OBSERVED_REPOSITORY_ID'], '${{ github.repository_id }}')
        self.assertIn(repository_name_guard, preflight['run'])
        self.assertIn(repository_id_guard, preflight['run'])
        self.assertIn(run_attempt_guard, preflight['run'])
        preflight_lines = preflight['run'].splitlines()
        preflight_guard = '\n'.join(
            preflight_lines[:preflight_lines.index(run_attempt_guard) + 1]) + \
            '\nprintf GUARD_CALLBACK'
        for changed in ({}, {'GITHUB_REPOSITORY': 'wrong/repository'},
                        {'OBSERVED_REPOSITORY_ID': '0'}, {'GITHUB_RUN_ATTEMPT': '2'}):
            result = subprocess.run(
                ['/bin/bash', '--noprofile', '--norc', '-e', '-u', '-o', 'pipefail', '-c',
                 preflight_guard],
                capture_output=True, text=True, env=dict(base_guard_environment, **changed))
            self.assertEqual('GUARD_CALLBACK' in result.stdout, not changed)
        self.assertIn('preflight-signing', preflight['run'])
        self.assertIn('rc4-fixture-signer.Dockerfile', preflight['run'])
        self.assertIn('org.omarchy.rc4.dockerfile-blob-sha', preflight['run'])
        self.assertIn('org.omarchy.rc4.base-image-digest', preflight['run'])
        self.assertIn('docker pull', preflight['run'])
        self.assertLess(preflight['run'].index('docker pull'), preflight['run'].index('docker image inspect'))
        feeder_text = (ROOT / 'scripts/rc4-signing-secret-feeder.py').read_text()
        self.assertIn("'--pull', 'never'", feeder_text)
        self.assertIn("'--network', 'none'", feeder_text)
        self.assertEqual(secret_step['env']['INPUT_DOCKERFILE_BLOB_SHA'],
                         '${{ fromJSON(inputs.image_provenance).dockerfile_blob_sha }}')
        self.assertEqual(secret_step['env']['INPUT_BASE_IMAGE_DIGEST'],
                         '${{ fromJSON(inputs.image_provenance).base_image_digest }}')
        self.assertIn('INPUT_DOCKERFILE_BLOB_SHA', feeder_text)
        self.assertIn('INPUT_BASE_IMAGE_DIGEST', feeder_text)
        self.assertIn('-v "$RUNNER_TEMP/rc4-sign/preflight-tmp:/task/tmp"', preflight['run'])
        self.assertIn('-e TMPDIR=/task/tmp', preflight['run'])
        candidate_upload = next(step for step in sign['steps']
                                if step.get('name') == 'Retain frozen candidate without publication capability')
        self.assertRegex(candidate_upload['uses'], r'^actions/upload-artifact@[a-f0-9]{40}$')
        self.assertIn('candidate-manifest.json', candidate_upload['with']['path'])
        post_upload = next(step for step in sign['steps']
                           if step.get('name') == 'Revalidate frozen candidate after upload')
        self.assertIn('rc4-sign-retain.py validate-candidate', post_upload['run'])
        self.assertIn('docker run --rm --network none', post_upload['run'])
        self.assertNotIn('secrets.', str(post_upload))
        receipt = next(step for step in sign['steps']
                       if step.get('name') == 'Write separate post-upload transport receipt')
        self.assertIn('candidate_manifest_sha256', receipt['run'])
        self.assertIn('[[ "$candidate_manifest_sha256" == "$PRE_UPLOAD_CANDIDATE_MANIFEST_SHA256" ]]',
                      receipt['run'])
        self.assertEqual(receipt['env']['PRE_UPLOAD_CANDIDATE_MANIFEST_SHA256'],
                         '${{ steps.candidate-identity.outputs.sha256 }}')
        self.assertEqual(receipt['env']['CANDIDATE_ARTIFACT_DIGEST'],
                         '${{ steps.candidate.outputs.artifact-digest }}')
        self.assertIn('--expected-artifact-digest "$CANDIDATE_ARTIFACT_DIGEST"', receipt['run'])
        self.assertIn('validate-artifact-transport', receipt['run'])
        self.assertIn('--expected-name "$expected_artifact_name"', receipt['run'])
        self.assertIn('--created-at "$artifact_created_at"', receipt['run'])
        self.assertNotIn('transport-receipt.json', candidate_upload['with']['path'])
        for job in (verify, sign):
            for step in job['steps']:
                if 'uses' in step:
                    self.assertRegex(step['uses'], r'^[^@]+@[a-f0-9]{40}$')
                if 'run' in step:
                    if step.get('shell') == 'python {0}':
                        compile(step['run'], '<workflow-python-step>', 'exec')
                    else:
                        subprocess.run(['bash', '-n'], input=step['run'], text=True, check=True)
        ci = yaml.safe_load((ROOT / '.github/workflows/test.yml').read_text())
        commands = '\n'.join(step.get('run', '') for step in ci['jobs']['self-tests']['steps'])
        self.assertIn('PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-rc4-sign-retain.py -v', commands)


class SecretBoundaryTests(unittest.TestCase):
    def test_presecret_subprocesses_cannot_inherit_protected_stdin(self):
        import subprocess
        module = load_helper(self)
        signing_path = ROOT / 'scripts/package-signing.py'
        spec = importlib.util.spec_from_file_location('package_signing_stdin', signing_path)
        assert spec is not None and spec.loader is not None
        signing = importlib.util.module_from_spec(spec); spec.loader.exec_module(signing)

        class Result:
            returncode = 0
            stderr = b''
            def __init__(self, stdout=b''): self.stdout = stdout

        native_calls = []
        def fake_native(command, **kwargs):
            native_calls.append((command, kwargs))
            if command[1] == '-tf':
                return Result(b'.PKGINFO\n')
            return Result(b'pkgname = alpha\npkgver = 1-1\narch = aarch64\n')
        with patch.object(module.subprocess, 'run', side_effect=fake_native):
            module.read_package_info_native(Path('/fixture/alpha.pkg.tar.zst'))
        self.assertTrue(native_calls)
        self.assertTrue(all(kwargs.get('stdin') is subprocess.DEVNULL
                            for _, kwargs in native_calls))

        child_calls = []
        def fake_child(*args, **kwargs):
            child_calls.append(kwargs)
            return Result()
        with patch.object(signing.subprocess, 'run', side_effect=fake_child):
            signing.run('gpg', '--version', check=False)
            signing.run('gpg', '--import', data=b'fixture-secret')
        self.assertIs(child_calls[0].get('stdin'), subprocess.DEVNULL)
        self.assertNotIn('input', child_calls[0])
        self.assertEqual(child_calls[1].get('input'), b'fixture-secret')
        self.assertNotIn('stdin', child_calls[1])

    def test_public_policy_and_toolchain_preflight_is_exact_without_secret(self):
        signing_path = ROOT / 'scripts/package-signing.py'
        spec = importlib.util.spec_from_file_location('package_signing_preflight', signing_path)
        assert spec is not None and spec.loader is not None
        signing = importlib.util.module_from_spec(spec); spec.loader.exec_module(signing)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            public = root / 'public.gpg'; public.write_bytes(b'public fixture')
            policy_path = root / 'policy.json'; policy_path.write_text(json.dumps({
                'primary_fingerprint': 'A' * 40,
                'signing_subkey_fingerprint': 'B' * 40,
                'public_key_sha256': sha(public),
                'trusted_primary_fingerprints': ['A' * 40],
            }, indent=2, sort_keys=True) + '\n')
            expected_policy_sha256 = sha(policy_path)
            events = []
            class FakeRing:
                def __init__(self, public_arg, policy_arg, secret=False):
                    events.append(('ring', Path(public_arg), Path(policy_arg), secret))
                    self.policy = signing.policy(policy_arg)
                def close(self): events.append(('close',))
            class Result:
                returncode = 0
                stdout = b'tool 1.0\n'
                stderr = b''
            with patch.object(signing, 'Keyring', FakeRing), \
                    patch.object(signing.shutil, 'which', side_effect=lambda name: '/usr/bin/' + name), \
                    patch.object(signing, 'run', side_effect=lambda *args, **kwargs: Result()):
                result = signing.preflight(
                    public, policy_path, sha(public), expected_policy_sha256, 'A' * 40, 'B' * 40)
            self.assertEqual(result['public_key_sha256'], sha(public))
            self.assertEqual(result['signing_policy_sha256'], expected_policy_sha256)
            self.assertEqual(events[0][-1], False)
            changed = json.loads(policy_path.read_text()); changed['primary_fingerprint'] = 'E' * 40
            policy_path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'policy'):
                signing.preflight(public, policy_path, sha(public), expected_policy_sha256,
                                  'A' * 40, 'B' * 40)

    def test_presecret_eligibility_and_stdin_only_secret_lifecycle(self):
        import io
        import struct
        module = load_helper(self)
        feeder_path = ROOT / 'scripts/rc4-signing-secret-feeder.py'
        self.assertTrue(feeder_path.is_file(), 'Missing stdin-only signing secret feeder')
        spec = importlib.util.spec_from_file_location('rc4_secret_feeder', feeder_path)
        assert spec is not None and spec.loader is not None
        feeder = importlib.util.module_from_spec(spec); spec.loader.exec_module(feeder)
        environment = {'RC4_SIGNING_SUBKEY_B64': 'a2V5LWJ5dGVz',
                       'RC4_SIGNING_PASSPHRASE': 'fixture passphrase'}
        wire = io.BytesIO()
        feeder.write_frame_from_environment(environment, wire)
        self.assertEqual(environment, {})
        events, captured = [], []
        def eligibility():
            events.append('eligibility')
            return 'validated-inputs'
        def fake_sign(validated, key, passphrase):
            events.append('sign')
            self.assertEqual(validated, 'validated-inputs')
            self.assertEqual(bytes(key), b'key-bytes')
            self.assertEqual(bytes(passphrase), b'fixture passphrase')
            self.assertFalse(module.SECRET_ENV & set(os.environ))
            captured.extend((key, passphrase))
            return 'signed'
        old = {key: os.environ.pop(key) for key in module.SECRET_ENV if key in os.environ}
        try:
            wire.seek(0)
            self.assertEqual(module.with_signing_secret(wire, eligibility, fake_sign), 'signed')
        finally:
            os.environ.update(old)
        self.assertEqual(events, ['eligibility', 'sign'])
        self.assertTrue(all(not any(secret) for secret in captured), 'In-memory secret buffers were not zeroed')

        child = {}
        class FakeProcess:
            def __init__(self, argv, **kwargs):
                child['argv'] = argv
                child['kwargs'] = kwargs
                self.stdin_fd = kwargs['stdin']
                self.child_stdin_fd = os.dup(self.stdin_fd)
                self.returncode = None
            def wait(self):
                chunks = []
                try:
                    while True:
                        chunk = os.read(self.child_stdin_fd, 4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                finally:
                    os.close(self.child_stdin_fd)
                child['wire'] = b''.join(chunks)
                self.returncode = 0
                return int(self.returncode)
        launch_environment = {
            'RC4_SIGNING_SUBKEY_B64': 'a2V5LWJ5dGVz',
            'RC4_SIGNING_PASSPHRASE': 'fixture passphrase',
            'SAFE_VALUE': 'must-not-reach-child',
            'AWS_SECRET_ACCESS_KEY': 'must-not-reach-child',
            'HOME': '/home/runner', 'LANG': 'C.UTF-8',
            'GITHUB_REPOSITORY': feeder.EXPECTED_REPOSITORY,
            'OBSERVED_REPOSITORY_ID': feeder.EXPECTED_REPOSITORY_ID,
            'EXPECTED_REPOSITORY_ID': feeder.EXPECTED_REPOSITORY_ID,
            'GITHUB_WORKSPACE': '/workspace', 'RUNNER_TEMP': '/runner-temp',
            'INPUT_SIGNER_IMAGE_DIGEST': 'sha256:' + 'a' * 64,
            'INPUT_IDENTITY_SHA256': 'b' * 64,
            'GITHUB_RUN_ID': '700', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'c' * 40,
            'INPUT_WORKFLOW_BLOB_SHA': 'd' * 40, 'INPUT_HELPER_BLOB_SHA': 'e' * 40,
            'INPUT_SIGNER_BLOB_SHA': 'f' * 40, 'INPUT_FEEDER_BLOB_SHA': '1' * 40,
            'INPUT_POLICY_BLOB_SHA': '2' * 40, 'INPUT_PUBLIC_KEY_BLOB_SHA': '3' * 40,
            'INPUT_DOCKERFILE_BLOB_SHA': '4' * 40, 'INPUT_BASE_IMAGE_DIGEST': 'sha256:' + '5' * 64,
        }
        argv = feeder.signer_argv(launch_environment, docker_executable='/usr/bin/docker')
        self.assertEqual(argv[0], '/usr/bin/docker')
        self.assertIn('--network', argv); self.assertIn('none', argv)
        self.assertIn('--read-only', argv); self.assertIn('--pull', argv)
        self.assertEqual(argv[argv.index('--pull') + 1], 'never')
        self.assertEqual(argv[argv.index('--user') + 1], f'{os.getuid()}:{os.getgid()}')
        self.assertEqual(argv[argv.index('--identity-sha256') + 1], 'b' * 64)
        self.assertEqual(argv[argv.index('--workflow-run-id') + 1], '700')
        self.assertEqual(argv[-2:], ['--signer-image-digest', 'sha256:' + 'a' * 64])
        expected_pairs = {
            '--identity': 'scripts/rc4-sign-retain-inputs.json',
            '--identity-sha256': 'b' * 64,
            '--metadata': '/task/verified/release-metadata.json',
            '--input': '/task/verified/input',
            '--unsigned-manifest': '/task/verified/unsigned-input-manifest.json',
            '--candidate': '/task/output/candidate',
            '--workflow-run-id': '700', '--workflow-run-attempt': '1',
            '--workflow-head-sha': 'c' * 40, '--workflow-blob-sha': 'd' * 40,
            '--helper-blob-sha': 'e' * 40, '--signer-blob-sha': 'f' * 40,
            '--feeder-blob-sha': '1' * 40, '--policy-blob-sha': '2' * 40,
            '--public-key-blob-sha': '3' * 40, '--dockerfile-blob-sha': '4' * 40,
            '--base-image-digest': 'sha256:' + '5' * 64,
            '--signer-image-digest': 'sha256:' + 'a' * 64,
        }
        for flag, expected in expected_pairs.items():
            self.assertEqual(argv[ len(argv) - 1 - argv[::-1].index(flag) + 1 ], expected)
        mounts = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == '-v']
        self.assertIn('/workspace:/w:ro', mounts)
        self.assertIn('/runner-temp/rc4-sign/verified:/task/verified:ro', mounts)
        self.assertIn('/runner-temp/rc4-sign/output:/task/output', mounts)
        self.assertIn('/runner-temp/rc4-sign/gnupg:/task/gnupg', mounts)
        for variable in ('TMPDIR=/task/gnupg', 'TMP=/task/gnupg', 'TEMP=/task/gnupg'):
            self.assertIn(variable, argv)
        for secret in ('key-bytes', 'fixture passphrase'):
            self.assertNotIn(secret, argv)
        with self.assertRaises(ValueError):
            feeder.signer_argv(dict(launch_environment, GITHUB_REPOSITORY='wrong'),
                               docker_executable='/usr/bin/docker')
        with self.assertRaises(ValueError):
            feeder.signer_argv(dict(launch_environment, OBSERVED_REPOSITORY_ID='0'),
                               docker_executable='/usr/bin/docker')
        with self.assertRaisesRegex(ValueError, 'attempt'):
            feeder.signer_argv(dict(launch_environment, GITHUB_RUN_ATTEMPT='2'),
                               docker_executable='/usr/bin/docker')
        feeder.run_isolated_signer(launch_environment, argv, popen_factory=FakeProcess)
        self.assertEqual(launch_environment['SAFE_VALUE'], 'must-not-reach-child')
        self.assertEqual(launch_environment['AWS_SECRET_ACCESS_KEY'], 'must-not-reach-child')
        self.assertEqual(child['kwargs']['env'], {'HOME': '/home/runner', 'LANG': 'C.UTF-8'})
        self.assertFalse(set(feeder.SECRET_NAMES) & set(child['kwargs']['env']))
        self.assertNotIn('SAFE_VALUE', child['kwargs']['env'])
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', child['kwargs']['env'])
        self.assertFalse(any('key-bytes' in value or 'fixture passphrase' in value
                             for value in child['argv']))
        self.assertIs(child['kwargs']['stdout'], feeder.subprocess.DEVNULL)
        self.assertIs(child['kwargs']['stderr'], feeder.subprocess.DEVNULL)
        launched_wire = io.BytesIO(child['wire'])
        key_size = struct.unpack('>I', launched_wire.read(4))[0]
        self.assertEqual(launched_wire.read(key_size), b'key-bytes')
        password_size = struct.unpack('>I', launched_wire.read(4))[0]
        self.assertEqual(launched_wire.read(password_size), b'fixture passphrase')
        self.assertEqual(launched_wire.read(), b'')

        class FailedProcess(FakeProcess):
            def wait(self):
                super().wait()
                self.returncode = 17
                return int(self.returncode)
        failed_environment = {
            'RC4_SIGNING_SUBKEY_B64': 'a2V5LWJ5dGVz',
            'RC4_SIGNING_PASSPHRASE': 'fixture passphrase',
        }
        with self.assertRaisesRegex(RuntimeError, 'isolated signer failed'):
            feeder.run_isolated_signer(failed_environment, argv, popen_factory=FailedProcess)
        self.assertEqual(failed_environment, {})
        events.clear()
        with self.assertRaisesRegex(ValueError, 'secret frame'):
            module.with_signing_secret(io.BytesIO(b'bad'), eligibility, fake_sign)
        self.assertEqual(events, ['eligibility'])

    def test_feeder_zeroes_malformed_credentials_and_closes_all_pipe_fds(self):
        feeder_path = ROOT / 'scripts/rc4-signing-secret-feeder.py'
        spec = importlib.util.spec_from_file_location('rc4_secret_feeder_failures', feeder_path)
        assert spec is not None and spec.loader is not None
        feeder = importlib.util.module_from_spec(spec); spec.loader.exec_module(feeder)
        for index, environment in enumerate((
            {'RC4_SIGNING_SUBKEY_B64': 'not-base64', 'RC4_SIGNING_PASSPHRASE': 'pass'},
            {'RC4_SIGNING_SUBKEY_B64': 'a2V5', 'RC4_SIGNING_PASSPHRASE': 'p' * (16 * 1024 + 1)},
        )):
            observed = []
            original_zero = feeder.zero
            def record(value):
                if isinstance(value, bytearray): observed.append(value)
                original_zero(value)
            with patch.object(feeder, 'zero', side_effect=record):
                with self.assertRaises(ValueError): feeder.pop_credentials(environment)
            self.assertEqual(environment, {})
            self.assertTrue(observed or index == 0)
            self.assertTrue(all(not any(value) for value in observed))

        captured = []
        original_pop = feeder.pop_credentials
        def capture_pop(environment):
            credentials = original_pop(environment); captured.extend(credentials); return credentials
        main_environment = {
            'RC4_SIGNING_SUBKEY_B64': 'a2V5', 'RC4_SIGNING_PASSPHRASE': 'pass',
            'GITHUB_REPOSITORY': 'wrong/repository',
            'OBSERVED_REPOSITORY_ID': feeder.EXPECTED_REPOSITORY_ID,
            'EXPECTED_REPOSITORY_ID': feeder.EXPECTED_REPOSITORY_ID,
        }
        with patch.dict(feeder.os.environ, main_environment, clear=True), \
             patch.object(feeder, 'pop_credentials', side_effect=capture_pop), \
             patch.object(feeder, 'launch_isolated_signer') as launch:
            with self.assertRaises(ValueError): feeder.main()
            self.assertFalse(set(feeder.SECRET_NAMES) & set(feeder.os.environ))
            launch.assert_not_called()
        self.assertTrue(captured and all(not any(value) for value in captured))

        real_pipe = os.pipe
        allocated = []
        def tracked_pipe():
            pair = real_pipe(); allocated.extend(pair); return pair
        def assert_closed():
            for file_descriptor in allocated:
                with self.assertRaises(OSError): os.fstat(file_descriptor)
            allocated.clear()
        credentials = (bytearray(b'key'), bytearray(b'pass'))
        argv = ['docker', 'run', '--network', 'none']
        with patch.object(feeder.os, 'pipe', side_effect=tracked_pipe):
            with self.assertRaisesRegex(OSError, 'spawn'):
                feeder.launch_isolated_signer({}, argv, credentials,
                                             popen_factory=lambda *a, **k: (_ for _ in ()).throw(OSError('spawn')))
        assert_closed()

        class ReaderProcess:
            def __init__(self, *args, **kwargs):
                self.child_fd = os.dup(kwargs['stdin']); self.returncode = None
            def wait(self):
                try:
                    while os.read(self.child_fd, 4096): pass
                finally:
                    os.close(self.child_fd)
                self.returncode = 0
                return 0
        with patch.object(feeder.os, 'pipe', side_effect=tracked_pipe), \
             patch.object(feeder, 'write_fd_part', side_effect=OSError('writer')):
            with self.assertRaisesRegex(OSError, 'writer'):
                feeder.launch_isolated_signer({}, argv, credentials, popen_factory=ReaderProcess)
        assert_closed()

        class WaitFailure(ReaderProcess):
            def wait(self):
                super().wait(); raise OSError('wait')
        with patch.object(feeder.os, 'pipe', side_effect=tracked_pipe):
            with self.assertRaisesRegex(OSError, 'wait'):
                feeder.launch_isolated_signer({}, argv, credentials, popen_factory=WaitFailure)
        assert_closed()

        class EarlyFailure(ReaderProcess):
            def __init__(self, *args, **kwargs):
                child_fd = os.dup(kwargs['stdin']); os.close(child_fd)
                self.returncode = None
            def wait(self): self.returncode = 23; return self.returncode
        with patch.object(feeder.os, 'pipe', side_effect=tracked_pipe):
            with self.assertRaisesRegex(RuntimeError, 'signer failed'):
                feeder.launch_isolated_signer({}, argv, credentials, popen_factory=EarlyFailure)
        assert_closed()
        for value in credentials: feeder.zero(value)

    def test_package_signer_accepts_explicit_secret_without_environment(self):
        from unittest.mock import patch
        signing_path = ROOT / 'scripts/package-signing.py'
        spec = importlib.util.spec_from_file_location('package_signing_explicit', signing_path)
        assert spec is not None and spec.loader is not None
        signing = importlib.util.module_from_spec(spec); spec.loader.exec_module(signing)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            public = root / 'public.gpg'; public.write_bytes(b'public fixture')
            primary, subkey = 'A' * 40, 'B' * 40
            policy = root / 'policy.json'; policy.write_text(json.dumps({
                'primary_fingerprint': primary, 'signing_subkey_fingerprint': subkey,
                'public_key_sha256': sha(public)}))
            calls = []
            class Result:
                returncode = 0
                stderr = b''
                def __init__(self, stdout=b''): self.stdout = stdout
            def record(kind, capability='', secret_marker=''):
                fields = [''] * 15; fields[0] = kind; fields[11] = capability; fields[14] = secret_marker
                return ':'.join(fields)
            def fingerprint(value):
                fields = [''] * 10; fields[0] = 'fpr'; fields[9] = value
                return ':'.join(fields)
            public_records = ('\n'.join((record('pub'), fingerprint(primary),
                                         record('sub', 's', '+'), fingerprint(subkey))) + '\n').encode()
            secret_records = ('\n'.join((record('sec', '', '#'), fingerprint(primary),
                                         record('ssb', 's', '+'), fingerprint(subkey))) + '\n').encode()
            def fake_run(*args, data=None, check=True):
                calls.append((args, None if data is None else bytes(data)))
                if args[0] == 'findmnt': return Result(b'apfs\n')
                if '--list-secret-keys' in args: return Result(secret_records)
                if '--list-keys' in args: return Result(public_records)
                return Result()
            old = {key: os.environ.pop(key) for key in signing.SECRET_ENV if key in os.environ}
            key_buffer = bytearray(b'raw-secret-key')
            password_buffer = bytearray(b'passphrase')
            try:
                with patch.object(signing, 'run', side_effect=fake_run):
                    ring = signing.Keyring(public, policy, secret=True,
                                           secret_material=(key_buffer, password_buffer))
                    self.assertIsInstance(ring.password, bytearray)
                    self.assertIs(ring.password, password_buffer)
                    self.assertEqual(ring.password, b'passphrase\n')
                    self.assertFalse(any(key_buffer), 'Imported key buffer was not zeroed promptly')
                    retained_password = ring.password
                    ring.close()
                    ring.close()
                    self.assertFalse(any(retained_password), 'Retained passphrase was not zeroed')
            finally:
                os.environ.update(old)
            imports = [data for args, data in calls if '--import' in args]
            self.assertEqual(imports, [b'public fixture', b'raw-secret-key'])
            self.assertEqual(sum(args[0] == 'gpgconf' for args, _ in calls), 1)
            self.assertFalse(signing.SECRET_ENV & set(os.environ) - set(old))

            failing_key = bytearray(b'failure-secret-key')
            failing_password = bytearray(b'failure-passphrase')
            def failing_run(*args, data=None, check=True):
                if args[0] == 'findmnt': return Result(b'apfs\n')
                if '--list-keys' in args: return Result(public_records)
                if '--list-secret-keys' in args: raise ValueError('synthetic secret listing failure')
                return Result()
            with patch.object(signing, 'run', side_effect=failing_run):
                with self.assertRaisesRegex(ValueError, 'synthetic secret listing failure'):
                    signing.Keyring(public, policy, secret=True,
                                    secret_material=(failing_key, failing_password))
            self.assertFalse(any(failing_key), 'Exception path retained imported key bytes')
            self.assertFalse(any(failing_password), 'Exception path retained passphrase bytes')

            malformed_key = bytearray(b'malformed-key')
            malformed_password = bytearray(b'bad\npassword')
            with patch.object(signing, 'run', side_effect=AssertionError('must fail before subprocess')):
                with self.assertRaisesRegex(ValueError, 'malformed'):
                    signing.Keyring(public, policy, secret=True,
                                    secret_material=(malformed_key, malformed_password))
            self.assertFalse(any(malformed_key), 'Malformed explicit key buffer was not zeroed')
            self.assertFalse(any(malformed_password), 'Malformed explicit passphrase was not zeroed')

            public_failure_key = bytearray(b'public-import-key')
            public_failure_password = bytearray(b'public-import-password')
            def public_import_failure(*args, data=None, check=True):
                if args[0] == 'findmnt': return Result(b'apfs\n')
                if '--import' in args: raise ValueError('synthetic public import failure')
                return Result()
            with patch.object(signing, 'run', side_effect=public_import_failure):
                with self.assertRaisesRegex(ValueError, 'synthetic public import failure'):
                    signing.Keyring(public, policy, secret=True,
                                    secret_material=(public_failure_key, public_failure_password))
            self.assertFalse(any(public_failure_key), 'Public import failure retained explicit key')
            self.assertFalse(any(public_failure_password), 'Public import failure retained passphrase')

            cleanup_key = bytearray(b'cleanup-key')
            cleanup_password = bytearray(b'cleanup-password')
            class FailingCleanup:
                def cleanup(self): raise OSError('synthetic cleanup failure')
            ring = object.__new__(signing.Keyring)
            ring._pending_key = cleanup_key
            ring.password = cleanup_password
            ring._closed = False
            ring.temp = FailingCleanup()
            ring.home = root
            with patch.object(signing, 'run', return_value=Result()):
                with self.assertRaisesRegex(OSError, 'synthetic cleanup failure'):
                    ring.close()
                ring.close()
            self.assertFalse(any(cleanup_key), 'Cleanup failure retained key bytes')
            self.assertFalse(any(cleanup_password), 'Cleanup failure retained passphrase bytes')


class SigningOrchestrationTests(unittest.TestCase):
    def test_fake_signer_runs_only_after_revalidation_and_preserves_exact_inputs(self):
        import io
        import struct
        module = load_helper(self)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            identity, identity_path, metadata_path, inputs = fixture(root)
            unsigned = root / 'unsigned-input-manifest.json'
            module.validate_inputs(identity_path, sha(identity_path), metadata_path, inputs, unsigned)
            before = {path.name: sha(path) for path in inputs.iterdir()}
            execution = execution_identity(701, 1)
            key, password = b'fixture-key', b'fixture-password'
            wire = io.BytesIO(struct.pack('>I', len(key)) + key +
                              struct.pack('>I', len(password)) + password)
            events = []
            class FakeRing:
                policy = {'primary_fingerprint': 'A' * 40, 'signing_subkey_fingerprint': 'B' * 40}
                def sign(self, path):
                    events.append(('sign', path.name))
                    Path(str(path) + '.sig').write_bytes(('sig:' + path.name).encode())
                def verify(self, path):
                    events.append(('verify', path.name))
                    if not Path(str(path) + '.sig').is_file():
                        raise ValueError('missing signature')
                def close(self):
                    events.append(('close', None))
            def ring_factory(raw_key, raw_password):
                events.append(('factory', bytes(raw_key), bytes(raw_password)))
                return FakeRing()
            def preflight(signer_image_digest):
                events.append(('preflight', signer_image_digest))
                return {'primary_fingerprint': 'A' * 40,
                        'signing_subkey_fingerprint': 'B' * 40,
                        'public_key_sha256': 'C' * 64,
                        'signing_policy_sha256': 'd' * 64}
            candidate = root / 'candidate'
            with synthetic_production(module, identity_path, identity):
                result = module.sign_candidate(identity_path, sha(identity_path), metadata_path, inputs,
                                               unsigned, candidate, execution, wire, ring_factory, preflight)
            self.assertEqual(result['classification'], CLASSIFICATION)
            self.assertEqual(len(result['signature_outputs']), 6)
            self.assertEqual({path.name: sha(path) for path in inputs.iterdir()}, before)
            self.assertEqual(events[0], ('preflight', execution['signer_image_digest']))
            self.assertEqual(events[1], ('factory', key, password))
            self.assertEqual(events[-1], ('close', None))
            self.assertEqual(len([event for event in events if event[0] == 'sign']), 6)
            self.assertEqual(len([event for event in events if event[0] == 'verify']), 6)
            self.assertTrue((candidate / 'candidate-manifest.json').is_file())

            # A workflow rerun must fail before preflight, secret read, Keyring, or signatures.
            events.clear()
            retry_wire = io.BytesIO(struct.pack('>I', len(key)) + key +
                                    struct.pack('>I', len(password)) + password)
            retry_candidate = root / 'retry-must-not-exist'
            with synthetic_production(module, identity_path, identity):
                with self.assertRaisesRegex(ValueError, 'attempt'):
                    module.sign_candidate(
                        identity_path, sha(identity_path), metadata_path, inputs, unsigned,
                        retry_candidate, execution_identity(701, 2), retry_wire, ring_factory, preflight)
            self.assertEqual(events, [])
            self.assertEqual(retry_wire.tell(), 0)
            self.assertFalse(retry_candidate.exists())

            # Deterministic failure occurs before secret read or signer creation.
            changed = json.loads(metadata_path.read_text()); changed['assets'][0]['size'] += 1
            metadata_path.write_text(json.dumps(changed))
            events.clear(); wire.seek(0)
            with synthetic_production(module, identity_path, identity):
                with self.assertRaisesRegex(ValueError, 'metadata'):
                    module.sign_candidate(identity_path, sha(identity_path), metadata_path, inputs,
                                          unsigned, root / 'must-not-exist', execution, wire,
                                          ring_factory, preflight)
            self.assertEqual(events, [])
            self.assertEqual(wire.tell(), 0)
            self.assertFalse((root / 'must-not-exist').exists())


if __name__ == '__main__':
    unittest.main()
