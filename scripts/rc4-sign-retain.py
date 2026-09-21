#!/usr/bin/env python3
"""Validate and retain an exact nonpublishing signed RC4 fixture.

This helper cannot publish and does not classify any output as RC5, a strict
successor, an upgrade candidate, or a publication candidate.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import sys
import urllib.request

CLASSIFICATION = 'nonpublishing signed RC4 exact-byte qualification fixture only'
REPOSITORY = 'omarchy-mac/omarchy-pkgs-aarch64'
REPOSITORY_ID = 1327386148
RELEASE_ID = 390634001
DATABASE_NAMES = {
    'omarchy-aarch64.db', 'omarchy-aarch64.db.tar.zst',
    'omarchy-aarch64.files', 'omarchy-aarch64.files.tar.zst',
}
SECRET_ENV = {'PACMAN_SIGNING_SUBKEY_B64', 'PACMAN_SIGNING_PASSPHRASE'}
HEX40 = re.compile(r'[0-9a-f]{40}')
HEX64 = re.compile(r'[0-9a-f]{64}')
SAFE_NAME = re.compile(r'[A-Za-z0-9@._+-]+')
FROZEN_IDENTITY_SHA256 = '6bd5c1df3a57b73ec0984c5b067b7e1f68fa1d9ed3d912a6a20a2f03f84173cf'
PRODUCTION_COUNTS = {'packages': 52, 'database_and_files': 4, 'evidence': 1}
PRIMARY_FINGERPRINT = 'FBD6874D423C418DDB6D143EECE19CDDE306DBD2'
SIGNING_SUBKEY_FINGERPRINT = 'D791ED0C72439D9F8757421258043B2770A25762'
PUBLIC_KEY_SHA256 = '118b1a5b48a74a2dd993860c4dc3f9d477d5c47c3b1422ea40e8e91f3c7e73d1'
SIGNING_POLICY_SHA256 = '460b9352f6c35de32db58cddf1c57cc455633f9cb495f7b1e9fb009d7470c71d'
SOURCE_EVIDENCE_HASHES = {
    'report_39_sha256': '1632ad43ba98c749cd22a9385870619e8b6580663eb798bb3a15a15e5c270363',
    'report_40_sha256': '64e6f1ee61943ed2cb10945bb285386c3d70a8e9fd80afe026a68b58d7451aee',
    'report_41_sha256': '5ebd851bc4918312af897cf3c659c1b683a902add3937825d1357202f4dcaa32',
    'rc_inventory_sha256': '54a6c94314b2050134a70bcaac701f149ab039eb03f54f4b10060f35c0092912',
    'retained_capture_manifest_sha256': 'a1a8cf9bb2b75fd4b76377d229118d2333e7cbf4efa75f9b99422ffa7506fa14',
    'retained_expected_identity_sha256': '5fd6cec66052ee0005ee59f5c2d3f1ea701f7a0ee1da6afb588c342d896179c5',
}
PROVENANCE_LIMITATIONS = [
    'Reports 39-41 establish exact official RC release byte and DB membership identity, not reproducibility.',
    'The two rc4-2 package BUILDINFO files omit source_commit, source_version, source_dirty and recipe_pin.',
    'pkgbuild_sha256sum values do not authenticate external source or recipe claims.',
    'build-inputs.txt remains a retained provenance claim and is not authenticated by this design.',
    'Signing these bytes proves only that the approved signing subkey signed the exact frozen bytes; it does not retroactively prove how they were built.',
    'No client trust, install/runtime behavior, negative rejection, positive qualification, publication or promotion claim is made.',
    'This fixture contains RC4 bytes and cannot establish RC4-to-RC5 transition correctness.',
    'It cannot establish first strict signed successor, successor source/runtime behavior, upgrade behavior or publication readiness.',
]
CANNOT_PROVE = [
    'RC4-to-RC5 transition',
    'successor source behavior',
    'successor runtime behavior',
    'upgrade behavior',
    'fresh-install behavior',
    'publication readiness',
]
PRODUCTION_CORE = {
    'omarchy': {'asset_id': 576676265, 'filename': 'omarchy-4.0.3rc4-2-aarch64.pkg.tar.xz',
                'version': '4.0.3rc4-2',
                'sha256': '14c618f8e937fab46aa7db7d1023d8f48039cd1d996f0804a172b1b3873a66f3'},
    'omarchy-settings': {'asset_id': 576675640,
                         'filename': 'omarchy-settings-4.0.3rc4-2-aarch64.pkg.tar.xz',
                         'version': '4.0.3rc4-2',
                         'sha256': 'c15940615004ea7d61cb6d7d0f7dee1af335688aa32f4ab8602eaa8923ad347e'},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_fields(value, fields, label):
    require(isinstance(value, dict) and set(value) == set(fields), f'{label} fields differ')


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def load_json(path, label):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f'{label} must be a regular non-symlink file')
    try:
        return json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f'{label} is not valid JSON') from error


def safe_filename(value):
    return (isinstance(value, str) and SAFE_NAME.fullmatch(value) is not None and
            PurePosixPath(value).name == value and '/' not in value and '\\' not in value)


def validate_identity(path, expected_sha256, production=False):
    path = Path(path)
    require(HEX64.fullmatch(expected_sha256 or '') is not None, 'Invalid immutable identity SHA256')
    if production:
        require(expected_sha256 == FROZEN_IDENTITY_SHA256,
                'production RC4 identity SHA256 is not the frozen 52-package set')
    require(path.is_file() and not path.is_symlink(), 'Immutable identity must be a regular non-symlink file')
    require(digest(path) == expected_sha256, 'Immutable identity bytes differ')
    identity = load_json(path, 'Immutable identity')
    exact_fields(identity, {'schema', 'classification', 'repository', 'repository_id', 'release_id',
                            'inputs', 'expected_counts'}, 'Immutable identity')
    require(identity['schema'] == 1 and type(identity['schema']) is int, 'Unsupported immutable identity schema')
    require(identity['classification'] == CLASSIFICATION, 'Identity is not the RC4 fixture-only classification')
    require(identity['repository'] == REPOSITORY and identity['repository_id'] == REPOSITORY_ID and
            identity['release_id'] == RELEASE_ID, 'Immutable identity repository or release differs')
    counts = identity['expected_counts']
    exact_fields(counts, {'packages', 'database_and_files', 'evidence'}, 'Expected counts')
    require(all(type(value) is int and value > 0 for value in counts.values()), 'Invalid expected counts')
    require(isinstance(identity['inputs'], list), 'Immutable inputs must be a list')
    names, ids = set(), set()
    actual = {'packages': 0, 'database_and_files': 0, 'evidence': 0}
    for row in identity['inputs']:
        require(isinstance(row, dict), 'Immutable input row differs')
        base = {'asset_id', 'filename', 'size', 'sha256', 'kind'}
        kind = row.get('kind')
        fields = base | ({'package_name', 'version', 'architecture'} if kind == 'package' else set())
        exact_fields(row, fields, 'Immutable input row')
        require(type(row['asset_id']) is int and row['asset_id'] > 0 and row['asset_id'] not in ids,
                'Invalid or duplicate immutable asset ID')
        require(safe_filename(row['filename']) and row['filename'] not in names,
                'Invalid or duplicate immutable filename')
        require(type(row['size']) is int and row['size'] > 0 and HEX64.fullmatch(row['sha256'] or ''),
                'Invalid immutable input size or SHA256')
        if kind == 'package':
            expected_architecture = ('any' if '-any.pkg.tar.' in row['filename'] else
                                     'aarch64' if '-aarch64.pkg.tar.' in row['filename'] else None)
            require(re.fullmatch(r'[A-Za-z0-9@._+-]+', row['package_name'] or '') and
                    re.fullmatch(r'[A-Za-z0-9:._+-]+', row['version'] or '') and
                    row['architecture'] in ('aarch64', 'any') and
                    row['architecture'] == expected_architecture,
                    'Invalid immutable package identity')
            actual['packages'] += 1
        elif kind in ('database', 'files'):
            require(row['filename'] in DATABASE_NAMES, 'Invalid immutable database/files alias')
            actual['database_and_files'] += 1
        elif kind == 'evidence':
            require(row['filename'] == 'build-inputs.txt', 'Invalid immutable evidence input')
            actual['evidence'] += 1
        else:
            raise ValueError('Invalid immutable input kind')
        ids.add(row['asset_id']); names.add(row['filename'])
    require(actual == counts, 'Immutable input counts differ')
    require({row['filename'] for row in identity['inputs'] if row['kind'] in ('database', 'files')} == DATABASE_NAMES,
            'Immutable database/files inventory differs')
    require(len(identity['inputs']) == sum(counts.values()), 'Immutable input inventory count differs')
    if production:
        require(counts == PRODUCTION_COUNTS,
                'production RC4 identity is not the fixed 52-package set')
        packages = {row['package_name']: row for row in identity['inputs'] if row['kind'] == 'package'}
        for name, expected in PRODUCTION_CORE.items():
            require(packages.get(name) is not None and
                    all(packages[name][field] == value for field, value in expected.items()),
                    'production RC4 core package identity differs')
    return identity


def parse_key_values(text, separator=' = '):
    values = {}
    for line in text.splitlines():
        if separator in line:
            key, value = line.split(separator, 1)
            values.setdefault(key, []).append(value)
    return values


def read_package_info_native(path):
    listed = subprocess.run(['bsdtar', '-tf', str(path)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(listed.returncode == 0, 'Package metadata cannot be read')
    try:
        members = listed.stdout.decode().splitlines()
    except UnicodeDecodeError as error:
        raise ValueError('Package member path differs') from error
    require(members and all(safe_archive_member(name) for name in members),
            'Package member path differs')
    require(members.count('.PKGINFO') == 1, 'Package metadata inventory differs')
    extracted = subprocess.run(['bsdtar', '-xOf', str(path), '.PKGINFO'], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(extracted.returncode == 0, 'Package metadata cannot be read')
    try:
        return parse_key_values(extracted.stdout.decode())
    except UnicodeDecodeError as error:
        raise ValueError('Package metadata cannot be read') from error


def read_package_info(path):
    try:
        with tarfile.open(path, 'r:*') as archive:
            members = [member for member in archive.getmembers() if member.name == '.PKGINFO']
            require(len(members) == 1 and members[0].isfile(), 'Package metadata inventory differs')
            stream = archive.extractfile(members[0])
            require(stream is not None, 'Package metadata missing')
            assert stream is not None
            return parse_key_values(stream.read().decode())
    except (tarfile.TarError, UnicodeDecodeError, OSError):
        return read_package_info_native(path)


def parse_db_desc(text):
    result = {}
    for section in text.strip().split('\n\n'):
        lines = section.splitlines()
        require(len(lines) >= 2 and lines[0].startswith('%') and lines[0].endswith('%'),
                'Database description is malformed')
        result[lines[0][1:-1]] = '\n'.join(lines[1:])
    return result


def safe_archive_member(name):
    path = PurePosixPath(name)
    return (not path.is_absolute() and '\\' not in name and '..' not in path.parts and
            all(part not in ('', '.') for part in path.parts))


def add_database_record(records, member_name, raw):
    require(safe_archive_member(member_name), 'Database member path differs')
    if not member_name.endswith('/desc'):
        return
    require(len(PurePosixPath(member_name).parts) == 2, 'Database member path differs')
    try:
        row = parse_db_desc(raw.decode())
    except UnicodeDecodeError as error:
        raise ValueError('Database description is malformed') from error
    require({'NAME', 'VERSION', 'FILENAME', 'CSIZE', 'SHA256SUM'} <= set(row),
            'Database description fields differ')
    require(row['NAME'] not in records, 'Database package name is duplicated')
    records[row['NAME']] = row


def read_database_native(path):
    listed = subprocess.run(['bsdtar', '-tf', str(path)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(listed.returncode == 0, 'Database cannot be read')
    try:
        members = listed.stdout.decode().splitlines()
    except UnicodeDecodeError as error:
        raise ValueError('Database member path differs') from error
    require(members, 'Database membership is empty')
    records = {}
    for member_name in members:
        require(safe_archive_member(member_name), 'Database member path differs')
        if not member_name.endswith('/desc'):
            continue
        extracted = subprocess.run(['bsdtar', '-xOf', str(path), member_name], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(extracted.returncode == 0, 'Database cannot be read')
        add_database_record(records, member_name, extracted.stdout)
    require(records, 'Database membership is empty')
    return records


def read_database(path):
    records = {}
    try:
        with tarfile.open(path, 'r:*') as archive:
            for member in archive.getmembers():
                require(safe_archive_member(member.name), 'Database member path differs')
                if not member.name.endswith('/desc'):
                    continue
                require(member.isfile(), 'Database member path differs')
                stream = archive.extractfile(member)
                require(stream is not None, 'Database description missing')
                assert stream is not None
                add_database_record(records, member.name, stream.read())
    except (tarfile.ReadError, tarfile.CompressionError):
        return read_database_native(path)
    except OSError as error:
        raise ValueError('Database cannot be read') from error
    require(records, 'Database membership is empty')
    return records


def write_new_json(path, value):
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), 'Output must be new')
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical(value)
    handle, temporary_name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, 'wb') as output:
            output.write(raw)
        with path.open('xb') as output:
            output.write(raw)
    finally:
        temporary.unlink(missing_ok=True)


def acquire_assets(identity_path, expected_sha256, release_assets, fetch_asset,
                   output_directory, metadata_output, production=False):
    """Acquire only reviewed numeric IDs after exact complete metadata comparison."""
    identity = validate_identity(identity_path, expected_sha256, production=production)
    require(isinstance(release_assets, list), 'Release asset metadata differs')
    expected = [(row['asset_id'], row['filename'], row['size'], 'sha256:' + row['sha256'], 'uploaded')
                for row in identity['inputs']]
    observed = []
    for row in release_assets:
        exact_fields(row, {'id', 'name', 'size', 'digest', 'state'}, 'Release asset metadata')
        observed.append((row['id'], row['name'], row['size'], row['digest'], row['state']))
    require(sorted(observed) == sorted(expected), 'Release asset metadata differs')
    output = Path(output_directory)
    metadata_path = Path(metadata_output)
    require(not output.exists() and not output.is_symlink(), 'Acquisition output must be new')
    require(not metadata_path.exists() and not metadata_path.is_symlink(), 'Metadata output must be new')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.rc4-acquisition.', dir=output.parent))
    try:
        for row in identity['inputs']:
            data = fetch_asset(row['asset_id'])
            require(isinstance(data, bytes) and len(data) == row['size'] and
                    hashlib.sha256(data).hexdigest() == row['sha256'],
                    f'downloaded bytes differ: {row["filename"]}')
            (temporary / row['filename']).write_bytes(data)
        temporary.rename(output)
        metadata = {'repository': REPOSITORY, 'repository_id': REPOSITORY_ID,
                    'release_id': RELEASE_ID, 'assets': [
                        {'id': row[0], 'name': row[1], 'size': row[2],
                         'digest': row[3], 'state': row[4]} for row in expected]}
        write_new_json(metadata_path, metadata)
        return metadata
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        raise


def validate_inputs(identity_path, expected_sha256, metadata_path, input_directory, output,
                    production=False):
    """Validate exact metadata, bytes, package metadata and complete DB membership."""
    identity = validate_identity(identity_path, expected_sha256, production=production)
    metadata = load_json(metadata_path, 'Release metadata')
    exact_fields(metadata, {'repository', 'repository_id', 'release_id', 'assets'}, 'Release metadata')
    require(metadata['repository'] == REPOSITORY and metadata['repository_id'] == REPOSITORY_ID and
            metadata['release_id'] == RELEASE_ID and isinstance(metadata['assets'], list),
            'Release metadata identity differs')
    expected_metadata = sorted((row['asset_id'], row['filename'], row['size'], 'sha256:' + row['sha256'], 'uploaded')
                               for row in identity['inputs'])
    observed_metadata = []
    for row in metadata['assets']:
        exact_fields(row, {'id', 'name', 'size', 'digest', 'state'}, 'Release asset metadata')
        observed_metadata.append((row['id'], row['name'], row['size'], row['digest'], row['state']))
    require(sorted(observed_metadata) == expected_metadata, 'Release asset metadata differs')

    root = Path(input_directory)
    require(root.is_dir() and not root.is_symlink(), 'Input directory is unsafe')
    expected_names = {row['filename'] for row in identity['inputs']}
    observed_names = {path.name for path in root.iterdir()}
    require(observed_names == expected_names, 'Input inventory differs')
    rows = {row['filename']: row for row in identity['inputs']}
    for name in sorted(expected_names):
        path, row = root / name, rows[name]
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == row['size'] and
                digest(path) == row['sha256'], f'Input bytes differ: {name}')

    packages = [row for row in identity['inputs'] if row['kind'] == 'package']
    for row in packages:
        info = read_package_info(root / row['filename'])
        require(info.get('pkgname') == [row['package_name']] and info.get('pkgver') == [row['version']] and
                info.get('arch') == [row['architecture']], f'Package metadata differs: {row["filename"]}')
    aliases = [row for row in identity['inputs'] if row['kind'] in ('database', 'files')]
    for kind in ('database', 'files'):
        hashes = {row['sha256'] for row in aliases if row['kind'] == kind}
        require(len(hashes) == 1, f'{kind} alias bytes differ')
    database = read_database(root / 'omarchy-aarch64.db')
    expected_db = {row['package_name']: row for row in packages}
    require(set(database) == set(expected_db), 'Database membership differs')
    for name, row in expected_db.items():
        record = database[name]
        require(record['VERSION'] == row['version'] and record['FILENAME'] == row['filename'] and
                record['CSIZE'] == str(row['size']) and record['SHA256SUM'] == row['sha256'],
                f'Database identity differs: {name}')

    counts = identity['expected_counts']
    result = {
        'schema': 1,
        'classification': CLASSIFICATION,
        'repository': REPOSITORY,
        'repository_id': REPOSITORY_ID,
        'release_id': RELEASE_ID,
        'immutable_identity_sha256': expected_sha256,
        'validated_counts': counts,
        'assets': identity['inputs'],
        'served_input_paths': sorted(row['filename'] for row in identity['inputs'] if row['kind'] != 'evidence'),
        'cannot_prove': CANNOT_PROVE,
        'provenance_limitations': PROVENANCE_LIMITATIONS,
        'qualification_approved': False,
        'publication_approved': False,
    }
    write_new_json(output, result)
    return result


def validate_unsigned_manifest(unsigned, identity, expected_sha256):
    exact_fields(unsigned, {
        'schema', 'classification', 'repository', 'repository_id', 'release_id',
        'immutable_identity_sha256', 'validated_counts', 'assets', 'served_input_paths',
        'cannot_prove', 'provenance_limitations', 'qualification_approved',
        'publication_approved',
    }, 'Unsigned input manifest')
    require(unsigned['schema'] == 1 and type(unsigned['schema']) is int and
            unsigned['classification'] == CLASSIFICATION and
            unsigned['repository'] == REPOSITORY and unsigned['repository_id'] == REPOSITORY_ID and
            unsigned['release_id'] == RELEASE_ID and
            unsigned['immutable_identity_sha256'] == expected_sha256 and
            unsigned['validated_counts'] == identity['expected_counts'] and
            unsigned['assets'] == identity['inputs'] and
            unsigned['served_input_paths'] == sorted(
                row['filename'] for row in identity['inputs'] if row['kind'] != 'evidence') and
            unsigned['cannot_prove'] == CANNOT_PROVE and
            unsigned['provenance_limitations'] == PROVENANCE_LIMITATIONS and
            unsigned['qualification_approved'] is False and
            unsigned['publication_approved'] is False,
            'Unsigned input manifest differs')


def serving_contract(identity):
    """Return the only repository paths that qualification may serve."""
    package_and_db = sorted(row['filename'] for row in identity['inputs'] if row['kind'] != 'evidence')
    signatures = sorted(name + '.sig' for name in package_and_db)
    return {
        'input_paths': package_and_db,
        'signature_paths': signatures,
        'served_paths': sorted(package_and_db + signatures),
        'evidence_only_paths': ['build-inputs.txt', 'candidate-manifest.json',
                                'transport-receipt.json', 'unsigned-input-manifest.json'],
    }


EXECUTION_FIELDS = {'repository', 'workflow_run_id', 'workflow_run_attempt', 'workflow_head_sha',
                    'workflow_path', 'workflow_blob_sha', 'helper_blob_shas',
                    'dockerfile_blob_sha', 'base_image_digest', 'signer_image_digest'}
HELPER_BLOB_PATHS = {
    'scripts/rc4-sign-retain.py',
    'scripts/package-signing.py',
    'scripts/rc4-signing-secret-feeder.py',
    'pkgbuilds/omarchy-mac-keyring/signing-policy.json',
    'pkgbuilds/omarchy-mac-keyring/omarchy-mac.gpg',
}
CANDIDATE_FIELDS = {
    'schema', 'classification', 'repository', 'workflow_run_id', 'workflow_run_attempt',
    'workflow_head_sha', 'workflow_path', 'workflow_blob_sha', 'helper_blob_shas',
    'dockerfile_blob_sha', 'base_image_digest', 'source_evidence_hashes',
    'input_release_id', 'input_assets', 'input_manifest_sha256', 'signing_policy',
    'signature_outputs', 'served_path_allowlist', 'evidence_only_paths',
    'output_inventory', 'qualification_approved', 'publication_approved',
}


def validate_execution(execution):
    exact_fields(execution, EXECUTION_FIELDS, 'Execution identity')
    require(execution['repository'] == REPOSITORY and
            type(execution['workflow_run_id']) is int and execution['workflow_run_id'] > 0,
            'Execution run identity differs')
    require(type(execution['workflow_run_attempt']) is int and
            execution['workflow_run_attempt'] == 1,
            'Execution workflow run attempt must be 1')
    require(HEX40.fullmatch(execution['workflow_head_sha'] or '') and
            execution['workflow_path'] == '.github/workflows/sign-and-retain-rc4-fixture.yml' and
            HEX40.fullmatch(execution['workflow_blob_sha'] or '') and
            HEX40.fullmatch(execution['dockerfile_blob_sha'] or ''),
            'Execution workflow identity differs')
    helpers = execution['helper_blob_shas']
    require(isinstance(helpers, dict) and set(helpers) == HELPER_BLOB_PATHS and
            all(HEX40.fullmatch(value or '') for value in helpers.values()),
            'Execution helper blob identities differ')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', execution['base_image_digest'] or '') and
            re.fullmatch(r'sha256:[0-9a-f]{64}', execution['signer_image_digest'] or ''),
            'Execution image digest differs')


def write_candidate_manifest(identity_path, expected_sha256, unsigned_manifest_path,
                             candidate_directory, execution, verify_signature, output):
    """Freeze the internal manifest before upload; it has no transport identity or self digest."""
    identity = validate_identity(identity_path, expected_sha256, production=True)
    validate_execution(execution)
    unsigned_path = Path(unsigned_manifest_path)
    unsigned = load_json(unsigned_path, 'Unsigned input manifest')
    validate_unsigned_manifest(unsigned, identity, expected_sha256)
    root = Path(candidate_directory)
    require(root.is_dir() and not root.is_symlink(), 'Candidate directory is unsafe')
    allowed_root = {'repository', 'evidence', 'candidate-manifest.json'}
    if Path(output).parent == root:
        allowed_root.add(Path(output).name)
    require({path.name for path in root.iterdir()} <= allowed_root, 'Candidate root inventory differs')
    repository, evidence = root / 'repository', root / 'evidence'
    require(repository.is_dir() and not repository.is_symlink() and
            evidence.is_dir() and not evidence.is_symlink(), 'Candidate paths are unsafe')
    contract = serving_contract(identity)
    require({path.name for path in repository.iterdir()} == set(contract['served_paths']),
            'Candidate repository inventory differs')
    require({path.name for path in evidence.iterdir()} == {'build-inputs.txt', 'unsigned-input-manifest.json'},
            'Candidate evidence inventory differs')
    by_name = {row['filename']: row for row in identity['inputs']}
    output_inventory = {}
    signature_outputs = []
    signer = None
    for name in contract['input_paths']:
        path, signature, row = repository / name, repository / (name + '.sig'), by_name[name]
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == row['size'] and
                digest(path) == row['sha256'], f'Candidate input bytes differ: {name}')
        require(signature.is_file() and not signature.is_symlink() and signature.stat().st_size > 0,
                f'Candidate signature missing or unsafe: {name}')
        verified = verify_signature(path, signature)
        exact_fields(verified, {'primary_fingerprint', 'signing_subkey_fingerprint'}, 'Verified signer')
        require(verified == {'primary_fingerprint': PRIMARY_FINGERPRINT,
                             'signing_subkey_fingerprint': SIGNING_SUBKEY_FINGERPRINT},
                'Verified signer fingerprints differ')
        require(signer is None or signer == verified, 'Candidate signatures use different signers')
        signer = verified
        output_inventory['repository/' + name] = {'size': path.stat().st_size, 'sha256': digest(path)}
        output_inventory['repository/' + signature.name] = {
            'size': signature.stat().st_size, 'sha256': digest(signature)}
        signature_outputs.append({'filename': signature.name, 'size': signature.stat().st_size,
                                  'sha256': digest(signature), 'signed_input_sha256': row['sha256'],
                                  **verified})
    evidence_sources = {
        'evidence/build-inputs.txt': next(row for row in identity['inputs'] if row['kind'] == 'evidence'),
        'evidence/unsigned-input-manifest.json': {
            'size': unsigned_path.stat().st_size, 'sha256': digest(unsigned_path)},
    }
    for relative, row in evidence_sources.items():
        path = root / relative
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == row['size'] and
                digest(path) == row['sha256'], f'Candidate evidence bytes differ: {relative}')
        output_inventory[relative] = {'size': path.stat().st_size, 'sha256': digest(path)}
    require(signer is not None, 'Candidate signatures are missing')
    manifest = {
        'schema': 1,
        'classification': CLASSIFICATION,
        'repository': REPOSITORY,
        'workflow_run_id': execution['workflow_run_id'],
        'workflow_run_attempt': execution['workflow_run_attempt'],
        'workflow_head_sha': execution['workflow_head_sha'],
        'workflow_path': execution['workflow_path'],
        'workflow_blob_sha': execution['workflow_blob_sha'],
        'helper_blob_shas': execution['helper_blob_shas'],
        'dockerfile_blob_sha': execution['dockerfile_blob_sha'],
        'base_image_digest': execution['base_image_digest'],
        'source_evidence_hashes': SOURCE_EVIDENCE_HASHES,
        'input_release_id': RELEASE_ID,
        'input_assets': identity['inputs'],
        'input_manifest_sha256': digest(unsigned_path),
        'signing_policy': {
            **signer,
            'public_key_sha256': PUBLIC_KEY_SHA256,
            'signing_policy_sha256': SIGNING_POLICY_SHA256,
            'signer_image_digest': execution['signer_image_digest'],
        },
        'signature_outputs': signature_outputs,
        'served_path_allowlist': contract['served_paths'],
        'evidence_only_paths': ['evidence/build-inputs.txt', 'evidence/unsigned-input-manifest.json'],
        'output_inventory': dict(sorted(output_inventory.items())),
        'qualification_approved': False,
        'publication_approved': False,
    }
    write_new_json(output, manifest)
    return manifest


def validate_candidate_manifest(manifest):
    """Validate every nested field against the frozen production fixture contract."""
    exact_fields(manifest, CANDIDATE_FIELDS, 'candidate manifest')
    require(manifest['schema'] == 1 and type(manifest['schema']) is int and
            manifest['classification'] == CLASSIFICATION and
            manifest['repository'] == REPOSITORY and
            manifest['input_release_id'] == RELEASE_ID and
            manifest['qualification_approved'] is False and manifest['publication_approved'] is False,
            'Candidate manifest identity differs')
    require(manifest['source_evidence_hashes'] == SOURCE_EVIDENCE_HASHES,
            'Candidate manifest source evidence differs')
    require(isinstance(manifest['signing_policy'], dict), 'Candidate signing policy differs')
    execution = {key: manifest[key] for key in EXECUTION_FIELDS - {'signer_image_digest'}}
    execution['signer_image_digest'] = manifest['signing_policy'].get('signer_image_digest')
    validate_execution(execution)
    forbidden = {'manifest_sha256', 'candidate_manifest_sha256', 'artifact_id', 'artifact_url',
                 'artifact_size', 'artifact_zip_sha256', 'transport_receipt_sha256', 'receipt_sha256'}
    def has_forbidden(value):
        if isinstance(value, dict):
            return bool(forbidden & set(value)) or any(has_forbidden(item) for item in value.values())
        if isinstance(value, list):
            return any(has_forbidden(item) for item in value)
        return False
    require(not has_forbidden(manifest), 'Candidate manifest has circular or post-upload fields')
    require(HEX64.fullmatch(manifest['input_manifest_sha256'] or ''),
            'Candidate manifest frozen identity differs')

    assets = manifest['input_assets']
    require(isinstance(assets, list), 'Candidate input assets differ')
    counts = {
        'packages': sum(row.get('kind') == 'package' for row in assets if isinstance(row, dict)),
        'database_and_files': sum(row.get('kind') in ('database', 'files') for row in assets
                                  if isinstance(row, dict)),
        'evidence': sum(row.get('kind') == 'evidence' for row in assets if isinstance(row, dict)),
    }
    reconstructed = {
        'schema': 1, 'classification': CLASSIFICATION, 'repository': REPOSITORY,
        'repository_id': REPOSITORY_ID, 'release_id': RELEASE_ID, 'inputs': assets,
        'expected_counts': counts,
    }
    require(counts == PRODUCTION_COUNTS and
            hashlib.sha256(canonical(reconstructed)).hexdigest() == FROZEN_IDENTITY_SHA256,
            'Candidate input assets differ from frozen production identity')
    packages = {row['package_name']: row for row in assets if row['kind'] == 'package'}
    for name, expected in PRODUCTION_CORE.items():
        require(packages.get(name) is not None and
                all(packages[name][field] == value for field, value in expected.items()),
                'Candidate production RC4 core package identity differs')

    contract = serving_contract(reconstructed)
    require(manifest['served_path_allowlist'] == contract['served_paths'] and
            manifest['evidence_only_paths'] ==
            ['evidence/build-inputs.txt', 'evidence/unsigned-input-manifest.json'],
            'Candidate serving or evidence paths differ')
    by_name = {row['filename']: row for row in assets}
    signatures = manifest['signature_outputs']
    require(isinstance(signatures, list) and
            [row.get('filename') for row in signatures if isinstance(row, dict)] ==
            contract['signature_paths'], 'Candidate signature inventory differs')
    expected_signer = {'primary_fingerprint': PRIMARY_FINGERPRINT,
                       'signing_subkey_fingerprint': SIGNING_SUBKEY_FINGERPRINT}
    signature_inventory = {}
    for row in signatures:
        exact_fields(row, {'filename', 'size', 'sha256', 'signed_input_sha256',
                           'primary_fingerprint', 'signing_subkey_fingerprint'},
                     'Candidate signature output')
        input_name = row['filename'][:-4]
        require(input_name in by_name and type(row['size']) is int and row['size'] > 0 and
                HEX64.fullmatch(row['sha256'] or '') and
                row['signed_input_sha256'] == by_name[input_name]['sha256'] and
                {key: row[key] for key in expected_signer} == expected_signer,
                'Candidate signature output differs')
        signature_inventory['repository/' + row['filename']] = {
            'size': row['size'], 'sha256': row['sha256']}
    require(manifest['signing_policy'] == {
        **expected_signer,
        'public_key_sha256': PUBLIC_KEY_SHA256,
        'signing_policy_sha256': SIGNING_POLICY_SHA256,
        'signer_image_digest': execution['signer_image_digest'],
    }, 'Candidate signing policy differs')

    expected_inventory = {}
    for name in contract['input_paths']:
        row = by_name[name]
        expected_inventory['repository/' + name] = {'size': row['size'], 'sha256': row['sha256']}
    expected_inventory.update(signature_inventory)
    evidence = next(row for row in assets if row['kind'] == 'evidence')
    expected_inventory['evidence/build-inputs.txt'] = {
        'size': evidence['size'], 'sha256': evidence['sha256']}
    unsigned_inventory = manifest['output_inventory'].get('evidence/unsigned-input-manifest.json')
    require(isinstance(unsigned_inventory, dict), 'Candidate unsigned manifest inventory differs')
    exact_fields(unsigned_inventory, {'size', 'sha256'}, 'Candidate unsigned manifest inventory')
    require(type(unsigned_inventory['size']) is int and unsigned_inventory['size'] > 0 and
            unsigned_inventory['sha256'] == manifest['input_manifest_sha256'],
            'Candidate unsigned manifest inventory differs')
    expected_inventory['evidence/unsigned-input-manifest.json'] = unsigned_inventory
    require(manifest['output_inventory'] == dict(sorted(expected_inventory.items())) and
            'candidate-manifest.json' not in manifest['output_inventory'] and
            'transport-receipt.json' not in manifest['output_inventory'],
            'Candidate output inventory differs')


def validate_candidate_directory(candidate_directory, manifest_path, verify_signature):
    """Revalidate exact retained files and signatures against the frozen manifest."""
    root = Path(candidate_directory)
    manifest_path = Path(manifest_path)
    require(root.is_dir() and not root.is_symlink(), 'Candidate directory is unsafe')
    require(manifest_path == root / 'candidate-manifest.json' and
            manifest_path.is_file() and not manifest_path.is_symlink(),
            'Candidate manifest path differs')
    manifest = load_json(manifest_path, 'Candidate manifest')
    validate_candidate_manifest(manifest)
    require({path.name for path in root.iterdir()} == {'repository', 'evidence', 'candidate-manifest.json'},
            'Candidate root inventory differs')
    repository, evidence = root / 'repository', root / 'evidence'
    require(repository.is_dir() and not repository.is_symlink() and
            evidence.is_dir() and not evidence.is_symlink(), 'Candidate paths are unsafe')
    observed = set()
    for prefix, directory in (('repository', repository), ('evidence', evidence)):
        for path in directory.iterdir():
            require(path.is_file() and not path.is_symlink(), 'Candidate output path is unsafe')
            observed.add(prefix + '/' + path.name)
    inventory = manifest['output_inventory']
    require(observed == set(inventory), 'Candidate output inventory differs')
    for relative, expected in inventory.items():
        relative_path = PurePosixPath(relative)
        require(len(relative_path.parts) == 2 and relative_path.parts[0] in ('repository', 'evidence') and
                safe_filename(relative_path.parts[1]), 'Candidate output path differs')
        path = root / relative_path
        require(path.stat().st_size == expected['size'] and digest(path) == expected['sha256'],
                f'Candidate output bytes differ: {relative}')
    validate_unsigned_manifest(
        load_json(evidence / 'unsigned-input-manifest.json', 'Unsigned input manifest'),
        {'inputs': manifest['input_assets'], 'expected_counts': PRODUCTION_COUNTS},
        FROZEN_IDENTITY_SHA256)
    expected_signer = {key: manifest['signing_policy'][key]
                       for key in ('primary_fingerprint', 'signing_subkey_fingerprint')}
    for row in manifest['signature_outputs']:
        path = repository / row['filename'][:-4]
        signature = repository / row['filename']
        verified = verify_signature(path, signature)
        exact_fields(verified, {'primary_fingerprint', 'signing_subkey_fingerprint'}, 'Verified signer')
        require(verified == expected_signer, 'Candidate signature signer differs')
    return manifest


def write_transport_receipt(candidate_manifest_path, transport, output):
    """Bind post-upload transport identity to the already frozen internal manifest."""
    candidate_path = Path(candidate_manifest_path)
    candidate = load_json(candidate_path, 'Candidate manifest')
    validate_candidate_manifest(candidate)
    fields = {'repository_id', 'repository', 'workflow_run_id', 'workflow_run_attempt', 'head_sha',
              'workflow_path', 'workflow_blob_sha', 'artifact_id', 'artifact_name', 'size_in_bytes',
              'artifact_zip_sha256', 'created_at'}
    exact_fields(transport, fields, 'Candidate transport')
    execution = candidate
    require(transport['repository_id'] == REPOSITORY_ID and transport['repository'] == REPOSITORY and
            transport['workflow_run_id'] == execution['workflow_run_id'] and
            transport['workflow_run_attempt'] == execution['workflow_run_attempt'] and
            transport['head_sha'] == execution['workflow_head_sha'] and
            transport['workflow_path'] == execution['workflow_path'] and
            transport['workflow_blob_sha'] == execution['workflow_blob_sha'],
            'Candidate transport execution linkage differs')
    for field in ('artifact_id', 'size_in_bytes'):
        require(type(transport[field]) is int and transport[field] > 0, f'Candidate transport {field} differs')
    expected_name = ('signed-rc4-exact-byte-qualification-fixture-'
                     f'{execution["workflow_run_id"]}-{execution["workflow_run_attempt"]}')
    require(transport['artifact_name'] == expected_name and
            HEX64.fullmatch(transport['artifact_zip_sha256'] or ''),
            'Candidate transport artifact identity differs')
    validate_created_at(transport['created_at'])
    receipt = {'schema': 1, **transport,
               'candidate_manifest_sha256': digest(candidate_path)}
    write_new_json(output, receipt)
    return receipt


def read_secret_part(stream, maximum):
    length_bytes = stream.read(4)
    require(len(length_bytes) == 4, 'Invalid signing secret frame')
    length = struct.unpack('>I', length_bytes)[0]
    require(0 < length <= maximum, 'Invalid signing secret frame')
    value = bytearray(stream.read(length))
    require(len(value) == length, 'Invalid signing secret frame')
    return value


def with_signing_secret(stream, eligibility, signer):
    """Run deterministic eligibility before reading a stdin-only secret frame."""
    validated = eligibility()
    require(not (SECRET_ENV & set(os.environ)), 'Signing secret must not enter signer environment')
    key = password = None
    try:
        key = read_secret_part(stream, 1024 * 1024)
        password = read_secret_part(stream, 16 * 1024)
        require(stream.read(1) == b'', 'Invalid signing secret frame')
        return signer(validated, key, password)
    finally:
        for secret in (key, password):
            if secret is not None:
                secret[:] = b'\x00' * len(secret)


def sign_candidate(identity_path, expected_sha256, metadata_path, input_directory,
                   unsigned_manifest_path, candidate_directory, execution, secret_stream,
                   ring_factory, signing_preflight):
    """Revalidate before secret read, sign exact copies, and freeze an internal manifest."""
    candidate = Path(candidate_directory)
    unsigned = Path(unsigned_manifest_path)

    def eligibility():
        validate_execution(execution)
        require(unsigned.is_file() and not unsigned.is_symlink(), 'Unsigned input manifest is unsafe')
        with tempfile.TemporaryDirectory(prefix='rc4-eligibility-', dir=os.environ.get('TMPDIR')) as directory:
            regenerated = Path(directory) / 'unsigned-input-manifest.json'
            validated = validate_inputs(identity_path, expected_sha256, metadata_path,
                                        input_directory, regenerated, production=True)
            require(regenerated.read_bytes() == unsigned.read_bytes(),
                    'Unsigned input manifest differs after eligibility revalidation')
        require(not candidate.exists() and not candidate.is_symlink(), 'Candidate output must be new')
        bootstrap = signing_preflight(execution['signer_image_digest'])
        require(bootstrap == {
            'primary_fingerprint': PRIMARY_FINGERPRINT,
            'signing_subkey_fingerprint': SIGNING_SUBKEY_FINGERPRINT,
            'public_key_sha256': PUBLIC_KEY_SHA256,
            'signing_policy_sha256': SIGNING_POLICY_SHA256,
        }, 'Signing bootstrap preflight differs')
        return validated

    def sign(validated, key, password):
        del validated
        contract = serving_contract(load_json(identity_path, 'Immutable identity'))
        repository, evidence = candidate / 'repository', candidate / 'evidence'
        repository.mkdir(parents=True)
        evidence.mkdir()
        source = Path(input_directory)
        try:
            for name in contract['input_paths']:
                shutil.copyfile(source / name, repository / name, follow_symlinks=False)
            shutil.copyfile(source / 'build-inputs.txt', evidence / 'build-inputs.txt', follow_symlinks=False)
            shutil.copyfile(unsigned, evidence / 'unsigned-input-manifest.json', follow_symlinks=False)
            ring = ring_factory(key, password)
            try:
                for name in contract['input_paths']:
                    ring.sign(repository / name)
                def verify(path, signature):
                    require(signature == Path(str(path) + '.sig'), 'Signature path differs')
                    ring.verify(path)
                    return {'primary_fingerprint': ring.policy['primary_fingerprint'],
                            'signing_subkey_fingerprint': ring.policy['signing_subkey_fingerprint']}
                return write_candidate_manifest(identity_path, expected_sha256, unsigned, candidate,
                                                execution, verify, candidate / 'candidate-manifest.json')
            finally:
                ring.close()
        except BaseException:
            shutil.rmtree(candidate, ignore_errors=True)
            raise

    return with_signing_secret(secret_stream, eligibility, sign)


def normalize_sha256_digest(value):
    require(isinstance(value, str), 'Artifact transport digest differs')
    normalized = value.removeprefix('sha256:')
    require(HEX64.fullmatch(normalized) is not None, 'Artifact transport digest differs')
    return normalized


def validate_created_at(value):
    # Receipt created_at is the API artifact creation time, not receipt wall-clock time.
    require(isinstance(value, str) and
            re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value),
            'Artifact created_at must be a UTC API timestamp')
    try:
        datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ValueError('Artifact created_at must be a valid UTC API timestamp') from error
    return value


def validate_artifact_transport(metadata, expected_artifact_id, expected_digest, expected_name=None):
    require(isinstance(metadata, dict) and type(expected_artifact_id) is int and
            expected_artifact_id > 0 and type(metadata.get('id')) is int and
            metadata.get('id') == expected_artifact_id and
            type(metadata.get('size_in_bytes')) is int and metadata['size_in_bytes'] > 0 and
            safe_filename(metadata.get('name')) and
            metadata.get('expired') is False, 'Artifact transport identity differs')
    require(expected_name is None or metadata['name'] == expected_name,
            'Artifact transport name differs')
    created_at = validate_created_at(metadata.get('created_at'))
    observed = normalize_sha256_digest(metadata.get('digest'))
    expected = normalize_sha256_digest(expected_digest)
    require(observed == expected, 'Artifact transport digest differs')
    return {'artifact_id': expected_artifact_id, 'artifact_name': metadata['name'],
            'size_in_bytes': metadata['size_in_bytes'], 'artifact_zip_sha256': observed,
            'created_at': created_at}


def github_request(path, token, accept='application/vnd.github+json'):
    require(token, 'GitHub token missing')
    request = urllib.request.Request('https://api.github.com' + path,
                                     headers={'Accept': accept, 'Authorization': 'Bearer ' + token,
                                              'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read()
    except Exception as error:
        detail = type(error).__name__
        status = getattr(error, 'code', None)
        if type(status) is int:
            detail += f' status={status}'
    # Raise outside the handler so tracebacks cannot expose the original response.
    raise ValueError(f'GitHub API request failed: {path} ({detail})')


def acquire_from_github(identity_path, expected_sha256, output, metadata_output):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
            os.environ.get('GITHUB_REPOSITORY') == REPOSITORY and
            os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch',
            'Release acquisition requires the exact hosted manual workflow context')
    token = os.environ.get('GH_TOKEN', '')
    first = json.loads(github_request(
        f'/repos/{REPOSITORY}/releases/{RELEASE_ID}/assets?per_page=100&page=1', token))
    second = json.loads(github_request(
        f'/repos/{REPOSITORY}/releases/{RELEASE_ID}/assets?per_page=100&page=2', token))
    require(isinstance(first, list) and second == [], 'Release asset pagination differs')
    metadata = [{'id': row.get('id'), 'name': row.get('name'), 'size': row.get('size'),
                 'digest': row.get('digest'), 'state': row.get('state')} for row in first]
    def fetch(asset_id):
        return github_request(f'/repos/{REPOSITORY}/releases/assets/{asset_id}', token,
                              'application/octet-stream')
    return acquire_assets(identity_path, expected_sha256, metadata, fetch, output, metadata_output,
                          production=True)


def load_signing_module():
    path = Path(__file__).with_name('package-signing.py')
    spec = importlib.util.spec_from_file_location('rc4_package_signing', path)
    require(spec is not None and spec.loader is not None, 'Signing helper unavailable')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight_signing(signer_image_digest):
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', signer_image_digest or ''),
            'Signer image digest differs')
    signing = load_signing_module()
    return signing.preflight(signing.PUBLIC, signing.POLICY, PUBLIC_KEY_SHA256,
                             SIGNING_POLICY_SHA256, PRIMARY_FINGERPRINT,
                             SIGNING_SUBKEY_FINGERPRINT)


def validate_candidate_public(candidate_directory, manifest_path):
    signing = load_signing_module()
    ring = signing.Keyring(signing.PUBLIC, signing.POLICY, secret=False)
    try:
        def verify(path, signature):
            require(signature == Path(str(path) + '.sig'), 'Signature path differs')
            ring.verify(path)
            return {'primary_fingerprint': ring.policy['primary_fingerprint'],
                    'signing_subkey_fingerprint': ring.policy['signing_subkey_fingerprint']}
        return validate_candidate_directory(candidate_directory, manifest_path, verify)
    finally:
        ring.close()


def write_transport_receipt_checked(candidate_manifest_path, expected_candidate_sha256,
                                    transport, output):
    require(HEX64.fullmatch(expected_candidate_sha256 or '') and
            digest(candidate_manifest_path) == expected_candidate_sha256,
            'Candidate manifest SHA256 differs before receipt')
    return write_transport_receipt(candidate_manifest_path, transport, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--identity', type=Path, required=True)
    common.add_argument('--identity-sha256', required=True)

    acquire = commands.add_parser('acquire', parents=[common], help='Acquire exact numeric release asset IDs')
    acquire.add_argument('--output', type=Path, required=True)
    acquire.add_argument('--metadata', type=Path, required=True)

    validate = commands.add_parser('validate-inputs', parents=[common], help='Validate exact RC4 fixture bytes')
    validate.add_argument('--metadata', type=Path, required=True)
    validate.add_argument('--input', type=Path, required=True)
    validate.add_argument('--output', type=Path, required=True)

    preflight = commands.add_parser('preflight-signing', help='Validate frozen public signing bootstrap')
    preflight.add_argument('--signer-image-digest', required=True)

    candidate_check = commands.add_parser('validate-candidate', help='Revalidate frozen candidate files and signatures')
    candidate_check.add_argument('--candidate', type=Path, required=True)
    candidate_check.add_argument('--candidate-manifest', type=Path, required=True)
    candidate_check.add_argument('--candidate-manifest-sha256', required=True)

    artifact_check = commands.add_parser('validate-artifact-transport',
                                         help='Validate exact artifact ID and transport digest')
    artifact_check.add_argument('--metadata', type=Path, required=True)
    artifact_check.add_argument('--artifact-id', type=int, required=True)
    artifact_check.add_argument('--expected-digest', required=True)
    artifact_check.add_argument('--expected-name', required=True)

    sign = commands.add_parser('sign-candidate', parents=[common], help='Sign and retain; never publish')
    sign.add_argument('--metadata', type=Path, required=True)
    sign.add_argument('--input', type=Path, required=True)
    sign.add_argument('--unsigned-manifest', type=Path, required=True)
    sign.add_argument('--candidate', type=Path, required=True)
    sign.add_argument('--workflow-run-id', type=int, required=True)
    sign.add_argument('--workflow-run-attempt', type=int, required=True)
    sign.add_argument('--workflow-head-sha', required=True)
    sign.add_argument('--workflow-blob-sha', required=True)
    sign.add_argument('--helper-blob-sha', required=True)
    sign.add_argument('--signer-blob-sha', required=True)
    sign.add_argument('--feeder-blob-sha', required=True)
    sign.add_argument('--policy-blob-sha', required=True)
    sign.add_argument('--public-key-blob-sha', required=True)
    sign.add_argument('--signer-image-digest', required=True)
    sign.add_argument('--dockerfile-blob-sha', required=True)
    sign.add_argument('--base-image-digest', required=True)

    receipt = commands.add_parser('write-receipt', help='Bind post-upload transport separately')
    receipt.add_argument('--candidate-manifest', type=Path, required=True)
    receipt.add_argument('--candidate-manifest-sha256', required=True)
    receipt.add_argument('--output', type=Path, required=True)
    receipt.add_argument('--repository-id', type=int, required=True)
    receipt.add_argument('--workflow-run-id', type=int, required=True)
    receipt.add_argument('--workflow-run-attempt', type=int, required=True)
    receipt.add_argument('--head-sha', required=True)
    receipt.add_argument('--workflow-blob-sha', required=True)
    receipt.add_argument('--artifact-id', type=int, required=True)
    receipt.add_argument('--artifact-name', required=True)
    receipt.add_argument('--size-in-bytes', type=int, required=True)
    receipt.add_argument('--artifact-zip-sha256', required=True)
    receipt.add_argument('--expected-artifact-digest', required=True)
    receipt.add_argument('--created-at', required=True)

    args = parser.parse_args()
    if args.command == 'acquire':
        acquire_from_github(args.identity, args.identity_sha256, args.output, args.metadata)
        print('PASS exact numeric-ID RC4 fixture acquisition')
    elif args.command == 'validate-inputs':
        validate_inputs(args.identity, args.identity_sha256, args.metadata, args.input, args.output,
                        production=True)
        print('PASS exact RC4 fixture inputs')
    elif args.command == 'preflight-signing':
        preflight_signing(args.signer_image_digest)
        print('PASS frozen public signing bootstrap and signer toolchain')
    elif args.command == 'validate-candidate':
        require(HEX64.fullmatch(args.candidate_manifest_sha256 or '') and
                digest(args.candidate_manifest) == args.candidate_manifest_sha256,
                'Candidate manifest SHA256 differs during retained-candidate validation')
        validate_candidate_public(args.candidate, args.candidate_manifest)
        print('PASS frozen candidate files, inventory, fingerprints and signatures')
    elif args.command == 'validate-artifact-transport':
        result = validate_artifact_transport(load_json(args.metadata, 'Artifact metadata'),
                                             args.artifact_id, args.expected_digest, args.expected_name)
        print(json.dumps(result, sort_keys=True))
    elif args.command == 'sign-candidate':
        execution = {'repository': REPOSITORY, 'workflow_run_id': args.workflow_run_id,
                     'workflow_run_attempt': args.workflow_run_attempt,
                     'workflow_head_sha': args.workflow_head_sha,
                     'workflow_path': '.github/workflows/sign-and-retain-rc4-fixture.yml',
                     'workflow_blob_sha': args.workflow_blob_sha,
                     'helper_blob_shas': {
                         'scripts/rc4-sign-retain.py': args.helper_blob_sha,
                         'scripts/package-signing.py': args.signer_blob_sha,
                         'scripts/rc4-signing-secret-feeder.py': args.feeder_blob_sha,
                         'pkgbuilds/omarchy-mac-keyring/signing-policy.json': args.policy_blob_sha,
                         'pkgbuilds/omarchy-mac-keyring/omarchy-mac.gpg': args.public_key_blob_sha,
                     },
                     'dockerfile_blob_sha': args.dockerfile_blob_sha,
                     'base_image_digest': args.base_image_digest,
                     'signer_image_digest': args.signer_image_digest}
        signing = load_signing_module()
        def ring_factory(key, password):
            return signing.Keyring(secret=True, secret_material=(key, password))
        def signing_preflight(signer_image_digest):
            require(signer_image_digest == args.signer_image_digest,
                    'Signer image digest changed before secret read')
            return signing.preflight(signing.PUBLIC, signing.POLICY, PUBLIC_KEY_SHA256,
                                     SIGNING_POLICY_SHA256, PRIMARY_FINGERPRINT,
                                     SIGNING_SUBKEY_FINGERPRINT)
        sign_candidate(args.identity, args.identity_sha256, args.metadata, args.input,
                       args.unsigned_manifest, args.candidate, execution, sys.stdin.buffer,
                       ring_factory, signing_preflight)
        print('PASS retained signed RC4 fixture; qualification and publication remain false')
    elif args.command == 'write-receipt':
        artifact_digest = normalize_sha256_digest(args.artifact_zip_sha256)
        require(artifact_digest == normalize_sha256_digest(args.expected_artifact_digest),
                'Artifact transport digest differs')
        transport = {'repository_id': args.repository_id, 'repository': REPOSITORY,
                     'workflow_run_id': args.workflow_run_id,
                     'workflow_run_attempt': args.workflow_run_attempt,
                     'head_sha': args.head_sha,
                     'workflow_path': '.github/workflows/sign-and-retain-rc4-fixture.yml',
                     'workflow_blob_sha': args.workflow_blob_sha, 'artifact_id': args.artifact_id,
                     'artifact_name': args.artifact_name, 'size_in_bytes': args.size_in_bytes,
                     'artifact_zip_sha256': artifact_digest, 'created_at': args.created_at}
        write_transport_receipt_checked(args.candidate_manifest, args.candidate_manifest_sha256,
                                       transport, args.output)
        print('PASS separate RC4 fixture transport receipt')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error))
