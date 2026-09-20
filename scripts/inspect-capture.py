#!/usr/bin/env python3
"""Inspect one recorded capture. Integrity evidence is NOT operator build approval."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

REPO = 'omarchy-mac/omarchy-pkgs-aarch64'
REPOSITORY_ID = 1327386148
CAPTURE_WORKFLOW = '.github/workflows/capture-rc-baseline.yml'


IDENTITY_FIELDS = {'schema', 'repository', 'repository_id', 'run_id', 'run_attempt', 'head_sha',
                   'head_branch', 'workflow_path', 'workflow_blob_sha', 'artifact_id', 'artifact_name',
                   'size_in_bytes', 'zip_sha256', 'approved_databases', 'catalog_sha256',
                   'published_capture', 'unapproved_build_proposal'}
PUBLISHED_FIELDS = {'database_sha256', 'lane_database_sha256', 'archives', 'lane',
                    'filtered_extras', 'manifest_sha256'}
PROPOSAL_FIELDS = {'source_repository', 'source_commit', 'source_version', 'recipe_pin',
                   'pkgrel', 'edge_conversion'}
DISPATCH_FIELDS = {'run_id', 'run_attempt', 'head_sha', 'workflow_blob_sha', 'artifact_id',
                   'artifact_name', 'size_in_bytes', 'zip_sha256'}
SEMANTIC_FIELDS = {'approved_databases', 'catalog_sha256', 'published_capture',
                   'unapproved_build_proposal'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_fields(value, fields, label):
    require(isinstance(value, dict) and set(value) == fields, f'{label} fields differ')


def is_hex(value, length):
    return isinstance(value, str) and re.fullmatch(f'[0-9a-f]{{{length}}}', value) is not None


def load_expected(path):
    """Load one explicit immutable capture identity; no default selection exists."""
    require(path.is_file() and not path.is_symlink(), 'Expected identity must be a regular non-symlink file')
    raw = path.read_bytes()
    try:
        expected = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('Expected identity is not valid JSON') from error
    exact_fields(expected, IDENTITY_FIELDS, 'Expected identity')
    require(type(expected['schema']) is int and expected['schema'] == 1, 'Unsupported expected identity schema')
    require(expected['repository'] == REPO and expected['repository_id'] == REPOSITORY_ID,
            'Expected identity repository differs')
    for field in ('run_id', 'run_attempt', 'artifact_id', 'size_in_bytes'):
        require(type(expected[field]) is int and expected[field] > 0, f'Invalid expected identity {field}')
    require(is_hex(expected['head_sha'], 40), 'Invalid expected capture head SHA')
    require(expected['head_branch'] == 'main', 'Expected capture branch must be main')
    require(expected['workflow_path'] == CAPTURE_WORKFLOW, 'Expected capture workflow path differs')
    require(is_hex(expected['workflow_blob_sha'], 40), 'Invalid expected capture workflow blob SHA')
    require(expected['artifact_name'] ==
            f'rc-baseline-capture-{expected["run_id"]}-{expected["run_attempt"]}',
            'Expected artifact name does not bind run and attempt')
    require(is_hex(expected['zip_sha256'], 64) and is_hex(expected['catalog_sha256'], 64),
            'Invalid expected transport or catalog SHA256')
    approved = expected['approved_databases']
    require(isinstance(approved, dict) and approved and
            set(approved) <= {'edge', 'rc', 'stable'} and
            all(is_hex(value, 64) for value in approved.values()), 'Invalid approved database identities')
    published = expected['published_capture']
    exact_fields(published, PUBLISHED_FIELDS, 'Published capture')
    require(published['lane'] in approved and
            published['lane_database_sha256'] == approved[published['lane']],
            'Published lane database differs from approved identity')
    require(all(is_hex(published[field], 64) for field in
                ('database_sha256', 'lane_database_sha256', 'manifest_sha256')),
            'Invalid published capture SHA256')
    require(type(published['archives']) is int and published['archives'] > 0,
            'Invalid published archive count')
    extras = published['filtered_extras']
    require(isinstance(extras, list) and len(extras) == len(set(extras)) and
            all(isinstance(item, str) and re.fullmatch(r'[A-Za-z0-9@._+-]+', item) for item in extras),
            'Invalid published filtered extras')
    proposal = expected['unapproved_build_proposal']
    exact_fields(proposal, PROPOSAL_FIELDS, 'Unapproved build proposal')
    require(proposal['source_repository'] == 'omarchy-mac/omarchy-mac' and
            is_hex(proposal['source_commit'], 40) and is_hex(proposal['recipe_pin'], 40) and
            isinstance(proposal['source_version'], str) and
            re.fullmatch(r'[A-Za-z0-9._+-]+', proposal['source_version']) and
            isinstance(proposal['pkgrel'], str) and re.fullmatch(r'[1-9][0-9]*', proposal['pkgrel']) and
            type(proposal['edge_conversion']) is bool, 'Invalid unapproved build proposal')
    return expected, hashlib.sha256(raw).hexdigest()


def write_identity(output, dispatch, semantics_text):
    """Convert explicit workflow inputs into one validated identity file."""
    exact_fields(dispatch, DISPATCH_FIELDS, 'Dispatch identity')
    require(all(isinstance(value, str) for value in dispatch.values()),
            'Dispatch identity values must be strings')
    try:
        semantics = json.loads(semantics_text)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError('Expected semantics are not valid JSON') from error
    exact_fields(semantics, SEMANTIC_FIELDS, 'Expected semantics')
    numbers = {}
    for field in ('run_id', 'run_attempt', 'artifact_id', 'size_in_bytes'):
        require(re.fullmatch(r'[1-9][0-9]*', dispatch[field]) is not None,
                f'Invalid dispatch identity {field}')
        numbers[field] = int(dispatch[field])
    identity = {'schema': 1, 'repository': REPO, 'repository_id': REPOSITORY_ID,
                'head_branch': 'main', 'workflow_path': CAPTURE_WORKFLOW,
                **dispatch, **numbers, **semantics}
    raw = (json.dumps(identity, indent=2, sort_keys=True) + '\n').encode()
    require(not output.exists() and not output.is_symlink(), 'Expected identity output must be new')
    output.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix='.expected-identity.', dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(raw)
        load_expected(temporary)
        with output.open('xb') as stream:
            stream.write(raw)
    finally:
        temporary.unlink(missing_ok=True)


def validate_identity(run, artifact, workflow, log, expected):
    """Fail closed on substitution, reruns, expiry or missing published evidence."""
    for field, value in {'id': expected['run_id'], 'run_attempt': expected['run_attempt'],
                         'event': 'workflow_dispatch', 'status': 'completed', 'conclusion': 'success',
                         'path': expected['workflow_path'], 'head_sha': expected['head_sha'],
                         'head_branch': expected['head_branch']}.items():
        require(run.get(field) == value, f'Capture run identity differs: {field}')
    for key in ('repository', 'head_repository'):
        require(run[key]['full_name'] == expected['repository'] and
                run[key]['id'] == expected['repository_id'],
                'Capture must come from the exact same repository, not a fork')
    require(workflow.get('path') == expected['workflow_path'] and
            workflow.get('sha') == expected['workflow_blob_sha'],
            'Capture workflow blob differs at the bound head')
    for field, value in {'id': expected['artifact_id'], 'name': expected['artifact_name'],
                         'size_in_bytes': expected['size_in_bytes'],
                         'digest': 'sha256:' + expected['zip_sha256']}.items():
        require(artifact.get(field) == value, f'Retained artifact identity differs: {field}')
    require(artifact.get('expired') is False, 'Retained artifact expired or expiry state is ambiguous')
    for field, value in {'id': expected['run_id'], 'head_sha': expected['head_sha'],
                         'head_branch': expected['head_branch'],
                         'repository_id': expected['repository_id'],
                         'head_repository_id': expected['repository_id']}.items():
        require(artifact['workflow_run'].get(field) == value, f'Artifact source differs: {field}')
    records = []
    for line in log.splitlines():
        match = re.search(r'(\{"database_sha256":.*\})$', line)
        if match:
            records.append(json.loads(match[1]))
    require(records == [expected['published_capture']], 'Published capture evidence missing, ambiguous or changed')


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def reserve(path, size):
    require(shutil.disk_usage(path).free >= size + 3 * 1024**3, 'Insufficient storage: preserve 3 GiB floor')


def extract_verified_zip(archive, output, checksum, size, max_unpacked=8 * 1024**3):
    """Verify transport bytes before any extraction; reject ambiguous ZIP paths."""
    require(archive.stat().st_size == size and digest(archive) == checksum, 'Artifact ZIP size/digest differs')
    require(not output.exists() and not output.is_symlink(), 'Capture output must be new')
    with zipfile.ZipFile(archive) as z:
        items = z.infolist()
        require(0 < len(items) <= 10000, 'Invalid ZIP member count')
        names = set()
        for item in items:
            name = item.filename
            require(re.fullmatch(r'[A-Za-z0-9_+./@:-]+', name) and not name.startswith('/') and
                    all(part not in ('', '.', '..') for part in name.split('/')), 'Unsafe ZIP path')
            require(name not in names, 'Duplicate ZIP path')
            names.add(name)
            kind = stat.S_IFMT(item.external_attr >> 16)
            require(kind in (0, stat.S_IFREG) and not item.is_dir() and not item.flag_bits & 1,
                    'Only unencrypted regular ZIP files allowed')
        require(not any(parent.as_posix() in names for name in names for parent in Path(name).parents),
                'ZIP file/directory conflict')
        total = sum(item.file_size for item in items)
        require(total <= max_unpacked, 'ZIP unpacked size exceeds limit')
        reserve(output.parent, total)
        output.mkdir()
        for item in items:
            target = output / item.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(item) as source, target.open('xb') as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
            require(target.stat().st_size == item.file_size, 'Extracted ZIP length differs')


def fetch(work, expected_path):
    """Only GET one explicit same-repository run/log/artifact, on GitHub-hosted runners."""
    expected, expected_sha256 = load_expected(expected_path)
    require(all(os.environ.get(key) == value for key, value in {
        'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
        'GITHUB_REPOSITORY': REPO, 'GITHUB_EVENT_NAME': 'workflow_dispatch'}.items()),
        'Full artifact download is restricted to hosted manual inspection')
    require(not work.exists(), 'Use a new inspection workspace')
    work.mkdir(parents=True)
    evidence = work / 'evidence'
    evidence.mkdir()
    def api(path):
        return json.loads(subprocess.run(['gh', 'api', f'repos/{REPO}/{path}'],
                                         check=True, stdout=subprocess.PIPE, timeout=120).stdout)
    run = api(f'actions/runs/{expected["run_id"]}')
    artifact = api(f'actions/artifacts/{expected["artifact_id"]}')
    workflow = api(f'contents/{expected["workflow_path"]}?ref={expected["head_sha"]}')
    log = subprocess.run(['gh', 'run', 'view', str(expected['run_id']), '--repo', REPO,
                          '--attempt', str(expected['run_attempt']), '--log'],
                         check=True, stdout=subprocess.PIPE, timeout=180).stdout.decode()
    validate_identity(run, artifact, workflow, log, expected)
    (evidence / 'expected-identity.json').write_bytes(expected_path.read_bytes())
    (evidence / 'run.json').write_text(json.dumps(run))
    (evidence / 'artifact.json').write_text(json.dumps(artifact))
    (evidence / 'workflow.json').write_text(json.dumps(workflow))
    (evidence / 'capture-run.log').write_text(log)
    # ZIP plus bounded extracted capture; tools are installed before reserving space.
    reserve(work, expected['size_in_bytes'] + 8 * 1024**3)
    archive = work / 'artifact.zip'
    with archive.open('xb') as stream:
        subprocess.run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{expected["artifact_id"]}/zip'],
                       check=True, stdout=stream, timeout=1200)
    extract_verified_zip(archive, work / 'capture', expected['zip_sha256'], expected['size_in_bytes'])
    (evidence / 'transport.json').write_text(json.dumps({
        'zip_sha256': digest(archive), 'size_in_bytes': archive.stat().st_size,
        'artifact_id': expected['artifact_id'], 'expected_identity_sha256': expected_sha256}))
    archive.unlink()


def inspect_capture(capture, expected):
    """Reuse canonical offline semantics; the recorded digest is evidence, not approval."""
    spec = importlib.util.spec_from_file_location('bootstrap_inspection', Path(__file__).with_name('bootstrap-rc.py'))
    assert spec is not None and spec.loader is not None
    boot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boot)
    recorded = expected['published_capture']['manifest_sha256']
    evidence = boot.check_capture(capture, recorded)
    actual = digest(capture / 'capture-manifest.json')
    primary_lane = expected['published_capture']['lane']
    overlay_lanes = set(expected['approved_databases']) - {primary_lane}
    require(len(overlay_lanes) <= 1, 'Expected database identities have ambiguous overlay lanes')
    expected_overlay = next(iter(overlay_lanes), 'none')
    require(evidence['lane'] == primary_lane and evidence['overlay_lane'] == expected_overlay,
            'Recorded capture lanes differ')
    for lane, checksum in expected['approved_databases'].items():
        require(digest(capture / 'sources' / f'{lane}.db') == checksum,
                f'Independently approved {lane} database differs')
    require(digest(capture / 'catalog.json') == expected['catalog_sha256'],
            'Frozen catalog differs from capture source commit')
    for key, value in expected['published_capture'].items():
        require((actual if key == 'manifest_sha256' else evidence[key]) == value,
                f'Published capture differs: {key}')
    rows = boot.bundle.database(capture / 'omarchy-aarch64.db')
    catalog = sorted(p['name'] for p in json.loads((capture / 'catalog.json').read_text())['packages'])
    require(set(catalog) == set(rows), 'Complete catalog required for this inspection')
    packages = [{'name': name, 'version': boot.bundle.field(rows[name], 'VERSION'), **item}
                for name, item in sorted(evidence['selected'].items())]
    origins = {lane: sum(p['lane'] == lane for p in packages) for lane in sorted({p['lane'] for p in packages})}
    provenance = {}
    keys = ('source_commit', 'source_version', 'source_dirty', 'recipe_pin')
    for lane in expected['approved_databases']:
        path = capture / 'sources' / f'{lane}-build-inputs.txt'
        if path.exists():
            values = {key: re.findall(r'^' + key + r'=(.*)$', path.read_text(), re.MULTILINE) for key in keys}
            provenance[lane] = {'sha256': digest(path), 'claims': values,
                                'qualification': 'Retained claims only; not authenticated build provenance'}
    proposal = dict(expected['unapproved_build_proposal'])
    proposal_lane = 'rc' if 'rc' in provenance else primary_lane
    claims = provenance.get(proposal_lane, {}).get('claims', {})
    corroborated = all(claims.get(key) == [proposal[key]] for key in ('source_commit', 'source_version', 'recipe_pin'))
    corroborated = corroborated and claims.get('source_dirty') == ['0']
    pair_filenames = [f'{name}-{proposal["source_version"]}-{proposal["pkgrel"]}-aarch64.pkg.tar.xz'
                      for name in ('omarchy', 'omarchy-settings')]
    collisions = {lane: sorted(set(pair_filenames) & set(assets)) for lane, assets in evidence['remote_assets'].items()}
    proposal.update(approved=False, capture_run_id=expected['run_id'],
                    capture_artifact_name=expected['artifact_name'],
                    capture_manifest_sha256=actual, retained_rc_provenance_corroborates=corroborated,
                    expected_pair_filenames=pair_filenames, observed_pair_filename_collisions=collisions)
    return {'schema': 1, 'scope': 'inspection-only; no build, signing, publication or runtime qualification',
            'repository': REPO, 'capture_run_id': expected['run_id'],
            'capture_artifact_id': expected['artifact_id'],
            'actual_capture_manifest_sha256': actual,
            'manifest_identity': 'matches explicit expected capture record; NOT operator approval',
            'build_approved': False, 'approved_source_databases': expected['approved_databases'],
            'catalog_sha256': digest(capture / 'catalog.json'), 'catalog_count': len(catalog),
            'package_count': len(packages), 'origin_counts': origins, 'packages': packages,
            'excluded_catalog_extras': evidence['excluded_catalog_extras'],
            'remote_observation_counts': {lane: {
                status: sum(item['verification'] == status for item in assets.values())
                for status in ('metadata-only', 'downloaded-verified')}
                for lane, assets in evidence['remote_assets'].items()},
            'retained_provenance': provenance, 'build_proposal': proposal,
            'outstanding_gates': [
                'Operator must separately approve the capture manifest and exact source_commit/pkgrel/edge_conversion inputs.',
                'Do not dispatch preparation from this report; retain protected environment approval.',
                'Stop if RC provenance does not corroborate the proposal or a proposed filename is already observed.',
                'New pkgrel changes only the desktop pair; extra-package reuse still requires functional/trust comparison.',
                'Metadata-only observations and historical filename absence are not current remote-byte/collision verification.',
                'Build, runtime qualification, signing and publication remain separate authorizations.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    writer = commands.add_parser('write-identity', help='Validate explicit dispatch inputs into one identity file')
    writer.add_argument('--output', type=Path, required=True)
    for field in sorted(DISPATCH_FIELDS):
        writer.add_argument('--' + field.replace('_', '-'), required=True)
    writer.add_argument('--expected-semantics-json', required=True)
    download = commands.add_parser('fetch', help='Hosted-only exact retained artifact download')
    download.add_argument('--expected', type=Path, required=True)
    download.add_argument('--work', type=Path, required=True)
    inspect = commands.add_parser('inspect', help='Offline inspection; never operator approval')
    inspect.add_argument('--expected', type=Path, required=True)
    inspect.add_argument('--capture', type=Path, required=True)
    inspect.add_argument('--evidence', type=Path, required=True)
    inspect.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'write-identity':
        dispatch = {field: getattr(args, field) for field in DISPATCH_FIELDS}
        write_identity(args.output, dispatch, args.expected_semantics_json)
    elif args.command == 'fetch':
        fetch(args.work, args.expected)
    else:
        expected, expected_sha256 = load_expected(args.expected)
        run = json.loads((args.evidence / 'run.json').read_text())
        artifact = json.loads((args.evidence / 'artifact.json').read_text())
        workflow = json.loads((args.evidence / 'workflow.json').read_text())
        log = (args.evidence / 'capture-run.log').read_text()
        validate_identity(run, artifact, workflow, log, expected)
        transport = json.loads((args.evidence / 'transport.json').read_text())
        expected_transport = {key: expected[key] for key in ('zip_sha256', 'size_in_bytes', 'artifact_id')}
        expected_transport['expected_identity_sha256'] = expected_sha256
        require(transport == expected_transport, 'Missing or inconsistent verified ZIP transfer evidence')
        report = inspect_capture(args.capture, expected)
        report['expected_identity_sha256'] = expected_sha256
        report['transport'] = transport
        report['capture_run_url'] = f'https://github.com/{REPO}/actions/runs/{expected["run_id"]}'
        text = json.dumps(report, indent=2, sort_keys=True) + '\n'
        require(len(text.encode()) <= 256 * 1024, 'Inspection report exceeds reviewable size limit')
        with args.report.open('x') as stream:
            stream.write(text)


if __name__ == '__main__':
    main()
