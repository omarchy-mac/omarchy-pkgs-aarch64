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
import zipfile

REPO = 'omarchy-mac/omarchy-pkgs-aarch64'
EXPECTED = json.loads(Path(__file__).with_name('retained-capture-35445613014.json').read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_identity(run, artifact, log):
    """Fail closed on substitution, reruns, expiry or missing published evidence."""
    for field, value in {'id': EXPECTED['run_id'], 'run_attempt': EXPECTED['run_attempt'],
                         'event': 'workflow_dispatch', 'status': 'completed', 'conclusion': 'success',
                         'path': '.github/workflows/capture-rc-baseline.yml',
                         'head_sha': EXPECTED['head_sha'], 'head_branch': 'main'}.items():
        require(run.get(field) == value, f'Capture run identity differs: {field}')
    for key in ('repository', 'head_repository'):
        require(run[key]['full_name'] == REPO and run[key]['id'] == EXPECTED['repository_id'],
                'Capture must come from the exact same repository, not a fork')
    for field, value in {'id': EXPECTED['artifact_id'], 'name': EXPECTED['artifact_name'],
                         'size_in_bytes': EXPECTED['size_in_bytes'],
                         'digest': 'sha256:' + EXPECTED['zip_sha256']}.items():
        require(artifact.get(field) == value, f'Retained artifact identity differs: {field}')
    require(artifact.get('expired') is False, 'Retained artifact expired')
    for field, value in {'id': EXPECTED['run_id'], 'head_sha': EXPECTED['head_sha'],
                         'head_branch': 'main', 'repository_id': EXPECTED['repository_id'],
                         'head_repository_id': EXPECTED['repository_id']}.items():
        require(artifact['workflow_run'].get(field) == value, f'Artifact source differs: {field}')
    records = []
    for line in log.splitlines():
        match = re.search(r'(\{"database_sha256":.*\})$', line)
        if match:
            records.append(json.loads(match[1]))
    require(records == [EXPECTED['published_capture']], 'Published capture evidence missing, ambiguous or changed')


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


def fetch(work):
    """Only GET the fixed same-repository run/log/artifact, on GitHub-hosted runners."""
    require(all(os.environ.get(key) == value for key, value in {
        'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
        'GITHUB_REPOSITORY': REPO, 'GITHUB_EVENT_NAME': 'workflow_dispatch'}.items()),
        'Full artifact download is restricted to hosted manual inspection')
    require(not work.exists(), 'Use a new inspection workspace')
    work.mkdir(parents=True)
    evidence = work / 'evidence'
    evidence.mkdir()
    endpoint = f'repos/{REPO}/actions'
    def api(path):
        return json.loads(subprocess.run(['gh', 'api', f'{endpoint}/{path}'],
                                         check=True, stdout=subprocess.PIPE, timeout=120).stdout)
    run = api(f'runs/{EXPECTED["run_id"]}')
    artifact = api(f'artifacts/{EXPECTED["artifact_id"]}')
    log = subprocess.run(['gh', 'run', 'view', str(EXPECTED['run_id']), '--repo', REPO,
                          '--attempt', str(EXPECTED['run_attempt']), '--log'],
                         check=True, stdout=subprocess.PIPE, timeout=180).stdout.decode()
    validate_identity(run, artifact, log)
    (evidence / 'run.json').write_text(json.dumps(run))
    (evidence / 'artifact.json').write_text(json.dumps(artifact))
    (evidence / 'capture-run.log').write_text(log)
    # ZIP plus bounded extracted capture; tools are installed before reserving space.
    reserve(work, EXPECTED['size_in_bytes'] + 8 * 1024**3)
    archive = work / 'artifact.zip'
    with archive.open('xb') as stream:
        subprocess.run(['gh', 'api', f'{endpoint}/artifacts/{EXPECTED["artifact_id"]}/zip'],
                       check=True, stdout=stream, timeout=1200)
    extract_verified_zip(archive, work / 'capture', EXPECTED['zip_sha256'], EXPECTED['size_in_bytes'])
    (evidence / 'transport.json').write_text(json.dumps({
        'zip_sha256': digest(archive), 'size_in_bytes': archive.stat().st_size,
        'artifact_id': EXPECTED['artifact_id']}))
    archive.unlink()


def inspect_capture(capture):
    """Reuse canonical offline semantics; the recorded digest is evidence, not approval."""
    spec = importlib.util.spec_from_file_location('bootstrap_inspection', Path(__file__).with_name('bootstrap-rc.py'))
    assert spec is not None and spec.loader is not None
    boot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boot)
    recorded = EXPECTED['published_capture']['manifest_sha256']
    evidence = boot.check_capture(capture, recorded)
    actual = digest(capture / 'capture-manifest.json')
    require(evidence['lane'] == 'edge' and evidence['overlay_lane'] == 'rc', 'Recorded capture lanes differ')
    for lane, checksum in EXPECTED['approved_databases'].items():
        require(digest(capture / 'sources' / f'{lane}.db') == checksum,
                f'Independently approved {lane} database differs')
    require(digest(capture / 'catalog.json') == EXPECTED['catalog_sha256'], 'Frozen catalog differs from capture source commit')
    for key, value in EXPECTED['published_capture'].items():
        require((actual if key == 'manifest_sha256' else evidence[key]) == value, f'Published capture differs: {key}')
    rows = boot.bundle.database(capture / 'omarchy-aarch64.db')
    catalog = sorted(p['name'] for p in json.loads((capture / 'catalog.json').read_text())['packages'])
    require(set(catalog) == set(rows), 'Complete catalog required for this inspection')
    packages = [{'name': name, 'version': boot.bundle.field(rows[name], 'VERSION'), **item}
                for name, item in sorted(evidence['selected'].items())]
    origins = {lane: sum(p['lane'] == lane for p in packages) for lane in sorted({p['lane'] for p in packages})}
    provenance = {}
    keys = ('source_commit', 'source_version', 'source_dirty', 'recipe_pin')
    for lane in ('edge', 'rc'):
        path = capture / 'sources' / f'{lane}-build-inputs.txt'
        if path.exists():
            values = {key: re.findall(r'^' + key + r'=(.*)$', path.read_text(), re.MULTILINE) for key in keys}
            provenance[lane] = {'sha256': digest(path), 'claims': values,
                                'qualification': 'Retained claims only; not authenticated build provenance'}
    proposal = dict(EXPECTED['unapproved_build_proposal'])
    claims = provenance.get('rc', {}).get('claims', {})
    corroborated = all(claims.get(key) == [proposal[key]] for key in ('source_commit', 'source_version', 'recipe_pin'))
    corroborated = corroborated and claims.get('source_dirty') == ['0']
    pair_filenames = [f'{name}-{proposal["source_version"]}-{proposal["pkgrel"]}-aarch64.pkg.tar.xz'
                      for name in ('omarchy', 'omarchy-settings')]
    collisions = {lane: sorted(set(pair_filenames) & set(assets)) for lane, assets in evidence['remote_assets'].items()}
    proposal.update(approved=False, capture_run_id=EXPECTED['run_id'], capture_artifact_name=EXPECTED['artifact_name'],
                    capture_manifest_sha256=actual, retained_rc_provenance_corroborates=corroborated,
                    expected_pair_filenames=pair_filenames, observed_pair_filename_collisions=collisions)
    return {'schema': 1, 'scope': 'inspection-only; no build, signing, publication or runtime qualification',
            'repository': REPO, 'capture_run_id': EXPECTED['run_id'], 'capture_artifact_id': EXPECTED['artifact_id'],
            'actual_capture_manifest_sha256': actual, 'manifest_identity': 'matches published capture record; NOT operator approval',
            'build_approved': False, 'approved_source_databases': EXPECTED['approved_databases'],
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
    download = commands.add_parser('fetch', help='Hosted-only exact retained artifact download')
    download.add_argument('--work', type=Path, required=True)
    inspect = commands.add_parser('inspect', help='Offline inspection; never operator approval')
    inspect.add_argument('--capture', type=Path, required=True)
    inspect.add_argument('--evidence', type=Path, required=True)
    inspect.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'fetch':
        fetch(args.work)
    else:
        run = json.loads((args.evidence / 'run.json').read_text())
        artifact = json.loads((args.evidence / 'artifact.json').read_text())
        log = (args.evidence / 'capture-run.log').read_text()
        validate_identity(run, artifact, log)
        transport = json.loads((args.evidence / 'transport.json').read_text())
        require(transport == {key: EXPECTED[key] for key in ('zip_sha256', 'size_in_bytes', 'artifact_id')},
                'Missing or inconsistent verified ZIP transfer evidence')
        report = inspect_capture(args.capture)
        report['transport'] = transport
        report['capture_run_url'] = f'https://github.com/{REPO}/actions/runs/{EXPECTED["run_id"]}'
        text = json.dumps(report, indent=2, sort_keys=True) + '\n'
        require(len(text.encode()) <= 256 * 1024, 'Inspection report exceeds reviewable size limit')
        with args.report.open('x') as stream:
            stream.write(text)


if __name__ == '__main__':
    main()
