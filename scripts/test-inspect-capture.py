#!/usr/bin/env python3
"""Small retained-inspection regressions; never download production artifacts."""
from pathlib import Path
import copy
import importlib.util
import unittest
import yaml


def inspector(test):
    path = ROOT / 'scripts/inspect-capture.py'
    test.assertTrue(path.exists(), 'Missing retained artifact inspector')
    spec = importlib.util.spec_from_file_location('inspector', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def explicit_identity(module):
    import json
    identity = json.loads((ROOT / 'scripts/retained-capture-35445613014.json').read_text())
    identity.update(schema=1, repository=module.REPO, head_branch='main',
                    workflow_path='.github/workflows/capture-rc-baseline.yml',
                    workflow_blob_sha='f' * 40)
    return identity


class IdentitySchemaTests(unittest.TestCase):
    def test_writer_builds_validated_identity_without_defaults(self):
        import json
        import tempfile
        module = inspector(self)
        self.assertTrue(hasattr(module, 'write_identity'), 'Missing validated identity writer')
        identity = explicit_identity(module)
        dispatch = {key: str(identity[key]) for key in
                    ('run_id', 'run_attempt', 'head_sha', 'workflow_blob_sha', 'artifact_id',
                     'artifact_name', 'size_in_bytes', 'zip_sha256')}
        semantics = {key: identity[key] for key in
                     ('approved_databases', 'catalog_sha256', 'published_capture',
                      'unapproved_build_proposal')}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'expected.json'
            module.write_identity(output, dispatch, json.dumps(semantics))
            loaded, _ = module.load_expected(output)
            self.assertEqual(loaded, identity)
            semantics['unexpected'] = True
            with self.assertRaises(ValueError):
                module.write_identity(Path(directory) / 'bad.json', dispatch, json.dumps(semantics))
            self.assertFalse((Path(directory) / 'bad.json').exists())

    def test_expected_identity_file_is_mandatory_exact_and_digest_bound(self):
        import hashlib
        import json
        import tempfile
        module = inspector(self)
        self.assertTrue(hasattr(module, 'load_expected'), 'Missing explicit expected-identity loader')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'expected-identity.json'
            identity = explicit_identity(module)
            path.write_text(json.dumps(identity, sort_keys=True) + '\n')
            loaded, checksum = module.load_expected(path)
            self.assertEqual(loaded, identity)
            self.assertEqual(checksum, hashlib.sha256(path.read_bytes()).hexdigest())
            for label, change in (
                    ('schema', lambda value: value.update(schema=2)),
                    ('missing', lambda value: value.pop('artifact_id')),
                    ('extra', lambda value: value.update(unexpected=True)),
                    ('nested-extra', lambda value: value['published_capture'].update(unexpected=True)),
                    ('workflow-blob', lambda value: value.update(workflow_blob_sha='0' * 39))):
                changed = copy.deepcopy(identity); change(changed)
                path.write_text(json.dumps(changed))
                with self.subTest(label=label), self.assertRaises(ValueError):
                    module.load_expected(path)


class IdentityTests(unittest.TestCase):
    def test_exact_identity_and_published_log_are_required(self):
        import inspect
        module = inspector(self)
        self.assertEqual(tuple(inspect.signature(module.validate_identity).parameters),
                         ('run', 'artifact', 'workflow', 'log', 'expected'),
                         'Identity validation must require an explicit workflow and expected identity')
        expected = explicit_identity(module)
        repo = {'id': expected['repository_id'], 'full_name': module.REPO}
        run = {'id': expected['run_id'], 'run_attempt': expected['run_attempt'], 'event': 'workflow_dispatch',
               'path': expected['workflow_path'], 'head_branch': expected['head_branch'],
               'head_sha': expected['head_sha'], 'status': 'completed', 'conclusion': 'success',
               'repository': repo, 'head_repository': repo}
        artifact = {'id': expected['artifact_id'], 'name': expected['artifact_name'],
                    'size_in_bytes': expected['size_in_bytes'], 'expired': False,
                    'digest': 'sha256:' + expected['zip_sha256'],
                    'workflow_run': {'id': expected['run_id'], 'head_sha': expected['head_sha'],
                                     'repository_id': expected['repository_id'],
                                     'head_repository_id': expected['repository_id'],
                                     'head_branch': expected['head_branch']}}
        workflow = {'path': expected['workflow_path'], 'sha': expected['workflow_blob_sha']}
        import json
        log = 'capture\tCapture step\t2026-09-19T13:27:17Z ' + json.dumps(expected['published_capture'])
        module.validate_identity(run, artifact, workflow, log, expected)
        for field, value in [('id', 1), ('run_attempt', 2), ('event', 'pull_request'),
                             ('status', 'in_progress'), ('conclusion', 'failure'),
                             ('head_sha', '0'*40), ('head_branch', 'other'),
                             ('path', '.github/workflows/other.yml'),
                             ('repository', {'id': 1, 'full_name': module.REPO}),
                             ('head_repository', {'id': 1, 'full_name': module.REPO})]:
            bad = copy.deepcopy(run); bad[field] = value
            with self.subTest(run=field), self.assertRaises((ValueError, KeyError)):
                module.validate_identity(bad, artifact, workflow, log, expected)
        for field, value in [('id', 1), ('name', 'wrong'), ('size_in_bytes', 1),
                             ('digest', 'sha256:'+'0'*64), ('expired', True), ('expired', None)]:
            bad = copy.deepcopy(artifact); bad[field] = value
            with self.subTest(artifact=field, value=value), self.assertRaises((ValueError, KeyError)):
                module.validate_identity(run, bad, workflow, log, expected)
        for field, value in [('id', 2), ('head_sha', '0'*40), ('head_branch', 'other'),
                             ('repository_id', 1), ('head_repository_id', 1)]:
            bad = copy.deepcopy(artifact); bad['workflow_run'][field] = value
            with self.subTest(linkage=field), self.assertRaises((ValueError, KeyError)):
                module.validate_identity(run, bad, workflow, log, expected)
        for field, value in [('path', '.github/workflows/other.yml'), ('sha', '0'*40)]:
            bad = copy.deepcopy(workflow); bad[field] = value
            with self.subTest(workflow=field), self.assertRaises(ValueError):
                module.validate_identity(run, artifact, bad, log, expected)
        for bad in ['', log.replace(expected['published_capture']['manifest_sha256'], '0'*64), log+'\n'+log]:
            with self.subTest(log=bad), self.assertRaises(ValueError):
                module.validate_identity(run, artifact, workflow, bad, expected)
        changed = copy.deepcopy(expected); changed['head_sha'] = '0' * 40
        with self.assertRaises(ValueError):
            module.validate_identity(run, artifact, workflow, log, changed)


class InspectionTests(unittest.TestCase):
    def test_real_tiny_capture_rejects_self_consistent_substitution_and_reports_origins(self):
        import hashlib
        import io
        import json
        import tarfile
        import tempfile
        from unittest.mock import patch
        import inspect
        module = inspector(self)
        self.assertEqual(tuple(inspect.signature(module.inspect_capture).parameters), ('capture', 'expected'),
                         'Offline inspection must require an explicit expected identity')
        expected = explicit_identity(module)
        self.assertTrue(hasattr(module, 'inspect_capture'), 'Missing offline semantic inspection/report')
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)/'capture'; capture.mkdir()
            (capture/'sources').mkdir(); (capture/'packages').mkdir()
            def sha(path):
                return hashlib.sha256(path.read_bytes()).hexdigest()
            def archive(path, entries):
                with tarfile.open(path, 'w:gz') as tar:
                    for name, data in entries.items():
                        content = data.encode(); item = tarfile.TarInfo(name); item.size = len(content)
                        tar.addfile(item, io.BytesIO(content))
            def write_json(path, data):
                path.write_text(json.dumps(data))
            rows, selected = {}, {}
            for name in ('omarchy', 'omarchy-settings', 'omarchy-mac-keyring'):
                filename = name+'-4.0.3rc4-1-aarch64.pkg.tar.gz'
                path = capture/'packages'/filename
                archive(path, {'.PKGINFO': f'pkgname = {name}\npkgver = 4.0.3rc4-1\narch = aarch64\n'})
                fields = {'NAME': name, 'VERSION': '4.0.3rc4-1', 'ARCH': 'aarch64',
                          'FILENAME': filename, 'CSIZE': str(path.stat().st_size), 'SHA256SUM': sha(path)}
                rows[name+'/desc'] = ''.join(f'%{key}%\n{value}\n\n' for key, value in fields.items())
                selected[name] = {'lane': 'rc', 'filename': filename, 'sha256': sha(path)}
            write_json(capture/'catalog.json', {'packages': [{'name': n} for n in selected]})
            for filename in ('sources/edge.db', 'sources/rc.db', 'omarchy-aarch64.db',
                             'omarchy-aarch64.db.tar.zst', 'omarchy-aarch64.files', 'omarchy-aarch64.files.tar.zst'):
                archive(capture/filename, rows)
            # The format is read by libarchive, not inferred from the suffix.
            for alias in ('omarchy-aarch64.db.tar.zst', 'omarchy-aarch64.files', 'omarchy-aarch64.files.tar.zst'):
                (capture/alias).write_bytes((capture/'omarchy-aarch64.db').read_bytes())
            proposal = expected['unapproved_build_proposal']
            (capture/'sources/rc-build-inputs.txt').write_text('\n'.join(
                f'{k}={proposal[k]}' for k in ('source_commit', 'source_version', 'recipe_pin'))+'\nsource_dirty=0\n')
            evidence = {'lane': 'edge', 'overlay_lane': 'rc', 'archives': len(selected),
                        'database_sha256': sha(capture/'omarchy-aarch64.db'),
                        'lane_database_sha256': sha(capture/'sources/edge.db'),
                        'overlay_database_sha256': sha(capture/'sources/rc.db'),
                        'selected': selected, 'filtered_extras': [], 'excluded_catalog_extras': {'edge': [], 'rc': []},
                        'remote_assets': {}}
            for lane in ('edge', 'rc'):
                observed = {}
                for db in ('omarchy-aarch64.db', 'omarchy-aarch64.db.tar.zst'):
                    observed[db] = {'classification': 'database', 'verification': 'downloaded-verified',
                                    'metadata': {}, 'path': f'sources/{lane}.db', 'sha256': sha(capture/f'sources/{lane}.db')}
                if lane == 'rc':
                    observed['build-inputs.txt'] = {'classification': 'provenance', 'verification': 'downloaded-verified',
                        'metadata': {}, 'path': 'sources/rc-build-inputs.txt', 'sha256': sha(capture/'sources/rc-build-inputs.txt')}
                evidence['remote_assets'][lane] = observed
            def manifest():
                write_json(capture/'capture-manifest.json', {'schema': 1, 'files': {
                    p.relative_to(capture).as_posix(): sha(p) for p in capture.rglob('*')
                    if p.is_file() and p.name != 'capture-manifest.json'}})
            write_json(capture/'capture.json', evidence); manifest()
            expected['published_capture'] = {k: evidence[k] for k in ('database_sha256', 'lane_database_sha256', 'archives', 'lane', 'filtered_extras')}
            expected['published_capture']['manifest_sha256'] = sha(capture/'capture-manifest.json')
            expected['catalog_sha256'] = sha(capture/'catalog.json')
            expected['approved_databases'] = {lane: sha(capture/f'sources/{lane}.db') for lane in ('edge', 'rc')}
            self.assertFalse(hasattr(module, 'EXPECTED'), 'Inspection must not expose an implicit EXPECTED identity')
            report = module.inspect_capture(capture, expected)
            self.assertEqual(report['actual_capture_manifest_sha256'], sha(capture/'capture-manifest.json'))
            self.assertFalse(report['build_approved'])
            self.assertEqual(report['origin_counts'], {'rc': 3})
            self.assertEqual(len(report['packages']), 3)
            self.assertEqual(report['build_proposal']['source_commit'], proposal['source_commit'])
            self.assertFalse(report['build_proposal']['edge_conversion'])
            self.assertTrue(report['build_proposal']['retained_rc_provenance_corroborates'])
            # Full orchestration with fixture ZIP/API responses, never a production download.
            import subprocess
            import sys
            import zipfile
            zip_path = Path(directory)/'fixture.zip'
            with zipfile.ZipFile(zip_path, 'w') as z:
                for file in capture.rglob('*'):
                    if file.is_file():
                        z.write(file, file.relative_to(capture).as_posix())
            expected['zip_sha256'] = sha(zip_path)
            expected['size_in_bytes'] = zip_path.stat().st_size
            expected_path = Path(directory)/'expected-identity.json'
            write_json(expected_path, expected)
            expected_identity_sha256 = sha(expected_path)
            repo = {'id': expected['repository_id'], 'full_name': module.REPO}
            run_data = {'id': expected['run_id'], 'run_attempt': expected['run_attempt'],
                        'event': 'workflow_dispatch', 'status': 'completed', 'conclusion': 'success',
                        'head_branch': expected['head_branch'], 'head_sha': expected['head_sha'],
                        'path': expected['workflow_path'], 'repository': repo, 'head_repository': repo}
            artifact_data = {'id': expected['artifact_id'], 'name': expected['artifact_name'],
                             'size_in_bytes': expected['size_in_bytes'], 'expired': False,
                             'digest': 'sha256:'+expected['zip_sha256'],
                             'workflow_run': {'id': expected['run_id'], 'head_sha': expected['head_sha'],
                                              'head_branch': expected['head_branch'],
                                              'repository_id': expected['repository_id'],
                                              'head_repository_id': expected['repository_id']}}
            workflow_data = {'path': expected['workflow_path'], 'sha': expected['workflow_blob_sha']}
            def fake_github(command, **kwargs):
                if command[-1].endswith('/zip'):
                    kwargs['stdout'].write(zip_path.read_bytes())
                    return subprocess.CompletedProcess(command, 0)
                if command[1] == 'run':
                    data = json.dumps(expected['published_capture']).encode()
                elif '/contents/' in command[-1]:
                    data = json.dumps(workflow_data).encode()
                else:
                    data = json.dumps(run_data if '/runs/' in command[-1] else artifact_data).encode()
                return subprocess.CompletedProcess(command, 0, stdout=data)
            work = Path(directory)/'download'
            with patch.dict(module.os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                    'GITHUB_REPOSITORY': module.REPO, 'GITHUB_EVENT_NAME': 'workflow_dispatch'}, clear=True), \
                    patch.object(module.subprocess, 'run', side_effect=fake_github), patch.object(module, 'reserve'):
                module.fetch(work, expected_path)
            self.assertFalse((work/'artifact.zip').exists())
            report_path = Path(directory)/'report.json'
            argv = ['inspect-capture.py', 'inspect', '--expected', str(work/'evidence/expected-identity.json'),
                    '--capture', str(work/'capture'), '--evidence', str(work/'evidence'),
                    '--report', str(report_path)]
            with patch.object(sys, 'argv', argv):
                module.main()
            saved = json.loads(report_path.read_text())
            self.assertEqual(saved['transport']['zip_sha256'], expected['zip_sha256'])
            self.assertEqual(saved['transport']['expected_identity_sha256'], expected_identity_sha256)
            self.assertEqual(saved['expected_identity_sha256'], expected_identity_sha256)
            self.assertEqual(saved['actual_capture_manifest_sha256'], expected['published_capture']['manifest_sha256'])
            self.assertFalse(saved['build_approved'])
            # Independent approved DBs are checked even if self-consistent captured hashes agree.
            expected['approved_databases']['rc'] = '0'*64
            with self.assertRaisesRegex(ValueError, 'approved.*database'):
                module.inspect_capture(capture, expected)
            expected['approved_databases']['rc'] = sha(capture/'sources/rc.db')
            # A changed origin plus freshly computed manifest must still fail semantic checking.
            evidence['selected']['omarchy']['lane'] = 'edge'
            write_json(capture/'capture.json', evidence); manifest()
            expected['published_capture']['manifest_sha256'] = sha(capture/'capture-manifest.json')
            with self.assertRaisesRegex(ValueError, 'origins'):
                module.inspect_capture(capture, expected)
            evidence['selected']['omarchy']['lane'] = 'rc'
            write_json(capture/'capture.json', evidence); manifest()
            expected['published_capture']['manifest_sha256'] = sha(capture/'capture-manifest.json')
            (capture/'unexpected').write_text('tamper')
            with self.assertRaisesRegex(ValueError, 'inventory'):
                module.inspect_capture(capture, expected)

class FetchTests(unittest.TestCase):
    def test_fetch_refuses_local_execution_and_bad_metadata_before_download(self):
        import inspect
        import json
        import tempfile
        from unittest.mock import patch
        module = inspector(self)
        self.assertTrue(hasattr(module, 'fetch'), 'Missing hosted-only fetch orchestration')
        self.assertEqual(tuple(inspect.signature(module.fetch).parameters), ('work', 'expected_path'),
                         'Fetch must require an explicit expected-identity path')
        with tempfile.TemporaryDirectory() as directory, patch.object(module.subprocess, 'run') as run:
            expected_path = Path(directory) / 'expected-identity.json'
            expected_path.write_text(json.dumps(explicit_identity(module)))
            with patch.dict(module.os.environ, {}, clear=True), self.assertRaises(ValueError):
                module.fetch(Path(directory)/'work', expected_path)
            run.assert_not_called()
            env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                   'GITHUB_REPOSITORY': module.REPO, 'GITHUB_EVENT_NAME': 'workflow_dispatch'}
            run.return_value.stdout = b'{}'
            with patch.dict(module.os.environ, env, clear=True), self.assertRaises((ValueError, KeyError)):
                module.fetch(Path(directory)/'work', expected_path)
            self.assertFalse(any('/zip' in str(call) for call in run.call_args_list))


class ArchiveTests(unittest.TestCase):
    def test_zip_digest_size_inventory_and_safe_extraction(self):
        import hashlib
        import stat
        import tempfile
        import zipfile
        module = inspector(self)
        self.assertTrue(hasattr(module, 'extract_verified_zip'), 'Missing fail-closed ZIP transfer verification')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def archive(entries):
                path = root / 'artifact.zip'
                with zipfile.ZipFile(path, 'w') as z:
                    for name, data in entries:
                        z.writestr(name, data)
                return path, hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size
            path, checksum, size = archive([('sources/edge.db', b'fixture')])
            for sha, length in [('0'*64, size), (checksum, size+1)]:
                with self.assertRaises(ValueError):
                    module.extract_verified_zip(path, root/'bad', sha, length)
                self.assertFalse((root/'bad').exists())
            module.extract_verified_zip(path, root/'good', checksum, size)
            self.assertEqual((root/'good/sources/edge.db').read_bytes(), b'fixture')
            link = zipfile.ZipInfo('link'); link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            for entries in [[('../escape', b'x')], [('/absolute', b'x')],
                            [('a/../b', b'x')], [('a\\b', b'x')], [(link, b'target')],
                            [('a', b'x'), ('a/b', b'y')], [('a/', b'')]]:
                path, checksum, size = archive(entries)
                with self.subTest(entries=entries), self.assertRaises(ValueError):
                    module.extract_verified_zip(path, root/'bad', checksum, size)
                self.assertFalse((root/'bad').exists())
            path, checksum, size = archive([('large', b'x'*20)])
            with self.assertRaises(ValueError):
                module.extract_verified_zip(path, root/'bad', checksum, size, max_unpacked=10)


ROOT = Path(__file__).resolve().parent.parent


class WorkflowTests(unittest.TestCase):
    def test_cli_entrypoint_is_wired_and_missing_evidence_fails_closed(self):
        import subprocess
        import tempfile
        import sys
        script = ROOT / 'scripts/inspect-capture.py'
        result = subprocess.run([sys.executable, str(script), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('fetch', result.stdout)
        self.assertIn('inspect', result.stdout)
        self.assertIn('write-identity', result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)/'report.json'
            result = subprocess.run([sys.executable, str(script), 'inspect', '--capture', directory,
                                     '--evidence', directory, '--report', str(report)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(report.exists())

    def test_manual_readonly_workflow_and_ci_wiring(self):
        path = ROOT / '.github/workflows/inspect-retained-capture.yml'
        self.assertTrue(path.is_file(), 'Missing hosted inspection-only workflow')
        workflow = yaml.safe_load(path.read_text())
        trigger = workflow.get('on', workflow.get(True))
        self.assertEqual(set(trigger), {'workflow_dispatch'})
        self.assertIsInstance(trigger['workflow_dispatch'], dict, 'Missing explicit dispatch identity inputs')
        inputs = trigger['workflow_dispatch']['inputs']
        self.assertEqual(set(inputs), {'capture_run_id', 'capture_run_attempt', 'capture_head_sha',
                                      'capture_workflow_blob_sha', 'capture_artifact_id',
                                      'capture_artifact_name', 'capture_artifact_size',
                                      'capture_artifact_zip_sha256', 'expected_semantics_json'})
        self.assertTrue(all(value.get('required') is True and value.get('type') == 'string'
                            for value in inputs.values()))
        self.assertEqual(workflow['permissions'], {'contents': 'read', 'actions': 'read'})
        job = workflow['jobs']['inspect']
        self.assertNotIn('environment', job)
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertIn('--network none', path.read_text())
        self.assertIn(':/capture:ro', path.read_text())
        self.assertIn(':/evidence:ro', path.read_text())
        self.assertEqual(job['if'], "github.repository == 'omarchy-mac/omarchy-pkgs-aarch64'")
        text = path.read_text()
        writer = next(step for step in job['steps'] if step.get('name') == 'Write exact retained capture identity')
        writer_text = writer['run']
        writer_env = writer['env']
        for input_name, env_name in {
                'capture_run_id': 'CAPTURE_RUN_ID',
                'capture_run_attempt': 'CAPTURE_RUN_ATTEMPT',
                'capture_head_sha': 'CAPTURE_HEAD_SHA',
                'capture_workflow_blob_sha': 'CAPTURE_WORKFLOW_BLOB_SHA',
                'capture_artifact_id': 'CAPTURE_ARTIFACT_ID',
                'capture_artifact_name': 'CAPTURE_ARTIFACT_NAME',
                'capture_artifact_size': 'CAPTURE_ARTIFACT_SIZE',
                'capture_artifact_zip_sha256': 'CAPTURE_ARTIFACT_ZIP_SHA256',
                'expected_semantics_json': 'EXPECTED_SEMANTICS_JSON'}.items():
            self.assertEqual(writer_env[env_name], '${{ inputs.' + input_name + ' }}')
        for flag, env_name in {
                '--run-id': 'CAPTURE_RUN_ID',
                '--run-attempt': 'CAPTURE_RUN_ATTEMPT',
                '--head-sha': 'CAPTURE_HEAD_SHA',
                '--workflow-blob-sha': 'CAPTURE_WORKFLOW_BLOB_SHA',
                '--artifact-id': 'CAPTURE_ARTIFACT_ID',
                '--artifact-name': 'CAPTURE_ARTIFACT_NAME',
                '--size-in-bytes': 'CAPTURE_ARTIFACT_SIZE',
                '--zip-sha256': 'CAPTURE_ARTIFACT_ZIP_SHA256',
                '--expected-semantics-json': 'EXPECTED_SEMANTICS_JSON'}.items():
            self.assertIn(flag + ' "$' + env_name + '"', writer_text)
        self.assertIn('--output "$RUNNER_TEMP/expected-retained-capture-identity.json"', writer_text)
        fetch = next(step for step in job['steps'] if step.get('name') == 'Fetch exact retained artifact and recorded capture evidence')
        self.assertIn('--expected "$RUNNER_TEMP/expected-retained-capture-identity.json"', fetch['run'])
        inspect = next(step for step in job['steps'] if step.get('name') == 'Offline semantic inspection without credentials or build execution')
        self.assertIn('--expected /evidence/expected-identity.json', inspect['run'])
        secret_steps = [step for step in job['steps'] if 'secrets.' in str(step)]
        self.assertEqual(len(secret_steps), 1)
        self.assertIs(secret_steps[0], fetch)
        self.assertEqual(fetch['env'], {'GH_TOKEN': '${{ secrets.GITHUB_TOKEN }}'})
        self.assertIn('inspect-capture.py write-identity', text)
        self.assertGreaterEqual(text.count('--expected'), 2)
        self.assertNotIn('retained-capture-35445613014.json', text)
        for forbidden in ('build-packages.sh', 'stage-input', 'SIGNING_SUBKEY', 'release upload',
                          'workflow run', '--privileged', 'docker.sock', 'contents: write', 'actions: write'):
            self.assertNotIn(forbidden, text)
        import subprocess
        for step in job['steps']:
            if 'uses' in step:
                self.assertRegex(step['uses'], r'@[a-f0-9]{40}$')
            if 'run' in step:
                subprocess.run(['bash', '-n'], input=step['run'], text=True, check=True)
            if 'secrets.' in str(step):
                self.assertIn('inspect-capture.py fetch', step['run'])
                self.assertEqual(step['env'], {'GH_TOKEN': '${{ secrets.GITHUB_TOKEN }}'})
        ci = yaml.safe_load((ROOT / '.github/workflows/test.yml').read_text())
        commands = '\n'.join(step.get('run', '') for step in ci['jobs']['self-tests']['steps'])
        self.assertIn('PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-inspect-capture.py -v', commands)


if __name__ == '__main__':
    unittest.main()
