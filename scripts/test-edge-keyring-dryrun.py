#!/usr/bin/env python3
"""Portable contracts; --native is reserved for hosted Arch publisher tools."""
import importlib.util
from pathlib import Path
import unittest
import io
import tarfile
import tempfile
import copy
import yaml

ROOT = Path(__file__).resolve().parents[1]


class Contracts(unittest.TestCase):
    def test_manual_readonly_job_and_complete_export(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/test.yml').read_text())
        self.assertIn('edge-keyring-dryrun', workflow['jobs'], 'missing no-build manual job')
        job = workflow['jobs']['edge-keyring-dryrun']
        self.assertEqual(job['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(job['concurrency'], {
            'group': 'edge-publish', 'cancel-in-progress': False, 'queue': 'max'})
        self.assertIn("github.event_name == 'workflow_dispatch'", job['if'])
        self.assertIn('inputs.edge_keyring_dryrun', job['if'])
        self.assertNotIn('environment', job)
        text = yaml.safe_dump(job)
        self.assertNotIn('secrets.', text)
        self.assertIn('--network none', text)
        self.assertIn('publisher.Dockerfile', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('actions/upload-artifact@', text)
        publish = (ROOT / 'scripts/publish.sh').read_text()
        export = publish.split('if [[ -n "${DB_OUT:-}" ]]')[1]
        self.assertIn('"${database_assets[@]}"', export, 'export both DBs and aliases')

    def test_acquisition_is_exact_and_fails_closed(self):
        spec = importlib.util.spec_from_file_location('dryrun', ROOT / 'scripts/edge-keyring-dryrun.py')
        dry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dry)
        self.assertTrue(hasattr(dry, 'check_keyring_asset'), 'missing fixed-asset acquisition guard')
        row = {'id': 570814012, 'name': 'omarchy-mac-keyring-20260914-2-any.pkg.tar.xz',
               'size': 9740, 'digest': 'sha256:8ca587d9c24d36cd2e67237ca69b3eeac1b3726e691228131d6d062d258cdfb7'}
        dry.check_keyring_asset([row])
        for key, value in [('id', 1), ('size', 9739), ('digest', 'sha256:' + '0'*64), ('name', 'other.pkg.tar.xz')]:
            bad = dict(row, **{key: value})
            with self.assertRaises(ValueError):
                dry.check_keyring_asset([bad])
        for rows in ([], [row, row]):
            with self.assertRaises(ValueError):
                dry.check_keyring_asset(rows)

    def test_snapshot_transport_denies_writes_and_paginates(self):
        spec = importlib.util.spec_from_file_location('dryrun', ROOT / 'scripts/edge-keyring-dryrun.py')
        dry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dry)
        self.assertTrue(hasattr(dry, 'snapshot_gh'), 'missing offline publisher transport')
        from unittest.mock import patch
        import json
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'before').mkdir()
            (root / 'edge-assets.json').write_text(json.dumps([{'name': 'old.pkg.tar.xz'}]))
            env = dict(SNAPSHOT=str(root), SNAPSHOT_LOG=str(root / 'calls.jsonl'))
            with patch.dict(os.environ, env):
                for verb in ('upload', 'delete-asset', 'create'):
                    with self.assertRaisesRegex(ValueError, 'read-only'):
                        dry.snapshot_gh(['release', verb, 'edge', '--repo', dry.REPO])
                (root / 'before' / (dry.DB + '.db.tar.zst')).write_bytes(b'database')
                target = root / 'download'
                dry.snapshot_gh(['release', 'download', 'edge', '--repo', dry.REPO,
                                 '--dir', str(target), '--clobber', '--pattern', dry.DB + '.db.tar.zst'])
                self.assertEqual((target / (dry.DB + '.db.tar.zst')).read_bytes(), b'database')
                with self.assertRaises(ValueError):
                    dry.snapshot_gh(['release', 'download', 'rc', '--repo', dry.REPO])
            rows = [{'id': i, 'name': str(i), 'size': 1, 'digest': 'sha256:x', 'updated_at': 'now'} for i in range(101)]
            with patch.object(dry, 'api', side_effect=[rows[:100], rows[100:]]) as api:
                self.assertEqual(len(dry.assets(dry.EDGE_RELEASE)), 101)
                self.assertEqual(api.call_count, 2)

    def test_inventory_reconciles_complete_db_and_files_with_assets(self):
        spec = importlib.util.spec_from_file_location('dryrun', ROOT / 'scripts/edge-keyring-dryrun.py')
        dry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dry)
        self.assertTrue(hasattr(dry, 'inventory'), 'missing complete inventory reconciliation')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            desc = b'%NAME%\nold\n\n%VERSION%\n1-1\n\n%FILENAME%\nold-1-1-any.pkg.tar.xz\n\n%CSIZE%\n7\n\n%SHA256SUM%\nabc\n\n'
            for ext in ('db', 'files'):
                path = root / (dry.DB + '.' + ext + '.tar.zst')
                # Portable tar fixture: native zstd/repo-add are not simulated.
                with tarfile.open(path, 'w') as tar:
                    entries = {'desc': desc}
                    if ext == 'files': entries['files'] = b'%FILES%\nusr/bin/old\n'
                    for name, data in entries.items():
                        info = tarfile.TarInfo('old-1-1/' + name); info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                (root / (dry.DB + '.' + ext)).write_bytes(path.read_bytes())
            rows = [{'name': 'old-1-1-any.pkg.tar.xz', 'size': 7, 'digest': 'sha256:abc'}]
            for suffix in dry.SUFFIXES:
                data = (root / (dry.DB + '.' + suffix)).read_bytes()
                rows.append({'name': dry.DB + '.' + suffix, 'size': len(data), 'digest': 'sha256:' + dry.digest(data)})
            dry.inventory(root, rows)
            for key, value in [('size', 8), ('digest', 'sha256:wrong'), ('name', 'wrong.pkg.tar.xz')]:
                bad = copy.deepcopy(rows); bad[0][key] = value
                with self.assertRaises(ValueError): dry.inventory(root, bad)
            with self.assertRaises(ValueError): dry.inventory(root, rows + [{'name': 'orphan.pkg.tar.xz'}])
            with self.assertRaises(ValueError): dry.inventory(root, rows + [{'name': 'edge-signing.json'}])

    def test_publisher_control_flow_forces_dryrun_without_credentials(self):
        spec = importlib.util.spec_from_file_location('dryrun', ROOT / 'scripts/edge-keyring-dryrun.py')
        dry = importlib.util.module_from_spec(spec); spec.loader.exec_module(dry)
        self.assertTrue(hasattr(dry, 'publisher'), 'missing publisher invocation')
        from unittest.mock import patch
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            incoming = root / 'incoming'; incoming.mkdir()
            # Subprocess IO only: this is NOT native publisher evidence.
            with patch.dict(os.environ, {'DRY_RUN': '0', 'GH_TOKEN': 'must-not-inherit',
                                         'PACMAN_SIGNING_PRIVATE_KEY': 'must-not-inherit'}), \
                 patch.object(dry.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                dry.publisher(incoming, root, root / 'result')
                call = run.call_args
                self.assertEqual(call.args[0], ['bash', 'scripts/publish.sh'])
                self.assertEqual(call.kwargs['env']['DRY_RUN'], '1')
                self.assertEqual(call.kwargs['env']['REPO_TAG'], 'edge')
                self.assertNotIn('GH_TOKEN', call.kwargs['env'])
                self.assertNotIn('PACMAN_SIGNING_PRIVATE_KEY', call.kwargs['env'])
                self.assertEqual(call.kwargs['cwd'], dry.ROOT)
            with patch.object(dry.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2)):
                with self.assertRaises(ValueError): dry.publisher(incoming, root, root / 'failure')

    def test_cli_exposes_acquisition_and_native_preservation(self):
        import subprocess
        import sys
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/edge-keyring-dryrun.py'), '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in ('--acquire', '--recheck', '--native'):
            self.assertIn(option, result.stdout, 'missing runnable entrypoint')

    def test_real_publisher_export_retains_both_databases_and_aliases(self):
        import os
        import subprocess
        source = (ROOT / 'scripts/publish.sh').read_text()
        export = 'if [[ -n "${DB_OUT:-}" ]]' + source.split('if [[ -n "${DB_OUT:-}" ]]')[1]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / 'work'; work.mkdir()
            assets = ['omarchy-aarch64.' + suffix for suffix in ('db', 'db.tar.zst', 'files', 'files.tar.zst')]
            # Include strict-mode signatures to cover the existing export caller too.
            assets += [name + '.sig' for name in assets]
            for name in assets + ['fixture.pkg.tar.xz']:
                (work / name).write_bytes(name.encode())
            out = root / 'out'
            script = 'set -euo pipefail\nlog() { :; }\nstaged=(fixture.pkg.tar.xz)\n'
            script += 'database_assets=(' + ' '.join(assets) + ')\n' + export
            result = subprocess.run(['bash', '-c', script], env=dict(os.environ, work=str(work),
                DB_OUT=str(out), mode='strict'), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in assets:
                self.assertEqual((out / name).read_bytes(), (work / name).read_bytes())
            self.assertEqual((out / 'smoke-packages/fixture.pkg.tar.xz').read_bytes(), b'fixture.pkg.tar.xz')
            self.assertEqual((out / 'signing-mode').read_text(), 'strict\n')

    def test_complete_record_preservation_rejects_any_old_change(self):
        path = ROOT / 'scripts/edge-keyring-dryrun.py'
        self.assertTrue(path.exists(), 'missing preservation wrapper')
        spec = importlib.util.spec_from_file_location('dryrun', path)
        dry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dry)
        before = {'old-1': {'desc': b'complete old metadata', 'files': b'%FILES%\nold/path\n'}}
        added = {'keyring-2': {'desc': b'new metadata', 'files': b'%FILES%\nkey\n'}}
        after = dict(before, **added)
        dry.preserved(before, after, {'keyring-2'})
        for part in ('desc', 'files'):
            changed = copy.deepcopy(after)
            changed['old-1'][part] += b'changed'
            with self.assertRaisesRegex(ValueError, 'changed'):
                dry.preserved(before, changed, {'keyring-2'})
        for changed in (added, before, dict(after, unexpected={})):
            with self.assertRaises(ValueError):
                dry.preserved(before, changed, {'keyring-2'})
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / 'fixture.tar.xz'
            with tarfile.open(archive, 'w:xz') as tar:
                for name, data in before['old-1'].items():
                    info = tarfile.TarInfo('old-1/' + name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            self.assertEqual(dry.records(archive), before)


if __name__ == '__main__':
    unittest.main()
