#!/usr/bin/env python3
"""Offline transport tests, not live publication or client qualification."""
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load():
    path = ROOT / 'scripts/edge-keyring-publish.py'
    spec = importlib.util.spec_from_file_location('publish', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Transport:
    def __init__(self, p):
        self.p = p
        self.rows = [dict(id=i, name=n, size=len(b'old'), digest='sha256:' + p.dry.digest(b'old'),
                          updated_at='before') for i, n in enumerate(p.ORDER[1:], 1)]
        self.rows.append(dict(id=99, name='unchanged.pkg.tar.xz', size=1,
                              digest='sha256:unchanged', updated_at='before'))
        self.old = copy.deepcopy(self.rows)
        self.data = {r['id']: b'old' for r in self.rows}
        self.writes = []
        self.reads = 0
        self.fail_at = None
        self.drift_at = None

    def api(self, endpoint, *, method='GET', data=None, raw=False):
        p = self.p
        if method != 'GET':
            self.writes.append((method, endpoint, data))
            if len(self.writes) == self.fail_at:
                raise RuntimeError('synthetic transport failure')
        if endpoint == 'releases/tags/edge':
            return {'id': p.dry.EDGE_RELEASE}
        if endpoint.startswith(f'releases/{p.dry.EDGE_RELEASE}/assets?'):
            self.reads += 1
            rows = copy.deepcopy(self.rows)
            if self.reads == self.drift_at:
                rows[0]['updated_at'] = 'drift'
            return rows
        if method == 'DELETE':
            ident = int(endpoint.split('/')[-1])
            self.rows = [r for r in self.rows if r['id'] != ident]
            return None
        if method == 'POST':
            from urllib.parse import parse_qs, urlparse
            name = parse_qs(urlparse(endpoint).query)['name'][0]
            row = dict(id=1000 + len(self.writes), name=name, size=len(data),
                       digest='sha256:' + p.dry.digest(data), updated_at='after')
            self.rows.append(row)
            self.data[row['id']] = data
            return row
        if endpoint.startswith('releases/assets/'):
            return self.data[int(endpoint.split('/')[-1])]
        raise AssertionError(endpoint)

    def public(self, name):
        row = next(r for r in self.rows if r['name'] == name)
        return self.data[row['id']]


class Publication(unittest.TestCase):
    def test_exact_transport_order_preserves_unrelated_assets(self):
        self.assertTrue((ROOT / 'scripts/edge-keyring-publish.py').exists(), 'missing exact-byte publisher')
        p = load()
        t = Transport(p)
        selected = {name: ('selected-' + name).encode() for name in p.ORDER}
        p.publish(t, t.old, selected)
        self.assertEqual([w[0] for w in t.writes], ['POST'] + ['DELETE', 'POST'] * 4)
        self.assertEqual([w[2] for w in t.writes if w[0] == 'POST'], list(selected.values()))
        self.assertEqual([w[1] for w in t.writes if w[0] == 'DELETE'],
                         ['releases/assets/' + str(i) for i in range(1, 5)])
        self.assertEqual(next(r for r in t.rows if r['id'] == 99), t.old[-1])
        self.assertGreaterEqual(t.reads, 3)


    def test_preflight_drift_and_wrong_live_bytes_never_write(self):
        p = load()
        for drift in (1, 2):
            t = Transport(p)
            t.drift_at = drift
            with self.assertRaisesRegex(ValueError, 'drift'):
                p.publish(t, t.old, {name: b'new' for name in p.ORDER})
            self.assertEqual(t.writes, [])
        t = Transport(p)
        t.data[1] = b'corrupt'
        with self.assertRaisesRegex(ValueError, 'baseline bytes'):
            p.publish(t, t.old, {name: b'new' for name in p.ORDER})
        self.assertEqual(t.writes, [])

    def test_every_mutation_failure_stops_without_retry_or_rollback(self):
        p = load()
        for failure in range(1, 10):
            t = Transport(p)
            t.fail_at = failure
            with self.assertRaisesRegex(RuntimeError, 'PARTIAL PUBLICATION POSSIBLE'):
                p.publish(t, t.old, {name: b'new' for name in p.ORDER})
            self.assertEqual(len(t.writes), failure)

    def test_postflight_drift_or_public_mismatch_is_explicit_partial_state(self):
        p = load()
        from unittest.mock import patch
        for read in (3, 4):
            t = Transport(p)
            t.drift_at = read
            with self.assertRaisesRegex(RuntimeError, 'PARTIAL PUBLICATION POSSIBLE'):
                p.publish(t, t.old, {name: b'new' for name in p.ORDER})
            self.assertEqual(len(t.writes), 9)
        t = Transport(p)
        with patch.object(t, 'public', return_value=b'wrong'), \
             self.assertRaisesRegex(RuntimeError, 'PARTIAL PUBLICATION POSSIBLE'):
            p.publish(t, t.old, {name: b'new' for name in p.ORDER})
        self.assertEqual(len(t.writes), 9)

    def test_complete_inventory_paginates_and_rejects_duplicates(self):
        p = load()
        from unittest.mock import patch
        t = Transport(p)
        rows = [dict(id=i, name=str(i), size=1, digest='sha256:x', updated_at='x') for i in range(101)]
        with patch.object(t, 'api', side_effect=[rows[:100], rows[100:]]) as api:
            self.assertEqual(len(p.assets(t)), 101)
            self.assertEqual(api.call_args.args[0], f'releases/{p.dry.EDGE_RELEASE}/assets?per_page=100&page=2')
        with patch.object(t, 'api', return_value=[rows[0], rows[0]]), self.assertRaises(ValueError):
            p.assets(t)


class Workflow(unittest.TestCase):
    def test_dedicated_write_job_is_opt_in_protected_locked_and_exclusive(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/test.yml').read_text())
        self.assertIn('edge-keyring-publish', workflow['jobs'], 'missing protected exact-byte job')
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        job = workflow['jobs']['edge-keyring-publish']
        self.assertEqual(job['permissions'], {'contents': 'write', 'actions': 'read'})
        self.assertEqual(job['environment'], 'package-signing-edge')
        self.assertEqual(job['concurrency'], {'group': 'edge-publish', 'cancel-in-progress': False, 'queue': 'max'})
        for guard in ("github.event_name == 'workflow_dispatch'", 'inputs.edge_keyring_publish',
                      '!inputs.edge_keyring_dryrun', '!inputs.publisher_readiness', '!inputs.retained_rc4_trust',
                      "github.repository_id == '1327386148'", "github.run_attempt == 1"):
            self.assertIn(guard, job['if'])
        for name, other in workflow['jobs'].items():
            if name != 'edge-keyring-publish':
                self.assertIn('!inputs.edge_keyring_publish', other['if'])
                self.assertNotEqual(other.get('permissions', {}).get('contents'), 'write')
        text = yaml.safe_dump(job)
        self.assertIn('APPROVED_SHA: ${{ inputs.edge_keyring_publish_sha }}', text)
        self.assertIn('scripts/edge-keyring-publish.py --publish', text)
        self.assertNotIn('docker', text)
        self.assertNotIn('secrets.', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('scripts/test-edge-keyring-publish.py', yaml.safe_dump(workflow['jobs']['self-tests']))


class Runtime(unittest.TestCase):
    def test_transport_sends_exact_bytes_and_reads_public_without_auth(self):
        p = load()
        self.assertTrue(hasattr(p, 'GitHub'), 'missing real transport')
        import subprocess
        from unittest.mock import patch, MagicMock
        with patch.object(p.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'{"id":1}')) as run:
            p.GitHub().api('https://uploads.github.com/repos/' + p.dry.REPO + '/releases/1/assets?name=x',
                           method='POST', data=b'\x00\xffexact')
            args = run.call_args.args[0]
            self.assertIn('POST', args)
            self.assertIn('Content-Type: application/octet-stream', args)
            self.assertEqual(run.call_args.kwargs['input'], b'\x00\xffexact')
            self.assertNotIn('--retry', args)
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'public'
        with patch.object(p.urllib.request, 'urlopen', return_value=response) as urlopen:
            self.assertEqual(p.GitHub().public(p.dry.KEYRING), b'public')
            request = urlopen.call_args.args[0]
            self.assertNotIn('Authorization', request.headers)
            self.assertIn('/releases/download/edge/', request.full_url)

    def test_cli_refuses_local_or_unreviewed_execution(self):
        p = load()
        self.assertTrue(hasattr(p, 'execution_guard'), 'missing hosted execution guard')
        from unittest.mock import patch
        import os
        env = dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY=p.dry.REPO,
                   GITHUB_REPOSITORY_ID='1327386148', GITHUB_EVENT_NAME='workflow_dispatch',
                   GITHUB_RUN_ATTEMPT='1', GITHUB_SHA='a' * 40, APPROVED_SHA='a' * 40)
        with patch.dict(os.environ, env, clear=True), patch.object(p.subprocess, 'check_output', return_value=b'a' * 40 + b'\n'):
            p.execution_guard()
            for key in env:
                with self.subTest(key=key), patch.dict(os.environ, {key: 'wrong'}):
                    with self.assertRaises(ValueError): p.execution_guard()


class Acquisition(unittest.TestCase):
    def test_pinned_artifact_acquisition_extracts_only_allowlist(self):
        p = load()
        self.assertTrue(hasattr(p, 'acquire'), 'missing pinned ZIP acquisition')
        import io
        import tempfile
        import zipfile
        from unittest.mock import patch
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            for name in p.MEMBERS:
                archive.writestr(name, name.encode())
            archive.writestr('output/next-publication-fixture-result/forbidden', b'NEVER EXTRACT')
        raw = buffer.getvalue()
        run = dict(id=p.RUN, run_attempt=1, head_sha=p.HEAD, conclusion='success',
                   status='completed', event='workflow_dispatch', path='.github/workflows/test.yml',
                   repository={'id': 1327386148})
        artifact = dict(id=p.ARTIFACT, name=p.ARTIFACT_NAME, expired=False,
                        size_in_bytes=len(raw), digest='sha256:' + p.dry.digest(raw),
                        workflow_run=dict(id=p.RUN, head_sha=p.HEAD, repository_id=1327386148,
                                          head_repository_id=1327386148))
        class API:
            def api(self, endpoint, **kw):
                return {f'actions/runs/{p.RUN}': run,
                        f'actions/artifacts/{p.ARTIFACT}': artifact,
                        f'actions/artifacts/{p.ARTIFACT}/zip': raw}[endpoint]
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, 'ZIP_SIZE', len(raw)), \
             patch.object(p, 'ZIP_SHA', p.dry.digest(raw)):
            root = Path(tmp)
            p.acquire(API(), root)
            self.assertEqual({str(f.relative_to(root)) for f in root.rglob('*') if f.is_file()}, set(p.MEMBERS))
            for field, value in [('id', 1), ('head_sha', '0' * 40), ('run_attempt', 2),
                                 ('conclusion', 'failure'), ('event', 'push')]:
                original = run[field]
                run[field] = value
                with self.assertRaises(ValueError):
                    p.acquire(API(), root / ('bad-' + field))
                run[field] = original
            for field, value in [('id', 1), ('name', 'other'), ('expired', True),
                                 ('digest', 'sha256:' + '0' * 64), ('size_in_bytes', 1)]:
                original = artifact[field]
                artifact[field] = value
                with self.assertRaises(ValueError):
                    p.acquire(API(), root / ('bad-artifact-' + field))
                artifact[field] = original


class Retained(unittest.TestCase):
    def test_retained_real_archive_validation(self):
        p = load()
        self.assertTrue(hasattr(p, 'validate'), 'missing pinned retained validation')
        # Optional operator-supplied tiny evidence; never a production CLI override.
        import os
        evidence = os.environ.get('EDGE_BOOTSTRAP_TEST_EVIDENCE')
        if not evidence:
            self.skipTest('set EDGE_BOOTSTRAP_TEST_EVIDENCE for retained tiny archive check')
        root = Path(evidence)
        before = {str(f.relative_to(root)): f.read_bytes() for f in root.rglob('*') if f.is_file()}
        rows, selected = p.validate(root)
        self.assertEqual(len(rows), 58)
        self.assertEqual(tuple(selected), p.ORDER)
        transport = Transport(p)
        transport.rows = copy.deepcopy(rows)
        transport.old = copy.deepcopy(rows)
        transport.data = {r['id']: (root / 'inputs/before' / r['name']).read_bytes()
                          for r in rows if r['name'] in p.ORDER[1:]}
        final = p.publish(transport, rows, selected)
        self.assertEqual(len(final), 59)
        self.assertEqual([w[2] for w in transport.writes if w[0] == 'POST'], list(selected.values()))
        self.assertEqual([r for r in rows if r['name'] not in p.ORDER],
                         [r for r in final if r['name'] not in p.ORDER])
        self.assertEqual(before, {str(f.relative_to(root)): f.read_bytes() for f in root.rglob('*') if f.is_file()})


if __name__ == '__main__':
    unittest.main()
