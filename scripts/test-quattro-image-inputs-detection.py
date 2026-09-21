#!/usr/bin/python3
"""A failed, expired or untrusted job must never suppress the hourly build."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import os
import tempfile

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('detect-quattro-image-inputs.py'))
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class CandidateReuseTest(unittest.TestCase):
    def setUp(self):
        self.artifact = {'expired': False, 'workflow_run': {
            'head_branch': 'main', 'head_repository_id': 123, 'repository_id': 123}}
        self.run = {'event': 'schedule', 'path': '.github/workflows/build-quattro-image-inputs.yml',
                    'conclusion': 'success'}
        self.jobs = [{'name': name, 'conclusion': 'success'} for name in
                     ('Build nine candidate packages', 'Sign nine candidate packages')]

    def test_successful_three_package_set_is_reused(self):
        self.assertTrue(candidate.trusted_artifact(self.artifact))
        self.assertTrue(candidate.successful_build(self.run, self.jobs))

    def test_expired_artifact_and_failed_or_cancelled_jobs_retry(self):
        self.artifact['expired'] = True
        self.assertFalse(candidate.trusted_artifact(self.artifact))
        for status in ('failure', 'cancelled', 'skipped', None):
            with self.subTest(status=status):
                self.jobs[0]['conclusion'] = status
                self.assertFalse(candidate.successful_build(self.run, self.jobs))

    def test_pr_and_fork_artifacts_cannot_suppress_main_builds(self):
        self.run['event'] = 'pull_request'
        self.assertFalse(candidate.successful_build(self.run, self.jobs))
        for key, value in (('head_branch', 'feature/recipe'), ('head_repository_id', 456),
                           ('head_repository_id', None)):
            with self.subTest(key=key, value=value):
                artifact = copy.deepcopy(self.artifact)
                artifact['workflow_run'][key] = value
                self.assertFalse(candidate.trusted_artifact(artifact))

    def test_unrelated_workflow_or_job_does_not_count_as_a_build(self):
        self.run['path'] = '.github/workflows/test.yml'
        self.assertFalse(candidate.successful_build(self.run, self.jobs))
        self.run['path'] = '.github/workflows/build-quattro-image-inputs.yml'
        self.assertFalse(candidate.successful_build(self.run, [{'name': 'Self-tests', 'conclusion': 'success'}]))

    def test_unsigned_build_is_not_reusable(self):
        self.assertFalse(candidate.successful_build(self.run, self.jobs[:1]))

    def test_manual_main_build_can_be_reused(self):
        self.run.update(event='workflow_dispatch', path='.github/workflows/build-quattro-image-inputs.yml')
        self.assertTrue(candidate.successful_build(self.run, self.jobs))

    def test_failed_workflow_and_push_events(self):
        self.run['conclusion'] = 'failure'
        self.assertFalse(candidate.successful_build(self.run, self.jobs))
        self.run.update(event='push', conclusion='success')
        self.assertTrue(candidate.successful_build(self.run, self.jobs))


class DetectionTest(unittest.TestCase):
    def detect(self, *, force=False, source='a' * 40, inputs=b'input tree', recipe='b' * 40,
               artifacts=None, run_status='success', job_status='success', sign_status='success',
               source_ref='quattro-upstream'):
        calls = []
        def api(path, paginate=False):
            calls.append(path)
            if '/commits/' in path:
                self.assertTrue(path.endswith(candidate.quote(source_ref or 'quattro-upstream', safe='')))
                return {'sha': source}
            if '/actions/artifacts?' in path:
                prefix = 'signed-' if not source_ref or source_ref == 'quattro-upstream' else ''
                self.assertIn('name=' + prefix + 'quattro-image-inputs-', path)
                return [{'artifacts': artifacts or []}]
            if path.endswith('/jobs?per_page=100'):
                return [{'jobs': [{'name': 'Build nine candidate packages', 'conclusion': job_status},
                                  {'name': 'Sign nine candidate packages', 'conclusion': sign_status}]}]
            return {'event': 'schedule', 'path': '.github/workflows/build-quattro-image-inputs.yml',
                    'conclusion': run_status}
        def command(args, **kwargs):
            if 'rev-parse' in args:
                return recipe + '\n'
            self.assertEqual(args[5:], list(candidate.BUILD_INPUTS))
            return inputs
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'outputs'
            env = {'GITHUB_REPOSITORY': 'owner/repo', 'SOURCE_REF': source_ref,
                   'FORCE_BUILD': 'true' if force else 'false', 'GITHUB_OUTPUT': str(output)}
            with patch.dict(os.environ, env), patch.object(candidate, 'api', side_effect=api), \
                    patch.object(candidate.subprocess, 'check_output', side_effect=command), patch('builtins.print'):
                candidate.main()
            result = dict(line.split('=', 1) for line in output.read_text().splitlines())
        self.assertEqual(sum('/commits/' in call for call in calls), 1)
        return result, calls

    def test_source_and_build_inputs_invalidate_but_unrelated_commits_do_not(self):
        first, _ = self.detect()
        same, _ = self.detect(recipe='c' * 40)
        changed_source, _ = self.detect(source='d' * 40)
        changed_inputs, _ = self.detect(inputs=b'changed build inputs')
        self.assertEqual(first['artifact_name'], same['artifact_name'])
        self.assertNotEqual(first['artifact_name'], changed_source['artifact_name'])
        self.assertNotEqual(first['artifact_name'], changed_inputs['artifact_name'])
        self.assertEqual(first['needs_build'], 'true')
        self.assertEqual(first['source_sha'], 'a' * 40)
        self.assertEqual(same['recipe_sha'], 'c' * 40)

    def test_matching_success_is_reused_but_failed_or_expired_candidates_retry(self):
        artifact = {'expired': False, 'workflow_run': {'id': 42, 'head_branch': 'main',
                    'head_repository_id': 123, 'repository_id': 123}}
        result, _ = self.detect(artifacts=[artifact])
        self.assertEqual(result['needs_build'], 'false')
        for kwargs in ({'run_status': 'failure'}, {'job_status': 'cancelled'},
                       {'sign_status': 'failure'}, {'sign_status': 'skipped'}, {'sign_status': 'cancelled'}):
            result, _ = self.detect(artifacts=[artifact], **kwargs)
            self.assertEqual(result['needs_build'], 'true')
        artifact['expired'] = True
        result, calls = self.detect(artifacts=[artifact])
        self.assertEqual(result['needs_build'], 'true')
        self.assertFalse(any('/actions/runs/' in call for call in calls))

    def test_arbitrary_refs_reuse_unsigned_builds(self):
        artifact = {'expired': False, 'workflow_run': {'id': 42, 'head_branch': 'main',
                    'head_repository_id': 123, 'repository_id': 123}}
        for ref in ('feature/image', 'a' * 40, 'refs/heads/quattro-upstream'):
            result, _ = self.detect(source_ref=ref, artifacts=[artifact], sign_status='skipped')
            self.assertEqual(result['needs_build'], 'false')
        result, _ = self.detect(source_ref='', artifacts=[artifact], sign_status='skipped')
        self.assertEqual(result['needs_build'], 'true')

    def test_force_bypasses_cache_lookup(self):
        result, calls = self.detect(force=True)
        self.assertEqual(result['needs_build'], 'true')
        self.assertFalse(any('/actions/artifacts?' in call for call in calls))


if __name__ == '__main__':
    unittest.main()
