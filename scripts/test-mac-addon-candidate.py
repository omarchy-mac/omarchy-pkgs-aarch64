#!/usr/bin/python3
"""A failed, expired or untrusted job must never suppress the hourly build."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('detect-mac-addon-candidate.py'))
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class CandidateReuseTest(unittest.TestCase):
    def setUp(self):
        self.artifact = {'expired': False, 'workflow_run': {
            'head_branch': 'main', 'head_repository_id': 123, 'repository_id': 123}}
        self.run = {'event': 'schedule', 'path': '.github/workflows/update-omarchy-mac.yml',
                    'conclusion': 'failure'}
        self.jobs = [{'name': 'Build latest add-on candidate / Build add-on archive', 'conclusion': 'success'}]

    def test_successful_addon_is_reused_even_if_independent_desktop_release_fails(self):
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
        self.run['path'] = '.github/workflows/update-omarchy-mac.yml'
        self.assertFalse(candidate.successful_build(self.run, [{'name': 'Self-tests', 'conclusion': 'success'}]))

    def test_manual_main_build_can_be_reused(self):
        self.run.update(event='workflow_dispatch', path='.github/workflows/build-mac-addon-candidate.yml')
        self.assertTrue(candidate.successful_build(self.run, self.jobs))


if __name__ == '__main__':
    unittest.main()
