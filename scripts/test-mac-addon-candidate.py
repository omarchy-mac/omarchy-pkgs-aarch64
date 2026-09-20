#!/usr/bin/python3
"""A failed, expired or untrusted job must never suppress the hourly build."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('detect-mac-addon-candidate.py'))
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


build_spec = importlib.util.spec_from_file_location('builder', Path(__file__).with_name('build-mac-addon-candidate.py'))
builder = importlib.util.module_from_spec(build_spec)
build_spec.loader.exec_module(builder)


class CandidateVersionTest(unittest.TestCase):
    def test_release_is_valid_for_makepkg_and_orders_reruns(self):
        release = builder.candidate_release('4', 35464345295, 1)
        self.assertRegex(release, r'^[0-9]+\.[0-9]+$')
        self.assertLess(int(release.split('.')[1]), int(builder.candidate_release('4', 35464345295, 2).split('.')[1]))
        self.assertLess(int(builder.candidate_release('4', 35464345295, 9999).split('.')[1]),
                        int(builder.candidate_release('4', 35464345296, 1).split('.')[1]))
        for attempt in (0, 10000):
            with self.assertRaises(ValueError):
                builder.candidate_release('4', 35464345295, attempt)


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
