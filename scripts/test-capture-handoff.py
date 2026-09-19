#!/usr/bin/env python3
"""Local workflow contracts; not a substitute for hosted Actions execution."""
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parent.parent

class HandoffTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.safe_load((ROOT/'.github/workflows'/name).read_text())

    def test_ci_runs_handoff_suite(self):
        steps=self.workflow('test.yml')['jobs']['self-tests']['steps']
        commands=[line.strip() for step in steps for line in step.get('run','').splitlines()]
        self.assertIn('PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-capture-handoff.py -v',commands)

    def test_retained_handoff_and_readonly_build_boundary(self):
        producer=self.workflow('prepare-rc-baseline.yml')
        inputs=producer.get('on',producer.get(True))['workflow_dispatch']['inputs']
        self.assertTrue({'capture_run_id','capture_artifact_name','capture_manifest_sha256'} <= set(inputs))
        self.assertFalse({'baseline_lane','baseline_database_sha256','target_database_sha256'} & set(inputs))
        self.assertEqual(producer['permissions'],{'contents':'read','actions':'read'})
        steps=producer['jobs']['prepare']['steps']
        download=next(s for s in steps if s.get('uses','').startswith('actions/download-artifact@'))
        self.assertEqual(download['with']['repository'],'${{ github.repository }}')
        self.assertEqual(download['with']['run-id'],'${{ inputs.capture_run_id }}')
        self.assertEqual(download['with']['name'],'${{ inputs.capture_artifact_name }}')
        scripts='\n'.join(s.get('run','') for s in steps)
        self.assertNotIn('bootstrap-rc.py capture ',scripts)
        self.assertNotIn('gh api',scripts)
        verify=next(i for i,s in enumerate(steps) if 'bootstrap-rc.py check-capture ' in s.get('run',''))
        build=next(i for i,s in enumerate(steps) if 'bash /vendor/desktop/build-packages.sh' in s.get('run',''))
        stage=next(s for s in steps if 'bootstrap-rc.py stage-input ' in s.get('run',''))
        self.assertLess(verify,build)
        self.assertIn('--manifest-sha256 "$CAPTURE_HASH"',steps[verify]['run'])
        self.assertIn('--capture-manifest-sha256 "$CAPTURE_HASH"',stage['run'])
        self.assertEqual(stage['env']['CAPTURE_HASH'],'${{ inputs.capture_manifest_sha256 }}')
        for step in (steps[verify],steps[build],stage):
            self.assertNotIn('-v "$RUNNER_TEMP/rc-producer:/task"',step['run'])
            self.assertIn('-v "$RUNNER_TEMP/rc-capture:/capture:ro"',step['run'])
        self.assertIn('--network none',stage['run'])

    def test_capture_is_separate_readonly_retained_workflow(self):
        path=ROOT/'.github/workflows/capture-rc-baseline.yml'
        self.assertTrue(path.is_file(),'separate capture workflow required')
        data=self.workflow(path.name)
        self.assertEqual(set(data.get('on',data.get(True))),{'workflow_dispatch'})
        self.assertEqual(data['permissions'],{'contents':'read'})
        steps=data['jobs']['capture']['steps']
        text=path.read_text()
        self.assertIn('bootstrap-rc.py capture ',text)
        self.assertNotIn('stage-input',text)
        self.assertNotIn('build-packages.sh',text)
        self.assertNotIn('SIGNING_SUBKEY',text)
        artifact=next(s for s in steps if s.get('uses','').startswith('actions/upload-artifact@') and s['with']['path'].endswith('/capture/'))
        self.assertEqual(artifact['with']['retention-days'],90)
        self.assertEqual(artifact['with']['if-no-files-found'],'error')
        self.assertIn('github.run_attempt',artifact['with']['name'])

    def test_all_run_blocks_parse_and_actions_are_pinned(self):
        for name in ('capture-rc-baseline.yml','prepare-rc-baseline.yml'):
            path=ROOT/'.github/workflows'/name
            self.assertTrue(path.exists())
            for job in self.workflow(name)['jobs'].values():
                for step in job['steps']:
                    if 'uses' in step:self.assertRegex(step['uses'],r'@[a-f0-9]{40}$')
                    if 'run' in step:
                        subprocess.run(['bash','-n'],input=step['run'],text=True,check=True)

if __name__=='__main__':unittest.main()
