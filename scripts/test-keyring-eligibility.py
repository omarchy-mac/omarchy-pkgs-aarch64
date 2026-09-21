#!/usr/bin/env python3
"""Lightweight eligibility contracts. Stub comparator/archive IO is NOT native evidence.

Native vercmp and real stage/seal/check fixtures run only in the Arch CI job.
"""
import argparse
from contextlib import ExitStack
import importlib.util
import json
import os
from itertools import product
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('release_bundle', ROOT / 'scripts/release-bundle.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)
KEYRING = 'omarchy-mac-keyring'
VERSION = '20260914-2'


def metadata(dependencies, version=VERSION):
    return dict(candidates=sorted(bundle.CANDIDATES), packages=[
        dict(name='omarchy', depends=dependencies), dict(name=KEYRING, version=version)])


class EligibilityTests(unittest.TestCase):
    def test_operators_use_pacman_comparison(self):
        # Stub results model signs, NOT pacman ordering. CI also runs these cases
        # with the native comparator, including epochs and numeric pkgrel.
        pairs = [(VERSION, VERSION, 0), (VERSION, '20260914-1', 1),
                 (VERSION, '20260914-3', -1), ('1:1-1', '20260914-2', 1),
                 ('2:1-1', '1:999-9', 1), ('20260914-10', VERSION, 1),
                 (VERSION, '20260914-10', -1),
                 ('1.0-1', '1.0', 0), ('1.0', '1.0-9', 0),
                 ('1.0-1.2', '1.0-1.1', 1), ('1.0-1.2', '1.0-1.10', -1),
                 ('1.0rc1-1', '1.0-1', -1), ('1.0alpha-1', '1.0beta-1', -1),
                 ('0:1.0-1', '1.0-1', 0), ('1.0-1', '0:1.0-1', 0),
                 ('1@vendor-1', '1@vendor-1', 0)]
        for installed, required, comparison in pairs:
            for operator, accepted in [('=', comparison == 0), ('>=', comparison >= 0),
                                       ('<=', comparison <= 0), ('>', comparison > 0), ('<', comparison < 0)]:
                with self.subTest(installed=installed, required=required, operator=operator):
                    expression = KEYRING + operator + required
                    with ExitStack() as stack:
                        command = None
                        if not os.environ.get('NATIVE_VERCMP'):
                            command = stack.enter_context(patch.object(bundle, 'run', return_value=str(comparison).encode()))
                        if accepted:
                            bundle.signing_eligibility(metadata([expression], installed))
                        else:
                            with self.assertRaisesRegex(ValueError, 'does not satisfy'):
                                bundle.signing_eligibility(metadata([expression], installed))
                        if command is not None:
                            command.assert_called_once_with('vercmp', installed, required)

    def test_legal_pkgver_punctuation_reaches_comparator_unchanged(self):
        for installed, required in [('1@vendor-1', '1-1'), ('1-1', '1@vendor-1')]:
            with self.subTest(installed=installed, required=required), \
                 patch.object(bundle, 'run', return_value=b'0') as command:
                bundle.signing_eligibility(metadata([KEYRING + '=' + required], installed))
                command.assert_called_once_with('vercmp', installed, required)

    def test_malformed_pkgrel_is_rejected_before_comparison(self):
        for installed, required, error in [('1-1.2.3', '1-1', 'version'),
                                            ('1-1', '1-1.2.3', 'dependency')]:
            with self.subTest(installed=installed, required=required), \
                 patch.object(bundle, 'run', return_value=b'0') as command:
                with self.assertRaisesRegex(ValueError, 'Invalid fork keyring ' + error):
                    bundle.signing_eligibility(metadata([KEYRING, KEYRING + '=' + required], installed))
                command.assert_not_called()

    def test_dependency_version_safety_and_argv_boundary(self):
        for invalid in ['1=2', '1>2', '1<2', '1 2', '1\t2', '1\n2', '1\x002']:
            for installed, required, error in [(invalid, '1', 'version'), ('1', invalid, 'dependency')]:
                with self.subTest(installed=installed, required=required), patch.object(bundle, 'run') as command:
                    with self.assertRaisesRegex(ValueError, 'Invalid fork keyring ' + error):
                        bundle.signing_eligibility(metadata([KEYRING + '=' + required], installed))
                    command.assert_not_called()
        # Other legal punctuation is data, including shell metacharacters.
        for version in ['1@vendor-1', '1!vendor-1', '1;$vendor-1']:
            with self.subTest(version=version), patch.object(bundle.subprocess, 'run') as command:
                command.return_value.stdout = b'0'
                bundle.signing_eligibility(metadata([KEYRING + '=' + version], version))
                command.assert_called_once_with(['vercmp', version, version], check=True,
                                               stdout=bundle.subprocess.PIPE, stderr=bundle.subprocess.PIPE,
                                               stdin=bundle.subprocess.DEVNULL)

    def test_malformed_constraints_cannot_hide_behind_bare_dependency(self):
        for suffix in ['>=', '=', '==1', '!=1', '=>1', '><1', '>= 1', '>=1 2',
                       '>=1\n', '>=1/2', '>=x:1', '>=1:', '>=1--2', '>=1-foo']:
            with self.subTest(suffix=suffix), patch.object(bundle, 'run') as command:
                with self.assertRaisesRegex(ValueError, 'Invalid fork keyring dependency'):
                    bundle.signing_eligibility(metadata([KEYRING, KEYRING + suffix]))
                command.assert_not_called()
        for version in ['', ' 1', '1\n', '1/2', 'x:1', '1:', '1--2']:
            with self.subTest(version=version), patch.object(bundle, 'run') as command:
                with self.assertRaisesRegex(ValueError, 'Invalid fork keyring version'):
                    bundle.signing_eligibility(metadata([KEYRING], version))
                command.assert_not_called()

    def test_exact_identity_bare_compatibility_and_all_constraints(self):
        for expression in ['other-keyring', KEYRING + '-extra', 'not-' + KEYRING,
                           KEYRING + '-extra>=1', KEYRING + 'x>=1']:
            with self.subTest(expression=expression), self.assertRaisesRegex(ValueError, 'requires the fork keyring dependency'):
                bundle.signing_eligibility(metadata([expression]))
        with patch.object(bundle, 'run') as command:
            bundle.signing_eligibility(metadata([KEYRING], '1-1'))  # no global floor
            command.assert_not_called()
        with patch.object(bundle, 'run', return_value=b'0') as command:
            bundle.signing_eligibility(metadata([KEYRING, KEYRING + '>=' + VERSION, KEYRING + '<=' + VERSION]))
            self.assertEqual(command.call_count, 2)
        for dependencies in [[KEYRING, KEYRING + '>' + VERSION],
                             [KEYRING + '>' + VERSION, KEYRING],
                             [KEYRING + '>=' + VERSION, KEYRING + '<' + VERSION]]:
            with self.subTest(dependencies=dependencies), patch.object(bundle, 'run', return_value=b'0'):
                with self.assertRaisesRegex(ValueError, 'does not satisfy'):
                    bundle.signing_eligibility(metadata(dependencies))
        for change in ('candidate', 'archive'):
            value = metadata([KEYRING])
            if change == 'candidate':
                value['candidates'].remove(KEYRING)
            else:
                value['packages'].pop()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'fork keyring'):
                bundle.signing_eligibility(value)

    def test_rejected_seal_and_bootstrap_never_touch_signer_or_staging(self):
        spec = importlib.util.spec_from_file_location('bootstrap', ROOT / 'scripts/bootstrap-rc.py')
        boot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boot)
        cases = [([KEYRING, KEYRING + '>=' + VERSION], 'does not satisfy', False),
                 ([KEYRING + '>=' + VERSION, KEYRING], 'does not satisfy', False),
                 ([KEYRING, KEYRING + '>='], 'Invalid fork keyring dependency', False),
                 ([KEYRING + '-extra>=1'], 'requires the fork keyring dependency', False),
                 ([], 'requires the fork keyring dependency', False),
                 ([KEYRING], 'Stage the fork keyring', True)]
        for entry, (dependencies, error, missing_candidate) in product(('seal', 'prepare'), cases):
            with self.subTest(entry=entry, dependencies=dependencies, missing_candidate=missing_candidate), tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
                root = Path(tmp)
                source = root / 'input'
                source.mkdir()
                (source / 'manifest.json').write_bytes(b'unchanged approved input')
                args = argparse.Namespace(bundle=source, input=source, output=root / 'output',
                                          public_key=root / 'absent-public', trust_policy=root / 'absent-policy',
                                          manifest_sha256='a'*64, source_commit='b'*40)
                value = metadata(dependencies, '20260914-1')
                if missing_candidate:
                    value['candidates'].remove(KEYRING)
                value['signature_policy'] = 'optional-existing-signatures; no signer authority asserted'
                before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                stack.enter_context(patch.object(boot, 'bundle', bundle))
                stack.enter_context(patch.object(boot, 'guard'))
                stack.enter_context(patch.object(boot, 'validate', return_value=value))
                stack.enter_context(patch.object(bundle, 'check', return_value=value))
                stack.enter_context(patch.object(bundle, 'run', return_value=b'-1'))
                policy = stack.enter_context(patch.object(bundle.signing, 'policy', side_effect=AssertionError('policy reached')))
                signer = stack.enter_context(patch.object(bundle.signing, 'Keyring', side_effect=AssertionError('signer reached')))
                staging = stack.enter_context(patch.object(bundle.tempfile, 'mkdtemp', side_effect=AssertionError('staging reached')))
                copy = stack.enter_context(patch.object(bundle, 'copy_file', side_effect=AssertionError('copy reached')))
                with self.assertRaisesRegex(ValueError, error):
                    (bundle.seal if entry == 'seal' else boot.prepare)(args)
                for operation in (policy, signer, staging, copy):
                    operation.assert_not_called()
                self.assertFalse(args.output.exists())
                self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()})
                self.assertEqual(sorted(p.name for p in root.iterdir()), ['input'])

    def test_credential_free_bootstrap_preflight_cli_preserves_approval_checks(self):
        spec = importlib.util.spec_from_file_location('bootstrap', ROOT / 'scripts/bootstrap-rc.py')
        boot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boot)
        for case in ('valid', 'unsatisfied', 'wrong-hash', 'wrong-source', 'wrong-inventory', 'signed-retry'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
                root = Path(tmp)
                source = root / 'input'
                source.mkdir()
                (source / 'manifest.json').write_text('approved input')
                value = metadata([KEYRING + '>=' + VERSION])
                value.update(channel='rc', version='4.0.3rc4-2', source={'commit': 'b'*40},
                             signature_policy=bundle.STRICT_POLICY if case == 'signed-retry' else
                             'optional-existing-signatures; no signer authority asserted')
                (root / 'packages.json').write_text(json.dumps({'packages': value['packages']}))
                if case == 'wrong-inventory':
                    value['packages'].append({'name': 'unapproved'})
                checksum = bundle.digest(source / 'manifest.json')
                argv = ['bootstrap-rc.py', 'check-eligibility', '--input', str(source),
                        '--manifest-sha256', '0'*64 if case == 'wrong-hash' else checksum,
                        '--source-commit', 'c'*40 if case == 'wrong-source' else 'b'*40]
                before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                stack.enter_context(patch.object(boot, 'ROOT', root))
                stack.enter_context(patch.object(boot, 'bundle', bundle))
                checked = stack.enter_context(patch.object(bundle, 'check', return_value=value))
                stack.enter_context(patch.object(bundle, 'run', return_value=b'-1' if case == 'unsatisfied' else b'0'))
                stack.enter_context(patch('sys.argv', argv))
                signer = stack.enter_context(patch.object(bundle.signing, 'Keyring', side_effect=AssertionError('signer reached')))
                staging = stack.enter_context(patch.object(bundle.tempfile, 'mkdtemp', side_effect=AssertionError('staging reached')))
                copy = stack.enter_context(patch.object(bundle, 'copy_file', side_effect=AssertionError('copy reached')))
                errors = {'unsatisfied': 'does not satisfy', 'wrong-hash': 'differs from approval',
                          'wrong-source': 'Source differs', 'wrong-inventory': 'Complete exact configured'}
                if case in errors:
                    with self.assertRaisesRegex(ValueError, errors[case]):
                        boot.main()
                else:
                    boot.main()
                    checked.assert_called_once()
                for operation in (signer, staging, copy):
                    operation.assert_not_called()
                self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()})
                self.assertEqual(sorted(p.name for p in root.iterdir()), ['input', 'packages.json'])

    def test_real_builder_dependency_passes_strict_check(self):
        # Actual check() with tiny inert files; stub only native archive/crypto IO.
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            records, db, infos = [], {}, {}
            for directory in ('assets', 'rollback', 'provenance'):
                (root / directory).mkdir()
            for name in sorted(bundle.CANDIDATES):
                version = '4.0.3rc4-2' if name in ('omarchy', 'omarchy-settings') else VERSION
                deps = (['omarchy-settings=4.0.3rc4', 'snapper', 'iwd', 'networkmanager',
                         'omarchy-keyring', 'ttf-jetbrains-mono-nerd-basic', KEYRING + '>=' + VERSION]
                        if name == 'omarchy' else [])
                filename = f'{name}-{version}-aarch64.pkg.tar.gz'
                for directory in ('assets', 'rollback'):
                    (root / directory / filename).write_bytes(b'inert package fixture')
                path = root / 'assets' / filename
                records.append(dict(name=name, version=version, arch='aarch64', depends=deps,
                                    filename=filename, sha256=bundle.digest(path)))
                db[name] = dict(NAME=[name], VERSION=[version], ARCH=['aarch64'], FILENAME=[filename],
                                SHA256SUM=[bundle.digest(path)], CSIZE=[str(path.stat().st_size)], PGPSIG=['stub'])
                infos[filename] = dict(pkgname=[name], pkgver=[version], arch=['aarch64'], depend=deps)
            for directory in ('assets', 'rollback'):
                for suffix in ('db', 'db.tar.zst', 'files', 'files.tar.zst'):
                    (root / directory / f'{bundle.DB}.{suffix}').write_bytes(b'inert database fixture')
            (root / 'provenance/captured-baseline.db').write_bytes(b'inert database fixture')
            (root / 'provenance/build-inputs.txt').write_bytes(b'provenance fixture')
            (root / 'provenance/signing-public.gpg').write_bytes(b'inert public fixture')
            policy = {'fixture': 'no keys'}
            manifest = dict(schema=1, version='4.0.3rc4-2', channel='rc', candidates=sorted(bundle.CANDIDATES),
                            signature_policy=bundle.STRICT_POLICY, signing_policy=policy, publisher_sha256='a'*64,
                            source=dict(commit='b'*40, recipe_commit='c'*40, builder_sha256='d'*64,
                                        overlay_sha256='e'*64, files={'version': {'mode': '100644', 'sha256': 'f'*64}}),
                            packages=records, baseline_db_sha256=bundle.digest(root / 'rollback' / f'{bundle.DB}.db'),
                            candidate_build_inputs_sha256=bundle.digest(root / 'provenance/build-inputs.txt'),
                            build_inputs=dict(recipe_commit='c'*40, recipe_pin='c'*40, custom_recipes='0',
                                              source_commit='b'*40, source_version='4.0.3rc4', source_dirty='0'))
            manifest['files'] = {p.relative_to(root).as_posix(): bundle.digest(p) for p in root.rglob('*') if p.is_file()}
            bundle.write_json(root / 'manifest.json', manifest)
            def native_io(*args):
                if args[0] == 'vercmp':
                    self.assertEqual(args, ('vercmp', VERSION, VERSION))
                    return b'0\n'
                self.assertEqual(args[:2], ('bsdtar', '-xOf'))
                return b'inert public fixture' if str(args[-1]).endswith('.gpg') else b'stub trusted'
            stack.enter_context(patch.object(bundle, 'database', return_value=db))
            stack.enter_context(patch.object(bundle, 'pkginfo', side_effect=lambda path: infos[path.name]))
            stack.enter_context(patch.object(bundle, 'run', side_effect=native_io))
            stack.enter_context(patch.object(bundle.signing, 'policy', return_value=policy))
            stack.enter_context(patch.object(bundle.signing, 'trusted_file', return_value='stub trusted'))
            signer = stack.enter_context(patch.object(bundle.signing, 'Keyring'))
            self.assertEqual(bundle.check(root), manifest)
            signer.reset_mock()
            # The final strict check must reject even a bare duplicate followed
            # by an unsatisfied constraint, before public-key initialization.
            desktop = next(item for item in records if item['name'] == 'omarchy')
            desktop['depends'].extend([KEYRING, KEYRING + '>' + VERSION])
            bundle.write_json(root / 'manifest.json', manifest)
            with self.assertRaisesRegex(ValueError, 'does not satisfy'):
                bundle.check(root)
            signer.assert_not_called()


class WorkflowContracts(unittest.TestCase):
    def workflow(self, name):
        import yaml
        return yaml.safe_load((ROOT / '.github/workflows' / name).read_text())

    def test_modified_workflow_shell_blocks_parse(self):
        import subprocess
        for name in ('test.yml', 'bootstrap-signed-rc.yml'):
            for job in self.workflow(name)['jobs'].values():
                for step in job['steps']:
                    if 'run' in step:
                        with self.subTest(workflow=name, step=step.get('name')):
                            subprocess.run(['bash', '-n'], input=step['run'], text=True, check=True)

    def test_native_suite_is_wired_in_actual_arch_ci(self):
        workflow = self.workflow('test.yml')
        scripts = '\n'.join(step.get('run', '') for step in workflow['jobs']['self-tests']['steps'])
        self.assertIn('NATIVE_VERCMP=1 PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-keyring-eligibility.py -v', scripts)
        self.assertIn('python3 scripts/test-release-bundle.py -v', scripts)
        self.assertIn('archlinux:base-devel', scripts)

    def test_eligibility_precedes_credentials_without_changing_gates(self):
        workflow = self.workflow('bootstrap-signed-rc.yml')
        job = workflow['jobs']['bootstrap']
        steps = job['steps']
        preflights = [i for i, step in enumerate(steps) if 'scripts/bootstrap-rc.py check-eligibility ' in step.get('run', '')]
        self.assertEqual(len(preflights), 1, 'credential-free eligibility preflight required')
        index = preflights[0]
        credential_steps = [i for i, step in enumerate(steps) if 'PACMAN_SIGNING_SUBKEY_B64' in step.get('env', {})]
        self.assertTrue(credential_steps)
        self.assertLess(index, min(credential_steps))
        step = steps[index]
        self.assertNotIn('if', step)
        self.assertNotIn('continue-on-error', step)
        self.assertEqual(set(step['env']), {'INPUT_HASH', 'INPUT_SOURCE'})
        self.assertEqual(step['env']['INPUT_HASH'], '${{ inputs.manifest_sha256 }}')
        self.assertEqual(step['env']['INPUT_SOURCE'], '${{ inputs.source_commit }}')
        script = step['run']
        for required in ('set -euo pipefail', '--network none', '/task/input:ro', '--input /task/input',
                         '--manifest-sha256 "$INPUT_HASH"', '--source-commit "$INPUT_SOURCE"'):
            self.assertIn(required, script)
        for forbidden in ('PACMAN_SIGNING_', 'secrets.', ' prepare ', ' seal ', '--output', '|| true'):
            self.assertNotIn(forbidden, script)
        self.assertEqual(job['environment'], 'package-signing')
        self.assertEqual(workflow['concurrency'], {'group': 'edge-publish', 'cancel-in-progress': False})
        self.assertEqual(set(workflow.get('on', workflow.get(True))), {'workflow_dispatch'})


if __name__ == '__main__':
    unittest.main()
