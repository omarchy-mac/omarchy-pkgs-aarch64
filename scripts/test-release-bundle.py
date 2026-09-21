#!/usr/bin/python3
"""Offline native libalpm archive/database fixtures. gh is always a read-only recorder."""
import argparse
import importlib.util
import sys
from unittest.mock import patch
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).with_name('release-bundle.py')
spec = importlib.util.spec_from_file_location('bundle', MODULE)
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def seal_fixture_from_pipe(stream, args):
    """Test-only integration; no RC4 identity bypass or production launcher."""
    parser_spec = importlib.util.spec_from_file_location('rc4_frame', MODULE.with_name('rc4-sign-retain.py'))
    parser = importlib.util.module_from_spec(parser_spec)
    parser_spec.loader.exec_module(parser)
    return parser.with_signing_secret(
        stream, lambda: bundle.check(args.bundle),
        lambda validated, key, password: bundle.seal(args, secret_material=(key, password)))


def launch_fixture_signer(argv, credentials):
    feeder_spec = importlib.util.spec_from_file_location('fixture_feeder', MODULE.with_name('rc4-signing-secret-feeder.py'))
    feeder = importlib.util.module_from_spec(feeder_spec)
    feeder_spec.loader.exec_module(feeder)
    try:
        feeder.launch_isolated_signer(os.environ, argv, credentials)
    finally:
        for value in credentials:
            feeder.zero(value)


class BundleIsolationTests(unittest.TestCase):
    """Portable process-IO tests; no native signing claims."""

    def test_tools_cannot_consume_inherited_private_stdin(self):
        script = f'''
import importlib.util, sys
spec = importlib.util.spec_from_file_location('bundle', {str(MODULE)!r})
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)
sys.stdout.buffer.write(bundle.run(sys.executable, '-c',
    'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'))
'''
        result = subprocess.run([sys.executable, '-c', script], input=b'private frame',
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertEqual(result.stdout, b'', 'Archive/tool subprocess inherited signing stdin')

    def test_seal_forwards_private_buffers_without_environment(self):
        # Only native archive/GnuPG boundaries are replaced; seal's ordering,
        # copy/staging cleanup and credential handoff execute normally.
        material = (bytearray(b'fixture key'), bytearray(b'fixture passphrase'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'unsigned'
            (source / 'rollback').mkdir(parents=True)
            (source / 'rollback' / (bundle.DB + '.db')).write_bytes(b'baseline')
            public = root / 'public.gpg'
            public.write_bytes(b'fixture public key')
            args = argparse.Namespace(bundle=source, output=root / 'signed',
                                      public_key=public, trust_policy=root / 'policy.json')
            manifest = dict(signature_policy='optional-existing-signatures; no signer authority asserted',
                            candidates=sorted(bundle.CANDIDATES), packages=[
                                dict(name='omarchy', depends=['omarchy-mac-keyring']),
                                dict(name='omarchy-mac-keyring', version='20260914-2')])

            def copy(source, target):
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)

            with patch.object(bundle, 'check', return_value=manifest), \
                 patch.object(bundle, 'copy_file', side_effect=copy), \
                 patch.object(bundle.signing, 'policy', return_value={'public_key_sha256': bundle.digest(public)}), \
                 patch.object(bundle.signing, 'Keyring', side_effect=RuntimeError('keyring reached')) as keyring:
                for explicit in (True, False):
                    with self.subTest(explicit=explicit):
                        try:
                            with self.assertRaisesRegex(RuntimeError, 'keyring reached'):
                                bundle.seal(args, **({'secret_material': material} if explicit else {}))
                        except TypeError as error:
                            self.fail(f'Seal cannot receive private credentials: {error}')
                        self.assertIs(keyring.call_args.kwargs.get('secret_material'),
                                      material if explicit else None)
                        self.assertTrue(keyring.call_args.kwargs['secret'])
                        self.assertFalse(args.output.exists())
                        self.assertEqual(list(root.glob('.signed-bundle-*')), [])

    def test_private_pipe_reaches_seal_as_mutable_buffers(self):
        import threading
        feeder_spec = importlib.util.spec_from_file_location('feeder', MODULE.with_name('rc4-signing-secret-feeder.py'))
        feeder = importlib.util.module_from_spec(feeder_spec)
        feeder_spec.loader.exec_module(feeder)
        read_fd, write_fd = os.pipe()
        def write():
            try:
                feeder.write_fd_part(write_fd, bytearray(b'fixture key'))
                feeder.write_fd_part(write_fd, bytearray(b'fixture passphrase'))
            finally:
                os.close(write_fd)
        writer = threading.Thread(target=write)
        writer.start()
        observed = []
        def seal(args, *, secret_material):
            self.assertTrue(all(isinstance(x, bytearray) for x in secret_material))
            self.assertEqual(secret_material, (b'fixture key', b'fixture passphrase'))
            observed.extend(secret_material)
        args = argparse.Namespace(bundle=Path('unsigned'))
        try:
            with os.fdopen(read_fd, 'rb') as stream, \
                 patch.object(bundle, 'check', return_value={}) as check, \
                 patch.object(bundle, 'seal', side_effect=seal):
                entry = globals().get('seal_fixture_from_pipe')
                self.assertIsNotNone(entry, 'Fixture has no private-pipe seal entry point')
                entry(stream, args)
                check.assert_called_once_with(args.bundle)
        finally:
            writer.join()
        self.assertEqual(len(observed), 2)
        self.assertTrue(all(not any(x) for x in observed))

    def test_private_frame_rejection_never_seals(self):
        import io
        import struct
        args = argparse.Namespace(bundle=Path('unsigned'))
        frames = [b'', struct.pack('>I', 1024 * 1024 + 1),
                  struct.pack('>I', 3) + b'ab',
                  struct.pack('>I', 1) + b'k' + struct.pack('>I', 1) + b'p' + b'extra']
        with patch.object(bundle, 'check', return_value={}), patch.object(bundle, 'seal') as seal:
            for frame in frames:
                with self.subTest(frame=frame), self.assertRaises(ValueError):
                    seal_fixture_from_pipe(io.BytesIO(frame), args)
            seal.assert_not_called()

    def test_fixture_launcher_uses_real_sanitized_child_pipe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key, password = bytearray(b'fixture key'), bytearray(b'fixture passphrase')
            marker = root / 'child.json'
            child = '''import json, os, struct, sys
stream = sys.stdin.buffer
parts = [stream.read(struct.unpack('>I', stream.read(4))[0]) for _ in range(2)]
assert stream.read(1) == b''
assert parts == [b'fixture key', b'fixture passphrase']
assert not any('SIGNING' in name for name in os.environ)
open(sys.argv[1], 'w').write(json.dumps({'pipe': True}))
'''
            entry = globals().get('launch_fixture_signer')
            self.assertIsNotNone(entry, 'Fixture does not launch existing private feeder')
            entry([sys.executable, '-c', child, str(marker)], (key, password))
            self.assertEqual(json.loads(marker.read_text()), {'pipe': True})
            self.assertFalse(any(key))
            self.assertFalse(any(password))

    def test_explicit_subprocess_input_is_preserved(self):
        result = bundle.run(sys.executable, '-c',
                            'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())',
                            input=b'explicit input')
        self.assertEqual(result, b'explicit input')

    def test_explicit_subprocess_stdin_is_preserved(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b'explicit stream')
            stream.seek(0)
            result = bundle.run(sys.executable, '-c',
                                'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())',
                                stdin=stream)
        self.assertEqual(result, b'explicit stream')


class ReleaseBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key_spec = importlib.util.spec_from_file_location('fixture_signing', Path(__file__).with_name('test-package-signing.py'))
        keys = importlib.util.module_from_spec(key_spec); key_spec.loader.exec_module(keys)
        cls.keys = keys.SigningTests
        cls.keys.setUpClass()
        # All bundle/bootstrap fixtures exercise additive historical client trust.
        cls.keys.run_gpg('--quick-generate-key', 'Historical bundle trust', 'ed25519', 'cert', '1d')
        historical=cls.keys.fingerprints()[-1]
        cls.keys.public.write_bytes(cls.keys.run_gpg('--export',historical,cls.keys.primary))
        policy=json.loads(cls.keys.policy.read_text())
        policy.update(public_key_sha256=bundle.signing.digest(cls.keys.public),trusted_primary_fingerprints=[historical,cls.keys.primary])
        cls.keys.policy.write_text(json.dumps(policy))
        cls.temp = tempfile.TemporaryDirectory(prefix='bundle-tests-')
        cls.root = Path(cls.temp.name)
        cls.source = cls.root / 'source'
        cls.source.mkdir()
        (cls.source / 'build-inputs').mkdir()
        (cls.source / 'version').write_text('4.0.3rc1\n')
        (cls.source / 'build-packages.sh').write_text('#!/bin/bash\ntrue\n')
        (cls.source / 'build-inputs/omarchy-pkgs-revision').write_text('1' * 40 + '\n')
        (cls.source / 'build-inputs/omarchy-first-run-packages.patch').write_text('fixture overlay\n')
        bundle.run('git', 'init', '-q', cls.source)
        bundle.run('git', '-C', cls.source, 'add', '.')
        cls.commit('Fixture RC source')
        cls.rc_commit = bundle.run('git', '-C', cls.source, 'rev-parse', 'HEAD').decode().strip()
        cls.base = cls.root / 'baseline'
        cls.base.mkdir()
        for name, version in [('omarchy', '4.0.2-2'), ('omarchy-settings', '4.0.2-2'),
                              ('omarchy-keyring', '20251027-1'), ('ttf-jetbrains-mono-nerd-basic', '3.5.1-1'), ('fixture-app', '2.0-1')]:
            cls.make_package(cls.base, name, version)
        bundle.build_db(cls.base)
        cls.base_db = cls.root / 'baseline.db'
        shutil.copyfile(cls.base / 'omarchy-aarch64.db', cls.base_db)
        for path in list(cls.base.iterdir()):
            if '.pkg.tar.' not in path.name:
                path.unlink()
        cls.candidates = cls.root / 'candidate'
        cls.candidates.mkdir()
        for name in ['omarchy', 'omarchy-settings']:
            cls.make_package(cls.candidates, name, '4.0.3rc1-1')
        for path in cls.base.iterdir():
            if path.name.startswith(('omarchy-keyring-', 'ttf-')):
                shutil.copyfile(path, cls.candidates / path.name)
        cls.write_build_inputs(cls.candidates, cls.rc_commit, '4.0.3rc1')
        cls.make_package(cls.candidates, 'omarchy-mac-keyring', '20260913-1')
        cls.rc = cls.root / 'rc-bundle'
        cls.stage(cls.rc)
        cls.bin = cls.root / 'bin'
        cls.bin.mkdir()
        cls.remote = cls.root / 'remote.json'
        cls.remote.write_text(json.dumps({'assets': []}))
        cls.recorder = cls.root / 'gh.log'
        (cls.bin / 'gh').write_text('''#!/usr/bin/python3
import json, os, sys
with open(os.environ['GH_RECORDER'], 'a') as f:
    f.write(json.dumps(sys.argv[1:]) + '\\n')
assert sys.argv[1:3] == ['release', 'view'], 'remote mutation or unexpected read'
print(open(os.environ['GH_FIXTURE']).read())
''')
        (cls.bin / 'gh').chmod(0o755)
        cls.env = dict(os.environ, PATH=str(cls.bin) + ':' + os.environ['PATH'],
                       GH_RECORDER=str(cls.recorder), GH_FIXTURE=str(cls.remote), PYTHONDONTWRITEBYTECODE='1')
        cls.validation = cls.make_receipt(cls.rc, 'rc')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
        cls.keys.tearDownClass()

    @classmethod
    def commit(cls, message):
        bundle.run('git', '-C', cls.source, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                   '-c', 'commit.gpgsign=false', 'commit', '-qm', message)

    @classmethod
    def write_build_inputs(cls, directory, commit, version):
        (directory / 'build-inputs.txt').write_text('recipe_commit=' + '1' * 40 + '\nrecipe_pin=' + '1' * 40 +
                                                   '\ncustom_recipes=0\nsource_commit=' + commit + '\nsource_version=' + version + '\nsource_dirty=0\n')

    @classmethod
    def make_package(cls, destination, name, version, content='payload', revoked='', builddate=1,
                     keyring_dependency='omarchy-mac-keyring'):
        root = Path(tempfile.mkdtemp(dir=cls.root))
        arch = 'any' if name in {'omarchy-keyring', 'omarchy-mac-keyring', 'ttf-jetbrains-mono-nerd-basic'} else 'aarch64'
        info = f'pkgname = {name}\npkgbase = {name}\npkgver = {version}\npkgdesc = fixture\narch = {arch}\nsize = 10\nbuilddate = {builddate}\n'
        if name == 'omarchy':
            for dep in ['omarchy-settings=' + version.rsplit('-', 1)[0], 'snapper', 'iwd', 'networkmanager',
                        'omarchy-keyring', keyring_dependency, 'ttf-jetbrains-mono-nerd-basic']:
                info += 'depend = ' + dep + '\n'
        (root / '.PKGINFO').write_text(info)
        (root / 'fixture').write_text(content)
        output = destination / f'{name}-{version}-{arch}.pkg.tar.gz'
        members=['.PKGINFO','fixture']
        if name == 'omarchy-mac-keyring':
            keys=root/'usr/share/pacman/keyrings';keys.mkdir(parents=True)
            (keys/'omarchy-mac.gpg').write_bytes(cls.keys.public.read_bytes())
            (keys/'omarchy-mac-trusted').write_text(bundle.signing.trusted_file(bundle.signing.policy(cls.keys.policy))+'\n')
            if revoked is not None:(keys/'omarchy-mac-revoked').write_text(revoked)
            members.append('usr')
        bundle.run('bsdtar', '-czf', output, '-C', root, *members)
        shutil.rmtree(root)
        return output

    @classmethod
    def stage(cls, output, candidates=None, release='4.0.3rc1', commit=None):
        args = ['stage', '--base-db', str(cls.base_db), '--base-packages', str(cls.base),
                '--candidates', str(candidates or cls.candidates), '--source', str(cls.source),
                '--source-commit', commit or cls.rc_commit, '--release', release, '--output', str(output)+'.unsigned']
        result = subprocess.run(['python3', str(MODULE), *args], capture_output=True, text=True)
        if result.returncode:
            print(result.stderr, file=__import__('sys').stderr)
            result.check_returncode()
        result = subprocess.run(['python3', str(MODULE), 'seal', '--bundle', str(output)+'.unsigned',
                                 '--output', str(output), '--public-key', str(cls.keys.public),
                                 '--trust-policy', str(cls.keys.policy)], capture_output=True, text=True)
        if result.returncode: print(result.stderr, file=__import__('sys').stderr)
        result.check_returncode()
        return result

    @classmethod
    def make_receipt(cls, directory, suffix):
        report = cls.root / (suffix + '.report.txt')
        report.write_text('Synthetic fixture evidence only; not release qualification.\n')
        receipt = cls.root / (suffix + '.validation.json')
        receipt.write_text(json.dumps({'manifest_sha256': bundle.digest(directory / 'manifest.json'),
                                      'checks': {key: 'pass' for key in bundle.CHECKS},
                                      'report': report.name, 'report_sha256': bundle.digest(report)}))
        return receipt

    def command(self, *arguments):
        return subprocess.run(['python3', str(MODULE), *map(str, arguments), '--trust-policy', str(self.keys.policy)], env=self.env,
                              capture_output=True, text=True)

    def test_01_complete_inventory_and_rollback(self):
        manifest = bundle.check(self.rc, self.keys.policy)
        self.assertEqual(len(manifest['packages']), 6)
        self.assertEqual(set(manifest['reused_candidates']), {'omarchy-keyring', 'ttf-jetbrains-mono-nerd-basic'})
        self.assertEqual(bundle.digest(self.rc / 'provenance/captured-baseline.db'), bundle.digest(self.base_db))
        self.assertEqual(set(bundle.database(self.rc / 'assets/omarchy-aarch64.files')), set(bundle.database(self.base_db)) | {'omarchy-mac-keyring'})

    def test_private_material_seal_and_independent_check(self):
        # Native hosted fixture: no production key and no secret environment in seal.
        import base64
        unsigned = Path(str(self.rc) + '.unsigned')
        before = {p.relative_to(unsigned): bundle.digest(p)
                  for p in unsigned.rglob('*') if p.is_file()}
        key = bytearray(base64.b64decode(os.environ['PACMAN_SIGNING_SUBKEY_B64']))
        password = bytearray(os.environ['PACMAN_SIGNING_PASSPHRASE'].encode())
        clean = {k: v for k, v in os.environ.items() if k not in bundle.signing.SECRET_ENV}
        output = self.root / 'private-material-bundle'
        with patch.dict(os.environ, clean, clear=True):
            launch_fixture_signer([
                sys.executable, '-B', str(Path(__file__).resolve()), '--private-fixture-child',
                str(unsigned), str(output), str(self.keys.public), str(self.keys.policy),
                os.environ['TMPDIR']], (key, password))
            manifest = bundle.check(output, self.keys.policy)
        self.assertEqual(manifest['signature_policy'], bundle.STRICT_POLICY)
        self.assertEqual(manifest['unsigned_manifest_sha256'], bundle.digest(unsigned / 'manifest.json'))
        self.assertEqual(before, {p.relative_to(unsigned): bundle.digest(p)
                                  for p in unsigned.rglob('*') if p.is_file()})
        self.assertFalse(any(key))
        self.assertFalse(any(password))

    def test_versioned_keyring_stage_seal_and_strict_check(self):
        # Hosted-only native archive/vercmp/signing fixture, matching the builder.
        candidates = self.root / 'versioned-keyring-candidates'
        shutil.copytree(self.candidates, candidates)
        for name in ('omarchy', 'omarchy-mac-keyring'):
            bundle.archives(candidates)[name][0].unlink()
        self.make_package(candidates, 'omarchy', '4.0.3rc1-1',
                          keyring_dependency='omarchy-mac-keyring>=20260914-2')
        self.make_package(candidates, 'omarchy-mac-keyring', '20260914-2')
        output = self.root / 'versioned-keyring-bundle'
        self.stage(output, candidates)
        manifest = bundle.check(output, self.keys.policy)
        records = {item['name']: item for item in manifest['packages']}
        self.assertEqual(records['omarchy-mac-keyring']['version'], '20260914-2')
        self.assertIn('omarchy-mac-keyring>=20260914-2', records['omarchy']['depends'])
        unsigned = Path(str(output) + '.unsigned')
        self.assertEqual(manifest['unsigned_manifest_sha256'], bundle.digest(unsigned / 'manifest.json'))
        self.assertNotEqual(bundle.check(unsigned)['signature_policy'], bundle.STRICT_POLICY)

    def test_02_untracked_source_contamination_rejected(self):
        extra = self.source / 'ignored-runtime'
        extra.write_text('untracked')
        try:
            with self.assertRaises(subprocess.CalledProcessError):
                self.stage(self.root / 'dirty')
        finally:
            extra.unlink()
        self.assertFalse((self.root / 'dirty').exists())

    def test_03_partial_pair_and_filename_rebuild_rejected(self):
        partial = self.root / 'partial'
        shutil.copytree(self.candidates, partial)
        next(partial.glob('omarchy-settings-*')).unlink()
        with self.assertRaises(subprocess.CalledProcessError):
            self.stage(self.root / 'partial-bundle', partial)
        rebuilt = self.root / 'rebuilt'
        shutil.copytree(self.candidates, rebuilt)
        self.make_package(rebuilt, 'omarchy-keyring', '20251027-1', 'different bytes')
        with self.assertRaises(subprocess.CalledProcessError):
            self.stage(self.root / 'rebuilt-bundle', rebuilt)

    def test_04_changed_missing_extra_bundle_assets_rejected(self):
        for kind in ['changed', 'missing', 'extra']:
            target = self.root / kind
            shutil.copytree(self.rc, target)
            path = next((target / 'assets').glob('omarchy-settings-*'))
            if kind == 'changed':
                with path.open('ab') as stream:
                    stream.write(b'changed')
            elif kind == 'missing':
                path.unlink()
            else:
                (target / 'assets/unexpected').write_text('extra')
            with self.assertRaises(ValueError):
                bundle.check(target, self.keys.policy)

    def test_05_publish_plan_reads_only_and_database_last(self):
        self.remote.write_text(json.dumps({'assets': []}))
        result = self.command('publish', '--bundle', self.rc, '--validation', self.validation,
                              '--repo', 'fixture/repository', '--lane', 'rc')
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan['mode'], 'plan-only')
        self.assertEqual(plan['steps'][-1]['operation'], 'activate_authenticated_immutable_server')
        steps = [item['operation'] for item in plan['steps']]
        self.assertIn('upload_complete_signed_snapshot_without_clobber', steps)
        self.assertNotIn('replace_database_alias', steps)
        calls = [json.loads(line) for line in self.recorder.read_text().splitlines()]
        self.assertTrue(all(call[:2] == ['release', 'view'] for call in calls))
        for lane in ['stable', 'edge']:
            self.assertNotEqual(self.command('publish', '--bundle', self.rc, '--validation', self.validation,
                                            '--repo', 'fixture/repository', '--lane', lane).returncode, 0)
        self.assertNotEqual(self.command('publish', '--bundle', self.rc, '--validation', self.validation,
                                        '--repo', 'fixture/repository', '--lane', 'rc', '--execute').returncode, 0)

    def test_06_remote_collision_and_changed_lane_rejected(self):
        metadata = {'assets': [{'name': 'omarchy-aarch64.db', 'digest': 'sha256:' + 'f' * 64}]}
        self.remote.write_text(json.dumps(metadata))
        result = self.command('publish', '--bundle', self.rc, '--validation', self.validation,
                              '--repo', 'fixture/repository', '--lane', 'rc')
        self.assertNotEqual(result.returncode, 0)
        name = next((self.rc / 'assets').glob('omarchy-*.pkg.tar.*')).name
        self.remote.write_text(json.dumps({'assets': [{'name': name, 'digest': 'sha256:' + 'f' * 64}]}))
        self.assertNotEqual(self.command('publish', '--bundle', self.rc, '--validation', self.validation,
                                        '--repo', 'fixture/repository', '--lane', 'rc').returncode, 0)
        self.remote.write_text(json.dumps({'assets': []}))

    def test_07_promote_separately_rebuilt_final_and_legacy_edge(self):
        (self.source / 'version').write_text('4.0.3\n')
        bundle.run('git', '-C', self.source, 'add', 'version')
        self.commit('Fixture final version only')
        commit = bundle.run('git', '-C', self.source, 'rev-parse', 'HEAD').decode().strip()
        candidates = self.root / 'final-candidates'
        shutil.copytree(self.candidates, candidates)
        for name in ['omarchy', 'omarchy-settings']:
            next(candidates.glob(name + '-4.0.3rc1-*')).unlink()
            self.make_package(candidates, name, '4.0.3-1')
        self.write_build_inputs(candidates, commit, '4.0.3')
        final = self.root / 'final-bundle'
        self.stage(final, candidates, release='4.0.3', commit=commit)
        validation = self.make_receipt(final, 'final')
        result = self.command('promote', '--bundle', final, '--validation', validation,
                              '--rc-bundle', self.rc, '--rc-validation', self.validation,
                              '--edge-bundle', final, '--edge-validation', validation, '--repo', 'fixture/repository')
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan['stable']['lane'], 'stable')
        self.assertEqual(plan['legacy_edge']['lane'], 'edge')
        self.assertNotEqual(self.command('promote', '--bundle', self.rc, '--validation', self.validation,
                                        '--rc-bundle', self.rc, '--rc-validation', self.validation,
                                        '--edge-bundle', final, '--edge-validation', validation,
                                        '--repo', 'fixture/repository').returncode, 0)
        bundle.run('git', '-C', self.source, 'checkout', '--detach', self.rc_commit)

    def test_08_malformed_manifest_and_stale_receipt_rejected(self):
        target = self.root / 'malformed-manifest'
        shutil.copytree(self.rc, target)
        manifest = json.loads((target / 'manifest.json').read_text())
        manifest['source']['files']['version']['sha256'] = 'invalid'
        (target / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            bundle.check(target, self.keys.policy)
        receipt = self.root / 'stale.validation.json'
        value = json.loads(self.validation.read_text())
        value['manifest_sha256'] = '0' * 64
        receipt.write_text(json.dumps(value))
        self.assertNotEqual(self.command('publish', '--bundle', self.rc, '--validation', receipt,
                                        '--repo', 'fixture/repository', '--lane', 'rc').returncode, 0)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--private-fixture-child':
        parser = argparse.ArgumentParser(description='Disposable fixture only; not a production signer')
        for name in ('bundle', 'output', 'public_key', 'trust_policy', 'scratch'):
            parser.add_argument(name, type=Path)
        args = parser.parse_args(sys.argv[2:])
        os.environ['TMPDIR'] = str(args.scratch)
        tempfile.tempdir = str(args.scratch)
        seal_fixture_from_pipe(sys.stdin.buffer, args)
    else:
        unittest.main()
