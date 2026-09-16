#!/usr/bin/env python3
"""Exercise smoke-test.sh with real archive parsing and mocked network/pacman."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
DB = 'omarchy-aarch64'
MOCK = r'''
import json, os, shutil, sys, tarfile
from pathlib import Path
name, args = Path(sys.argv[0]).name, sys.argv[1:]
root = Path(os.environ['SMOKE_FIXTURE'])
with (root/'calls').open('a') as log:
    log.write(json.dumps([name, *args])+'\n')
def value(flag): return args[args.index(flag)+1]
if name == 'findmnt': print('ext4')
elif name == 'gh':
    if args[:2] == ['release', 'download']:
        source = root/('old.db' if os.environ.get('CACHED_ASSET') else 'new.db')
        for suffix in ('db', 'files'):
            shutil.copyfile(source, Path(value('--dir'))/f'omarchy-aarch64.{suffix}.tar.zst')
    else:
        print('omarchy-aarch64.db')
        if os.environ.get('STRICT'): print('omarchy-aarch64.db.sig')
elif name == 'pacman':
    db = Path(value('--dbpath'))/'sync/omarchy-aarch64.db'
    if '-Syy' in args or '-Sy' in args:
        counter = root/'sync-count'
        attempt = int(counter.read_text())+1 if counter.exists() else 1
        counter.write_text(str(attempt))
        (root/'pacman.conf').write_text(Path(value('--config')).read_text())
        if os.environ.get('SYNC_FAILURE') == 'always' or (os.environ.get('SYNC_FAILURE') == 'first' and attempt <= 2):
            print('invalid database signature', file=sys.stderr)
            sys.exit(1)
        stale = os.environ.get('STALE') == 'always' or (os.environ.get('STALE') == 'first' and attempt == 1)
        db.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root/('old.db' if stale else 'new.db'), db)
    else:
        with tarfile.open(db) as archive:
            names = [member.name.split('/')[0].removesuffix('-1-1') for member in archive if member.name.endswith('/desc')]
        if '-Sl' in args:
            for package in names: print('omarchy-aarch64', package, '1-1')
        else:
            requested = [arg.split('/')[1] for arg in args if arg.startswith('omarchy-aarch64/')]
            assert requested and set(requested) <= set(names), 'target not found'
            if '-Sddp' in args:
                for package in requested: print(f'https://example.invalid/{package}.pkg.tar.xz')
            elif '-Sddw' in args:
                (root/'verified').write_text(json.dumps(requested))
            else: raise AssertionError(args)
elif name == 'curl': print('200')
elif name not in ('pacman-key', 'gpgconf', 'sleep'): raise AssertionError(name)
'''


class SmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='smoke-tests-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root/'tools'; self.tools.mkdir()
        for name in ('gh', 'pacman', 'pacman-key', 'gpgconf', 'curl', 'sleep', 'findmnt'):
            path = self.tools/name
            path.write_text(f'#!{sys.executable}\n'+MOCK)
            path.chmod(0o755)
        self.local = self.root/'packages'; self.local.mkdir()
        self.package = self.local/'new-package-1-1-aarch64.pkg.tar.xz'
        with tarfile.open(self.package, 'w:xz') as archive:
            self.add(archive, '.PKGINFO', 'pkgname = new-package\npkgver = 1-1\narch = aarch64\nsize = 0\n')
        self.database(self.root/'old.db', ['old-package'])
        self.database(self.root/'new.db', ['old-package', 'new-package'])
        self.env = dict(os.environ, PATH=str(self.tools)+':'+os.environ['PATH'],
                        TMPDIR=str(self.root), GH_REPO='fixture/repo',
                        SMOKE_FIXTURE=str(self.root), PKGDIR=str(self.local))
        for name in ('SMOKE_EXPECTED_DB', 'SMOKE_PACKAGES', 'SMOKE_FULL', 'STRICT', 'STALE', 'SYNC_FAILURE', 'CACHED_ASSET'):
            self.env.pop(name, None)

    @staticmethod
    def add(archive, name, content):
        data = content.encode()
        member = tarfile.TarInfo(name); member.size = len(data)
        archive.addfile(member, io.BytesIO(data))

    def database(self, path, names):
        with tarfile.open(path, 'w:gz') as archive:
            for name in names:
                fields = {'NAME':name, 'VERSION':'1-1', 'ARCH':'aarch64',
                          'FILENAME':f'{name}-1-1-aarch64.pkg.tar.xz',
                          'CSIZE':str(self.package.stat().st_size),
                          'SHA256SUM':hashlib.sha256(self.package.read_bytes()).hexdigest()}
                self.add(archive, f'{name}-1-1/desc', '\n\n'.join(f'%{key}%\n{value}' for key,value in fields.items())+'\n')

    def run_smoke(self, success=True, **env):
        result = subprocess.run(['bash', str(ROOT/'scripts/smoke-test.sh')], cwd=ROOT,
                                env=dict(self.env, **env), capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode == 0, success, result.stdout+result.stderr)
        calls = [json.loads(line) for line in (self.root/'calls').read_text().splitlines()]
        if success:
            self.assertEqual(json.loads((self.root/'verified').read_text()), ['new-package'])
        else:
            self.assertFalse((self.root/'verified').exists())
        return result, calls

    def test_fresh_database_verifies_changed_package(self):
        _, calls = self.run_smoke()
        self.assertEqual((self.root/'sync-count').read_text(), '1')
        self.assertFalse(any(call[0] == 'sleep' for call in calls))

    def test_stale_database_is_forced_to_refresh_before_package_selection(self):
        _, calls = self.run_smoke(STALE='first')
        syncs = [call for call in calls if call[0] == 'pacman' and '-Syy' in call]
        self.assertEqual(len(syncs), 2)
        self.assertEqual(sum(call[0] == 'sleep' for call in calls), 1)

    def test_persistently_stale_database_fails_after_bounded_retries(self):
        result, calls = self.run_smoke(success=False, STALE='always')
        self.assertIn('after 12 attempts', result.stderr)
        self.assertEqual((self.root/'sync-count').read_text(), '12')
        self.assertEqual(sum(call[0] == 'sleep' for call in calls), 11)
        self.assertFalse(any(call[0] == 'curl' for call in calls))

    def test_sync_failure_can_recover(self):
        self.run_smoke(SYNC_FAILURE='first')
        self.assertEqual((self.root/'sync-count').read_text(), '3')

    def test_signature_failure_never_relaxes_strict_policy(self):
        result, _ = self.run_smoke(success=False, STRICT='1', SYNC_FAILURE='always')
        self.assertIn('invalid database signature', result.stderr)
        self.assertIn('PackageRequired DatabaseRequired TrustedOnly', (self.root/'pacman.conf').read_text())
        self.assertEqual((self.root/'sync-count').read_text(), '24')

    def test_publisher_database_overrides_stale_api_asset(self):
        self.run_smoke(CACHED_ASSET='1', SMOKE_EXPECTED_DB=str(self.root/'new.db'))
        self.assertEqual((self.root/'sync-count').read_text(), '1')

    def test_local_archive_mismatch_still_fails(self):
        with tarfile.open(self.package, 'w:xz') as archive:
            self.add(archive, '.PKGINFO', 'pkgname = new-package\npkgver = 1-1\narch = aarch64\nsize = 0\n')
            self.add(archive, 'payload', 'changed')
        result, _ = self.run_smoke(success=False)
        self.assertIn('Local smoke archive differs from published database', result.stderr)


if __name__ == '__main__':
    unittest.main()
