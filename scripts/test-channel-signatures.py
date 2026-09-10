#!/usr/bin/python3
"""Offline real-crypto tests; every private key is disposable under short /tmp paths."""
import argparse
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location('signatures', Path(__file__).with_name('channel-signatures.py'))
signatures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signatures)
snapshot = signatures.snapshot


class SigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix='chs-key-', dir='/tmp')
        cls.home = Path(cls.keys.name)
        cls.home.chmod(0o700)
        cls.addClassCleanup(cls.cleanup_keys)
        cls.env = dict(os.environ, GNUPGHOME=str(cls.home))
        for user in ('Disposable Approved Test <approved@example.invalid>', 'Disposable Unapproved Test <wrong@example.invalid>'):
            cls.gpg('--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', user, 'ed25519', 'sign', '0')
        keys = cls.gpg('--with-colons', '--list-keys').decode()
        cls.fingerprints = [line.split(':')[9] for line in keys.splitlines() if line.startswith('fpr:')]
        cls.keyring = cls.home / 'public.gpg'
        cls.keyring.write_bytes(cls.gpg('--export'))

    @classmethod
    def cleanup_keys(cls):
        subprocess.run(['gpgconf', '--homedir', str(cls.home), '--kill', 'all'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.keys.cleanup()

    @classmethod
    def gpg(cls, *args):
        return subprocess.run(['gpg', '--no-options', '--homedir', str(cls.home), *args], env=cls.env, check=True, capture_output=True).stdout

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='chs-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.packages = self.root / 'packages'
        self.packages.mkdir()
        self.policy = self.root / 'approved.json'
        self.policy.write_text(json.dumps([self.fingerprints[0]]))
        for name in ['omarchy', 'omarchy-settings', *sorted(snapshot.STACK), 'overlay-tool']:
            path = self.package(name)
            if name in snapshot.STACK:
                self.sign(path)
        inventory = self.root / 'inventory.json'
        inventory.write_text(json.dumps(['overlay-tool', *snapshot.STACK]))
        self.input = self.root / 'unsigned'
        snapshot.prepare(argparse.Namespace(packages=str(self.packages), output=str(self.input), channel='rc',
            inventory=str(inventory), source_sha='a'*40, recipe_sha='b'*40, publisher_sha='c'*40,
            bootstrap=False, signed_inventory=None, signature_keyring=str(self.keyring)))
        self.manifest = json.loads((self.input/'channel-manifest.json').read_text())
        self.input_hash = snapshot.sha(self.input/'channel-manifest.json')
        self.request = self.root/'request.json'
        signatures.request(argparse.Namespace(snapshot=str(self.input), input_manifest_sha256=self.input_hash,
            signature_keyring=str(self.keyring), output=str(self.request)))
        self.response = self.root/'response'
        self.response.mkdir()
        self.unsigned = json.loads(self.request.read_text())['unsigned_packages']
        for row in self.unsigned:
            self.sign(self.input/row['filename'], self.response/(row['filename']+'.sig'))

    def package(self, name):
        data = f'pkgname = {name}\npkgver = 4.0.3-1\narch = aarch64\ndepend = snapper\n'.encode()
        path = self.packages/f'{name}-4.0.3-1-aarch64.pkg.tar.xz'
        with tarfile.open(path, 'w:xz') as archive:
            info = tarfile.TarInfo('.PKGINFO'); info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            if name == 'omarchy':
                archive.addfile(tarfile.TarInfo('usr/share/omarchy/install/helpers/arm-channel-manifest.py'), io.BytesIO())
        return path

    def sign(self, archive, output=None, signer=0):
        output = output or archive.with_name(archive.name+'.sig')
        self.gpg('--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '', '--local-user', self.fingerprints[signer],
                 '--output', str(output), '--detach-sign', str(archive))

    def import_args(self):
        return argparse.Namespace(snapshot=str(self.input), request=str(self.request), request_sha256=snapshot.sha(self.request),
            signatures=str(self.response), signature_keyring=str(self.keyring), approved_signers=str(self.policy),
            publisher_sha='d'*40, output=str(self.root/'signed'))

    def complete(self):
        args = self.import_args()
        signatures.import_signatures(args)
        return Path(args.output)

    def test_valid_import_preserves_all_archive_and_old_signature_bytes(self):
        output = self.complete()
        after = snapshot.verify(output, self.keyring, self.policy, True)
        self.assertEqual(snapshot.sha(self.input/'channel-manifest.json'), self.input_hash)
        self.assertNotEqual(snapshot.sha(output/'channel-manifest.json'), self.input_hash)
        self.assertEqual(after['desktop_build']['publisher_sha'], 'c'*40)
        self.assertEqual(after['publisher_sha'], 'd'*40)
        for row in self.manifest['packages']:
            self.assertEqual((self.input/row['filename']).read_bytes(), (output/row['filename']).read_bytes())
            if 'signature_sha256' in row:
                self.assertEqual((self.input/(row['filename']+'.sig')).read_bytes(), (output/(row['filename']+'.sig')).read_bytes())
        promoted = self.root/'stable'
        snapshot.promote(argparse.Namespace(snapshot=str(output), output=str(promoted), channel='stable', signature_keyring=str(self.keyring), approved_signers=str(self.policy)))
        stable = snapshot.verify(promoted, self.keyring, self.policy, True)
        self.assertEqual(after['packages'], stable['packages'])
        self.assertEqual(after['databases'], stable['databases'])
        self.assertEqual(after['signing_assembly'], stable['signing_assembly'])

    def test_missing_extra_corrupt_wrong_package_and_unapproved_signatures(self):
        first = self.response/(self.unsigned[0]['filename']+'.sig')
        original = first.read_bytes()
        other = self.response/(self.unsigned[1]['filename']+'.sig')
        cases = [('missing', None), ('corrupt', b'not a signature'), ('wrong-package', other.read_bytes())]
        for kind, content in cases:
            with self.subTest(kind=kind):
                if content is None: first.unlink()
                else: first.write_bytes(content)
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    signatures.import_signatures(self.import_args())
                self.assertFalse((self.root/'signed').exists())
                first.write_bytes(original)
        self.sign(self.input/self.unsigned[0]['filename'], first, signer=1)
        with self.assertRaisesRegex(ValueError, 'Unapproved'):
            signatures.import_signatures(self.import_args())
        first.write_bytes(original)
        existing = next(row for row in self.manifest['packages'] if 'signature_sha256' in row)
        (self.response/(existing['filename']+'.sig')).write_bytes((self.input/(existing['filename']+'.sig')).read_bytes())
        with self.assertRaisesRegex(ValueError, 'extra|replacement'):
            signatures.import_signatures(self.import_args())

    def test_unsigned_omitted_inventory_and_absent_policy_stop_before_public_access(self):
        for mode in ['unsigned', 'omitted', 'policy']:
            with self.subTest(mode=mode):
                source = self.input if mode == 'unsigned' else self.complete()
                if mode == 'omitted':
                    manifest = json.loads((source/'channel-manifest.json').read_text())
                    manifest['signed_packages'].remove('overlay-tool')
                    snapshot.write_manifest(source, manifest)
                args = argparse.Namespace(snapshot=str(source), repo='unused/never-publish', signature_keyring=str(self.keyring),
                                          approved_signers=None if mode == 'policy' else str(self.policy))
                with mock.patch.object(snapshot.subprocess, 'run', side_effect=AssertionError('No external process should be reached before inventory/policy rejection')):
                    with self.assertRaises(ValueError): snapshot.publish(args)
                if source != self.input: shutil.rmtree(source)

    def test_automatic_entry_point_stops_unsigned_snapshot_before_any_write(self):
        candidate=self.root/'candidate'; candidate.mkdir()
        (candidate/'snapshot').symlink_to(self.input, target_is_directory=True)
        binaries=self.root/'bin'; binaries.mkdir()
        marker=self.root/'public-write-attempt'
        gh=binaries/'gh'; gh.write_text('#!/bin/bash\ntouch "$PUBLIC_WRITE_MARKER"\nexit 99\n'); gh.chmod(0o755)
        env=dict(os.environ, PATH=str(binaries)+':'+os.environ['PATH'], PUBLIC_WRITE_MARKER=str(marker),
            GH_REPO='unused/never-publish', EDGE_CANDIDATE=str(candidate), EDGE_EVIDENCE=str(self.root/'unused-evidence'),
            EXPECTED_PUBLISHER_SHA='d'*40, SIGNATURE_KEYRING=str(self.keyring), APPROVED_SIGNERS=str(self.policy))
        result=subprocess.run(['bash',str(Path(__file__).with_name('publish-edge.sh'))],env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('every package',result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse((self.root/'unused-evidence').exists())
        with self.assertRaises(ValueError):
            snapshot.promote(argparse.Namespace(snapshot=str(self.input),output=str(self.root/'not-promoted'),channel='stable',
                signature_keyring=str(self.keyring),approved_signers=str(self.policy)))
        self.assertFalse((self.root/'not-promoted').exists())

    def test_tampered_archive_request_hash_and_database_signature_fail(self):
        args = self.import_args(); args.request_sha256='0'*64
        with self.assertRaisesRegex(ValueError, 'request changed'): signatures.import_signatures(args)
        archive = self.input/self.unsigned[0]['filename']; original = archive.read_bytes()
        archive.write_bytes(original+b'tampered')
        with self.assertRaisesRegex(ValueError, 'Package changed'): signatures.import_signatures(self.import_args())
        archive.write_bytes(original)
        output = self.complete()
        manifest = json.loads((output/'channel-manifest.json').read_text())
        # A hash-consistent database with a wrong embedded detached signature
        # must fail independently of archive hashes and gpgv verification.
        members=[]
        raw=subprocess.check_output(['bsdtar','-cf','-','--format=ustar','@'+str(output/'omarchy.db')])
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as db:
            for member in db:
                data=db.extractfile(member).read() if member.isfile() else None
                if data and member.name.endswith('/desc'):
                    lines=data.decode().splitlines()
                    if '%PGPSIG%' in lines:
                        lines[lines.index('%PGPSIG%')+1]=base64.b64encode(b'wrong detached bytes').decode()
                        data=('\n'.join(lines)+'\n').encode(); member.size=len(data)
                members.append((member,data))
        for name in ['omarchy.db','omarchy.db.tar.zst']:
            with tarfile.open(output/name,'w') as db:
                for member,data in members: db.addfile(member,io.BytesIO(data) if data is not None else None)
            manifest['databases'][name]=snapshot.sha(output/name)
        snapshot.write_manifest(output,manifest)
        with self.assertRaisesRegex(ValueError,'signature differs'): snapshot.verify(output,self.keyring,self.policy,True)

    def test_current_key_validity_and_primary_approved_signing_subkey(self):
        archive = self.input/self.unsigned[0]['filename']
        signature = self.root/'validity.sig'
        keyring = self.root/'validity-public.gpg'
        def generate(label, usage='sign', expiry='0', old=False):
            identity = f'Disposable {label} Test <{label}@example.invalid>'
            options = ['--faked-system-time', '1577836800'] if old else []
            self.gpg(*options, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                     '--quick-generate-key', identity, 'ed25519', usage, expiry)
            return next(line.split(':')[9] for line in self.gpg('--with-colons', '--list-keys', identity).decode().splitlines() if line.startswith('fpr:'))
        def sign_as(fingerprint, *options):
            self.gpg(*options, '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '',
                     '--local-user', fingerprint, '--output', str(signature), '--detach-sign', str(archive))
            keyring.write_bytes(self.gpg('--export'))
        expired = generate('expired', expiry='1d', old=True)
        sign_as(expired, '--faked-system-time', '1577836860')
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            snapshot.verify_signature(signature, archive, keyring, {expired})
        old = generate('expired-signature', old=True)
        sign_as(old, '--faked-system-time', '1577836860', '--default-sig-expire', '1d')
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            snapshot.verify_signature(signature, archive, keyring, {old})
        revoked = generate('revoked')
        sign_as(revoked)
        certificate = self.root/'test-revocation.asc'
        certificate.write_bytes((self.home/'openpgp-revocs.d'/f'{revoked}.rev').read_bytes().replace(b':-----BEGIN PGP PUBLIC KEY BLOCK-----', b'-----BEGIN PGP PUBLIC KEY BLOCK-----'))
        self.gpg('--batch', '--import', str(certificate))
        keyring.write_bytes(self.gpg('--export'))
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            snapshot.verify_signature(signature, archive, keyring, {revoked})
        primary = generate('subkey', usage='cert')
        self.gpg('--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-add-key', primary, 'ed25519', 'sign', '0')
        sign_as(primary)
        verified = snapshot.verify_signature(signature, archive, keyring, {primary})
        self.assertEqual(verified['primary_fingerprint'], primary)
        self.assertNotEqual(verified['signing_fingerprint'], primary)
        with self.assertRaisesRegex(ValueError, 'Unapproved'):
            snapshot.verify_signature(signature, archive, keyring, {self.fingerprints[1]})

    def test_safe_zip_accepts_exact_files_and_rejects_unsafe_entries(self):
        output=self.complete()
        bundle=self.root/'signed.zip'
        with zipfile.ZipFile(bundle,'w') as archive:
            for path in output.iterdir(): archive.write(path,path.name)
        args=argparse.Namespace(archive=str(bundle),archive_sha256=snapshot.sha(bundle),manifest_sha256=snapshot.sha(output/'channel-manifest.json'),
            signature_keyring=str(self.keyring),approved_signers=str(self.policy),output=str(self.root/'unpacked'))
        signatures.unpack(args)
        shutil.rmtree(args.output)
        for kind,name,mode in [('traversal','../escape',stat.S_IFREG|0o644),('symlink','link',stat.S_IFLNK|0o777),('duplicate','channel-manifest.json',stat.S_IFREG|0o644)]:
            with self.subTest(kind=kind):
                invalid=self.root/(kind+'.zip')
                shutil.copy2(bundle,invalid)
                with zipfile.ZipFile(invalid,'a') as archive:
                    entry=zipfile.ZipInfo(name); entry.external_attr=mode<<16
                    archive.writestr(entry,'invalid')
                args.archive=str(invalid); args.archive_sha256=snapshot.sha(invalid)
                with self.assertRaises(ValueError): signatures.unpack(args)
                self.assertFalse(Path(args.output).exists())


if __name__=='__main__':
    unittest.main()
