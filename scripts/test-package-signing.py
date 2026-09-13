#!/usr/bin/env python3
"""Real GnuPG fixture keys; no production secrets or host trust are used."""
import base64, hashlib, importlib.util, json, os, subprocess, tempfile, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('signing',Path(__file__).with_name('package-signing.py'))
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)

class SigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='signing-tests-',dir=os.environ['TMPDIR'])
        cls.root=Path(cls.temp.name);cls.home=cls.root/'primary';cls.home.mkdir(mode=0o700)
        cls.gpg=['gpg','--homedir',str(cls.home),'--batch','--pinentry-mode','loopback','--passphrase-fd','0']
        cls.password=b'fixture secret\n'
        cls.run_gpg('--quick-generate-key','Package signing fixture','ed25519','cert','1d')
        cls.primary=cls.fingerprints()[0]
        cls.run_gpg('--quick-add-key',cls.primary,'ed25519','sign','1d')
        cls.subkey=cls.fingerprints()[1]
        cls.public=cls.root/'public.gpg';cls.public.write_bytes(cls.run_gpg('--export',cls.primary))
        cls.policy=cls.root/'policy.json';cls.policy.write_text(json.dumps({'primary_fingerprint':cls.primary,'signing_subkey_fingerprint':cls.subkey,'public_key_sha256':hashlib.sha256(cls.public.read_bytes()).hexdigest()}))
        cls.env=dict(os.environ)
        os.environ.update(PACMAN_SIGNING_PRIMARY_FPR=cls.primary,PACMAN_SIGNING_SUBKEY_FPR=cls.subkey,PACMAN_SIGNING_SUBKEY_B64=base64.b64encode(cls.run_gpg('--export-secret-subkeys',cls.subkey+'!')).decode(),PACMAN_SIGNING_PASSPHRASE='fixture secret')

    @classmethod
    def run_gpg(cls,*args):
        result=subprocess.run(cls.gpg+list(args),input=cls.password,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if result.returncode:raise RuntimeError(result.stderr.decode())
        return result.stdout
    @classmethod
    def fingerprints(cls):
        return [x.split(':')[9] for x in cls.run_gpg('--with-colons','--list-keys').decode().splitlines() if x.startswith('fpr:')]
    @classmethod
    def tearDownClass(cls):
        os.environ.clear();os.environ.update(cls.env)
        subprocess.run(['gpgconf','--homedir',str(cls.home),'--kill','gpg-agent'],check=True)
        cls.temp.cleanup()
    def ring(self,secret=False):return s.Keyring(self.public,self.policy,secret)
    def test_01_sign_verify_and_retry(self):
        p=self.root/'fixture.pkg.tar.xz';p.write_bytes(b'qualified archive bytes')
        ring=self.ring(True)
        try:
            ring.sign(p);before=Path(str(p)+'.sig').read_bytes();ring.sign(p);self.assertEqual(before,Path(str(p)+'.sig').read_bytes())
        finally:ring.close()
        ring=self.ring()
        try:ring.verify(p)
        finally:ring.close()
        self.assertEqual(s.packages(self.root),[p])
    def test_02_tamper_and_missing_fail(self):
        p=self.root/'tampered';p.write_bytes(b'original');ring=self.ring(True)
        try:
            ring.sign(p);p.write_bytes(b'changed')
            with self.assertRaises(ValueError):ring.verify(p)
            Path(str(p)+'.sig').unlink()
            with self.assertRaises(ValueError):ring.verify(p)
        finally:ring.close()
    def test_03_missing_secret_and_wrong_fingerprint(self):
        old=os.environ.pop('PACMAN_SIGNING_PASSPHRASE')
        try:
            with self.assertRaises(ValueError):self.ring(True)
        finally:os.environ['PACMAN_SIGNING_PASSPHRASE']=old
        old=os.environ['PACMAN_SIGNING_SUBKEY_FPR'];os.environ['PACMAN_SIGNING_SUBKEY_FPR']='0'*40
        try:
            with self.assertRaises(ValueError):self.ring(True)
        finally:os.environ['PACMAN_SIGNING_SUBKEY_FPR']=old
    def test_04_primary_secret_rejected(self):
        old=os.environ['PACMAN_SIGNING_SUBKEY_B64'];os.environ['PACMAN_SIGNING_SUBKEY_B64']=base64.b64encode(self.run_gpg('--export-secret-keys',self.primary)).decode()
        try:
            with self.assertRaises(ValueError):self.ring(True)
        finally:os.environ['PACMAN_SIGNING_SUBKEY_B64']=old
    def test_05_database_aliases(self):
        directory=self.root/'db';directory.mkdir();ring=self.ring(True)
        try:
            for p in s.databases(directory):p.write_bytes(b'qualified database bytes');ring.sign(p);ring.verify(p)
            for p in s.databases(directory):p.write_bytes(b'changed');self.assertRaises(ValueError,ring.verify,p)
        finally:ring.close()
    def test_06_no_orphan_signature(self):
        directory=self.root/'orphan';directory.mkdir();(directory/'test.pkg.tar.xz').write_bytes(b'archive');(directory/'lost.pkg.tar.xz.sig').write_bytes(b'sig')
        with self.assertRaises(ValueError):s.packages(directory)

    def test_07_other_subkey_rejected(self):
        self.run_gpg('--quick-add-key',self.primary,'ed25519','sign','1d')
        other=self.fingerprints()[-1]
        public=self.root/'other-public.gpg';public.write_bytes(self.run_gpg('--export',self.primary))
        policy=self.root/'other-policy.json';data=json.loads(self.policy.read_text());data['public_key_sha256']=hashlib.sha256(public.read_bytes()).hexdigest();policy.write_text(json.dumps(data))
        path=self.root/'other-signer';path.write_bytes(b'archive')
        self.run_gpg('--local-user',other+'!','--output',str(path)+'.sig','--detach-sign',str(path))
        ring=s.Keyring(public,policy)
        try:self.assertRaises(ValueError,ring.verify,path)
        finally:ring.close()
    def test_07b_extra_secret_subkey_rejected(self):
        old=os.environ['PACMAN_SIGNING_SUBKEY_B64']
        os.environ['PACMAN_SIGNING_SUBKEY_B64']=base64.b64encode(self.run_gpg('--export-secret-subkeys',self.primary)).decode()
        try:
            with self.assertRaises(ValueError):self.ring(True)
        finally:os.environ['PACMAN_SIGNING_SUBKEY_B64']=old
    def test_08_expired_signature_rejected(self):
        import time
        home=self.root/'expired';home.mkdir(mode=0o700)
        gpg=['gpg','--homedir',str(home),'--batch','--pinentry-mode','loopback','--passphrase','fixture','--faked-system-time',str(int(time.time())-3*86400)+'!']
        def call(*args):return subprocess.run(gpg+list(args),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
        try:
            call('--quick-generate-key','Expired fixture','ed25519','cert','1d')
            primary=[x.split(':')[9] for x in call('--with-colons','--list-keys').decode().splitlines() if x.startswith('fpr:')][0]
            call('--quick-add-key',primary,'ed25519','sign','1d')
            sub=[x.split(':')[9] for x in call('--with-colons','--list-keys').decode().splitlines() if x.startswith('fpr:')][1]
            public=home/'public.gpg';public.write_bytes(call('--export',primary));policy=home/'policy.json';policy.write_text(json.dumps({'primary_fingerprint':primary,'signing_subkey_fingerprint':sub,'public_key_sha256':hashlib.sha256(public.read_bytes()).hexdigest()}))
            path=home/'archive';path.write_bytes(b'archive');call('--local-user',sub+'!','--output',str(path)+'.sig','--detach-sign',str(path))
            ring=s.Keyring(public,policy)
            try:self.assertRaises(ValueError,ring.verify,path)
            finally:ring.close()
        finally:subprocess.run(['gpgconf','--homedir',str(home),'--kill','gpg-agent'],check=True)
    def test_09_revoked_primary_rejected(self):
        revocation=(self.home/'openpgp-revocs.d'/f'{self.primary}.rev').read_text().replace(':-----BEGIN PGP PUBLIC KEY BLOCK-----','-----BEGIN PGP PUBLIC KEY BLOCK-----')
        subprocess.run(['gpg','--homedir',str(self.home),'--batch','--import'],input=revocation.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        public=self.root/'revoked.gpg';public.write_bytes(self.run_gpg('--export',self.primary));data=json.loads(self.policy.read_text());data['public_key_sha256']=hashlib.sha256(public.read_bytes()).hexdigest();policy=self.root/'revoked.json';policy.write_text(json.dumps(data))
        ring=s.Keyring(public,policy)
        try:self.assertRaises(ValueError,ring.verify,self.root/'fixture.pkg.tar.xz')
        finally:ring.close()

if __name__=='__main__':unittest.main()
