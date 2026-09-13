#!/usr/bin/env python3
"""Real libalpm Required/TrustedOnly downloads into an isolated root; fixture keys only."""
import importlib.util,json,os,shutil,subprocess,tempfile
from pathlib import Path
require_root=os.geteuid()==0
if not require_root:raise SystemExit('Run this fixture in an isolated root namespace/container')
spec=importlib.util.spec_from_file_location('key_tests',Path(__file__).with_name('test-package-signing.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
keys=module.SigningTests;keys.setUpClass();s=module.s
root=keys.root/'pacman';root.mkdir();repo=root/'repo';repo.mkdir();tree=root/'payload';tree.mkdir()
def run(*args,ok=True):
 r=subprocess.run(list(map(str,args)),stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if ok and r.returncode:raise RuntimeError(r.stdout.decode())
 return r
try:
 (tree/'.PKGINFO').write_text('pkgname = signed-fixture\npkgbase = signed-fixture\npkgver = 1-1\npkgdesc = signature fixture\narch = any\nsize = 1\nbuilddate = 1\n')
 (tree/'fixture').write_text('x');archive=repo/'signed-fixture-1-1-any.pkg.tar.gz';run('bsdtar','-czf',archive,'-C',tree,'.PKGINFO','fixture')
 ring=s.Keyring(keys.public,keys.policy,secret=True)
 try:ring.sign(archive)
 finally:ring.close()
 original=archive.read_bytes()
 def database(embedded=True):
  for f in repo.glob('omarchy-aarch64.*'):f.unlink()
  cmd=['repo-add','--quiet']+(['--include-sigs'] if embedded else [])+[str(repo/'omarchy-aarch64.db.tar.zst'),str(archive)]
  run(*cmd)
  for kind in ['db','files']:
   (repo/f'omarchy-aarch64.{kind}').unlink();shutil.copyfile(repo/f'omarchy-aarch64.{kind}.tar.zst',repo/f'omarchy-aarch64.{kind}')
  ring=s.Keyring(keys.public,keys.policy,secret=True)
  try:
   for p in s.databases(repo):ring.sign(p)
  finally:ring.close()
 database()
 trust=root/'trust';run('pacman-key','--gpgdir',trust,'--init');run('pacman-key','--gpgdir',trust,'--add',keys.public);run('pacman-key','--gpgdir',trust,'--lsign-key',keys.primary)
 def attempt(name,success):
  task=root/name;task.mkdir();(task/'root').mkdir();(task/'db').mkdir();(task/'cache').mkdir()
  config=task/'pacman.conf';config.write_text(f'[options]\nArchitecture = auto\nGPGDir = {trust}\nCacheDir = {task / "cache"}\nSigLevel = PackageRequired DatabaseRequired TrustedOnly\n[omarchy-aarch64]\nServer = file://{repo}\n')
  cmd=['pacman','--config',str(config),'--root',str(task/'root'),'--dbpath',str(task/'db'),'--noconfirm']
  first=run(*cmd,'-Sy',ok=False);second=run(*cmd,'-Sddw','signed-fixture',ok=False) if first.returncode==0 else first
  passed=first.returncode==second.returncode==0
  if passed!=success:raise RuntimeError(name+' unexpected result\n'+first.stdout.decode()+second.stdout.decode())
  print('PASS native strict pacman:',name)
 attempt('valid',True)
 archive.write_bytes(original+b'tamper');attempt('tampered-package',False);archive.write_bytes(original)
 sig=repo/'omarchy-aarch64.db.sig';saved=sig.read_bytes();sig.unlink();attempt('missing-db-signature',False);sig.write_bytes(saved)
 db=repo/'omarchy-aarch64.db';saved=db.read_bytes();db.write_bytes(saved+b'tamper');attempt('tampered-database',False);db.write_bytes(saved)
 # Remove both signature delivery mechanisms: detached and embedded.
 Path(str(archive)+'.sig').unlink();database(embedded=False);attempt('missing-package-signature',False)
finally:
 if (root/'trust').exists():run('gpgconf','--homedir',root/'trust','--kill','gpg-agent',ok=False)
 keys.tearDownClass()
