#!/usr/bin/env python3
"""Supplemental signature/bootstrap mechanics, not fresh install/upgrade/reboot."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def fixture():
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


EXPECTED = {
    'schema': 1, 'repository': 'omarchy-mac/omarchy-pkgs-aarch64', 'repository_id': 1327386148,
    'workflow_run_id': 35640738629, 'workflow_run_attempt': 1,
    'head_sha': 'fec792c8784a8bfd48d401a6d3c0bff5ec896860',
    'workflow_path': '.github/workflows/sign-and-retain-rc4-fixture.yml',
    'workflow_blob_sha': 'b02cbc65f0fecd7a02cb7e9520efe744f73710df',
    'artifact_id': 10658751342,
    'artifact_name': 'signed-rc4-exact-byte-qualification-fixture-35640738629-1',
    'size_in_bytes': 1756601650,
    'artifact_zip_sha256': '4ee0a533b1140ea3a6f480cddedd3d15e07a0d25f5822f90d53412deb727afd3',
    'candidate_manifest_sha256': '7da3256314f407eba0ebd1b4fb458aedc642992fcaae46a932db8c78af3dec66',
    'created_at': '2026-09-21T18:56:24Z',
}
RECEIPT_ID = 10658407533
RECEIPT_NAME = 'signed-rc4-fixture-transport-receipt-35640738629-1'
RECEIPT_SHA = '1e0d496251d4344bbaf9c59523d7d36f67e2670a16eabbc0e14219762a522eaa'


def rc4():
    spec = importlib.util.spec_from_file_location('rc4', Path(__file__).with_name('rc4-sign-retain.py'))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_retained_metadata(candidate, receipt_metadata, run, receipt, workflow_blob):
    helper = rc4()
    e = EXPECTED
    helper.require(receipt == e, 'Pinned receipt differs')
    helper.require(workflow_blob == e['workflow_blob_sha'], 'Workflow blob differs')
    for metadata, artifact_id, digest, name, size in (
        (candidate, e['artifact_id'], e['artifact_zip_sha256'], e['artifact_name'], e['size_in_bytes']),
        (receipt_metadata, RECEIPT_ID, RECEIPT_SHA, RECEIPT_NAME, 581),
    ):
        helper.validate_artifact_transport(metadata, artifact_id, digest, name)
        helper.require(metadata['size_in_bytes'] == size, 'Artifact size differs')
        association = metadata.get('workflow_run', {})
        helper.require(all(association.get(k) == v for k, v in {
            'id': e['workflow_run_id'], 'head_sha': e['head_sha'],
            'repository_id': e['repository_id']}.items()), 'Artifact run association differs')
    helper.require(candidate['created_at'] == e['created_at'], 'Candidate creation time differs')
    helper.require(all(run.get(k) == v for k, v in {
        'id': e['workflow_run_id'], 'run_attempt': 1, 'head_sha': e['head_sha'],
        'path': e['workflow_path'], 'event': 'workflow_dispatch',
        'status': 'completed', 'conclusion': 'success'}.items()), 'Candidate run differs')
    helper.require(run.get('repository', {}).get('id') == e['repository_id'] and
                   run['repository'].get('full_name') == e['repository'], 'Run repository differs')


def extract_checked(archive, output, digest, size):
    import stat
    import zipfile
    helper = rc4()
    helper.require(archive.stat().st_size == size and helper.digest(archive) == digest, 'Downloaded ZIP bytes differ')
    helper.require(not output.exists(), 'Extraction target already exists')
    with zipfile.ZipFile(archive) as z:
        seen = set()
        for entry in z.infolist():
            name = entry.filename.rstrip('/')
            kind = stat.S_IFMT(entry.external_attr >> 16)
            helper.require(name not in ('', '.') and str(helper.PurePosixPath(name)) == name and
                           helper.safe_archive_member(name) and name not in seen and
                           kind in (0, stat.S_IFREG, stat.S_IFDIR), 'Unsafe ZIP member')
            seen.add(name)
        output.mkdir(parents=True)
        z.extractall(output)


def download_zip(artifact_id, archive):
    # Pass auth via stdin, not argv or an exception containing argv. Do not emit
    # curl's redirect diagnostics, which can include a signed transport URL.
    result = subprocess.run([
        'curl', '--fail', '--silent', '--location', '--max-time', '1200',
        '--header', '@-', '--header', 'Accept: application/vnd.github+json',
        'https://api.github.com/repos/'+EXPECTED['repository']+f'/actions/artifacts/{artifact_id}/zip',
        '--output', str(archive)],
        input=('Authorization: Bearer '+os.environ['GH_TOKEN']+'\n').encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    rc4().require(result.returncode == 0, 'Artifact ZIP download failed')


def acquire_retained(output):
    helper = rc4()
    e = EXPECTED
    helper.require(os.environ.get('GITHUB_ACTIONS') == 'true' and
                   os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
                   os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
                   os.environ.get('GITHUB_REPOSITORY') == e['repository'] and
                   os.environ.get('GITHUB_REPOSITORY_ID') == str(e['repository_id']),
                   'Acquisition requires exact hosted dispatch context')
    helper.require(not output.exists(), 'Acquisition target must be new')
    output.mkdir(parents=True)
    prefix = '/repos/' + e['repository']
    def api(path):
        return json.loads(helper.github_request(prefix+path, os.environ['GH_TOKEN']))
    candidate = api(f'/actions/artifacts/{e["artifact_id"]}')
    receipt_meta = api(f'/actions/artifacts/{RECEIPT_ID}')
    run = api(f'/actions/runs/{e["workflow_run_id"]}/attempts/1')
    blob = api('/contents/'+e['workflow_path']+'?ref='+e['head_sha'])['sha']
    # Fail before large download if independently fetched metadata differs.
    validate_retained_metadata(candidate, receipt_meta, run, dict(e), blob)
    for metadata, digest, name, size in ((receipt_meta, RECEIPT_SHA, RECEIPT_NAME, 581),
                                       (candidate, e['artifact_zip_sha256'], e['artifact_name'], e['size_in_bytes'])):
        meta_path = output/(str(metadata['id'])+'.json')
        meta_path.write_text(json.dumps(metadata))
        subprocess.run([sys.executable, str(Path(__file__).with_name('rc4-sign-retain.py')),
                        'validate-artifact-transport', '--metadata', str(meta_path),
                        '--artifact-id', str(metadata['id']), '--expected-digest', digest,
                        '--expected-name', name], check=True)
        archive = output/(str(metadata['id'])+'.zip')
        download_zip(metadata['id'], archive)
        target = output/('receipt' if metadata['id'] == RECEIPT_ID else 'candidate')
        extract_checked(archive, target, digest, size)
        if metadata['id'] == RECEIPT_ID:
            helper.require({p.name for p in target.iterdir()} == {'transport-receipt.json'}, 'Receipt inventory differs')
            validate_retained_metadata(candidate, receipt_meta, run,
                                      json.loads((target/'transport-receipt.json').read_text()), blob)
    helper.require(helper.digest(output/'candidate/candidate-manifest.json') == e['candidate_manifest_sha256'],
                   'Retained manifest digest differs')
    print('PASS retained ZIP, receipt, run and manifest identity (native signatures not yet tested)')


def signature_result(name, result, success):
    import re
    text = result.stdout.decode(errors='replace')
    signature_error = re.search(
        r'invalid or corrupted (?:package|database) \(PGP signature\)|'
        r'missing (?:required|PGP) signature|required key missing from keyring|'
        r'signature from .*(?:unknown trust|marginal trust|invalid)|invalid signature', text, re.I)
    if (success and (result.returncode != 0 or 'error:' in text.lower())) or (not success and (result.returncode == 0 or not signature_error)):
        raise RuntimeError(name+' unexpected result\n'+text)
    print('PASS supplemental native trust:', name, flush=True)


def retained_candidate(candidate):
    import platform
    helper = rc4()
    helper.require(os.geteuid() == 0 and platform.machine() == 'aarch64' and
                   os.environ.get('RC4_DISPOSABLE_CONTAINER') == '1',
                   'Retained tests require the disposable native ARM64 Arch container')
    os.environ['LC_ALL'] = 'C'
    for tool in ('pacman', 'pacman-key', 'pacman-conf', 'gpg', 'gpgconf', 'bsdtar', 'zstd', 'xz', 'vercmp', 'bash', 'cp'):
        helper.require(shutil.which(tool), 'Missing native tool: '+tool)
    def command(*args, ok=True):
        result = subprocess.run(list(map(str, args)), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if ok and result.returncode:
            raise RuntimeError(result.stdout.decode(errors='replace'))
        return result
    helper.require(command('pacman-conf', 'Architecture').stdout.strip() == b'aarch64', 'pacman architecture differs')
    signing = helper.load_signing_module()
    helper.require(helper.digest(signing.PUBLIC) == helper.PUBLIC_KEY_SHA256 and
                   helper.digest(signing.POLICY) == helper.SIGNING_POLICY_SHA256, 'Independent public trust pin differs')
    subprocess.run([sys.executable, str(Path(__file__).with_name('rc4-sign-retain.py')),
                    'validate-candidate', '--candidate', str(candidate),
                    '--candidate-manifest', str(candidate/'candidate-manifest.json'),
                    '--candidate-manifest-sha256', EXPECTED['candidate_manifest_sha256']], check=True)
    manifest = json.loads((candidate/'candidate-manifest.json').read_text())
    for field, expected in [('workflow_run_id', EXPECTED['workflow_run_id']),
                            ('workflow_run_attempt', 1), ('workflow_head_sha', EXPECTED['head_sha']),
                            ('workflow_blob_sha', EXPECTED['workflow_blob_sha'])]:
        helper.require(manifest[field] == expected, 'Candidate execution linkage differs')
    package_name = 'omarchy-mac-keyring'
    filename = 'omarchy-mac-keyring-20260914-2-any.pkg.tar.xz'
    repository = candidate/'repository'
    package = repository/filename
    helper.require(package.is_file(), 'Exact keyring package missing')
    with tempfile.TemporaryDirectory(prefix='rc4-trust-') as temporary:
        work = Path(temporary)
        trusted = work/'trusted'
        unrelated = work/'unrelated'
        for ring in (trusted, unrelated):
            command('pacman-key', '--gpgdir', ring, '--init')
        # pacman-key --init generates an unrelated, ultimately trusted local key.
        helper.require(helper.PRIMARY_FINGERPRINT.encode() not in command(
            'gpg', '--homedir', unrelated, '--with-colons', '--list-keys').stdout,
            'Unrelated-only keyring contains production trust')

        def attempt(name, success, *, database=False, mutation=None, ring=trusted, runnable=False):
            with tempfile.TemporaryDirectory(prefix=name+'-', dir=work) as directory:
                task = Path(directory)
                root = task/'root'; root.mkdir()
                db = task/'db'; db.mkdir()
                cache = task/'cache'; cache.mkdir()
                repo = task/'repo'; repo.mkdir()
                # Copy only inputs needed by the case, never mutate original retained bytes.
                inputs = ['omarchy-aarch64.db', 'omarchy-aarch64.db.sig', filename, filename+'.sig'] if database else [filename, filename+'.sig']
                for name_in in inputs:
                    shutil.copyfile(repository/name_in, repo/name_in)
                if mutation == 'package':
                    with (repo/filename).open('ab') as stream: stream.write(b'tamper')
                elif mutation == 'package-signature':
                    (repo/(filename+'.sig')).unlink()
                elif mutation == 'database':
                    with (repo/'omarchy-aarch64.db').open('ab') as stream: stream.write(b'tamper')
                elif mutation == 'database-signature':
                    (repo/'omarchy-aarch64.db.sig').unlink()
                if runnable:
                    # A real runnable root for package scriptlets, not an empty --root.
                    for source in ('usr', 'etc', 'bin', 'sbin', 'lib', 'lib64'):
                        if Path('/'+source).exists():
                            command('cp', '-a', '--reflink=auto', '/'+source, root/source)
                    shutil.rmtree(root/'etc/pacman.d/gnupg', ignore_errors=True)
                    (root/'dev').mkdir()
                    import stat
                    os.mknod(root/'dev/null', stat.S_IFCHR | 0o666, os.makedev(1, 3))
                    os.mknod(root/'dev/urandom', stat.S_IFCHR | 0o666, os.makedev(1, 9))
                    (root/'var/lib/pacman').mkdir(parents=True)
                    command('cp', '-a', '--reflink=auto', '/var/lib/pacman/local', db/'local')
                    (root/'tmp').mkdir(mode=0o1777)
                config = task/'pacman.conf'
                config.write_text(f'[options]\nArchitecture = aarch64\nGPGDir = {ring}\nCacheDir = {cache}\n'
                                  'SigLevel = PackageRequired DatabaseRequired TrustedOnly\n'
                                  'LocalFileSigLevel = Required TrustedOnly\n'
                                  f'[omarchy-aarch64]\nServer = file://{repo}\n')
                cmd = ['pacman', '--config', config, '--root', root, '--dbpath', db,
                       '--logfile', task/'pacman.log', '--noconfirm']
                if database:
                    result = command(*cmd, '-Sy', ok=False)
                    if success and result.returncode == 0:
                        result = command(*cmd, '-Sddw', package_name, ok=False)
                    signature_result(name, result, success)
                else:
                    # -U uses the detached signature; embedded DB signatures cannot mask absence.
                    result = command(*cmd, '-Udd', repo/filename, ok=False)
                    signature_result(name, result, success)
                    if success:
                        helper.require(command(*cmd, '-Q', package_name).stdout.strip() ==
                                       b'omarchy-mac-keyring 20260914-2', 'Exact package installation not recorded')
                        helper.require(helper.digest(root/'usr/share/pacman/keyrings/omarchy-mac.gpg') ==
                                       helper.PUBLIC_KEY_SHA256, 'Installed keyring payload differs')
                        helper.require('ALPM-SCRIPTLET' in (task/'pacman.log').read_text() or
                                       b'Initialize pacman trust' in result.stdout,
                                       'Keyring scriptlet execution not observed')

        attempt('untrusted-before-bootstrap', False, ring=trusted)
        # Only independently pinned checkout public material bootstraps this ring.
        command('pacman-key', '--gpgdir', trusted, '--add', signing.PUBLIC)
        command('pacman-key', '--gpgdir', trusted, '--lsign-key', helper.PRIMARY_FINGERPRINT)
        attempt('valid-package-install', True, runnable=True)
        attempt('modified-package', False, mutation='package')
        attempt('missing-package-signature', False, mutation='package-signature')
        attempt('unrelated-package-trust', False, ring=unrelated)
        attempt('valid-database-download', True, database=True)
        attempt('modified-database', False, database=True, mutation='database')
        attempt('missing-database-signature', False, database=True, mutation='database-signature')
        attempt('unrelated-database-trust', False, database=True, ring=unrelated)

        # Install the selected keyring into this disposable runnable container with
        # scriptlets enabled, using external pinned trust to authenticate its signature.
        bootstrap = work/'bootstrap.conf'
        bootstrap.write_text(f'[options]\nArchitecture = aarch64\nGPGDir = {trusted}\n'
                             'SigLevel = PackageRequired DatabaseRequired TrustedOnly\n'
                             'LocalFileSigLevel = Required TrustedOnly\n')
        command('pacman', '--config', bootstrap, '--noconfirm', '-U', package)
        helper.require(command('pacman', '-Q', package_name).stdout.strip() ==
                       b'omarchy-mac-keyring 20260914-2', 'Container keyring installation differs')
        fresh = work/'fresh-populated'
        command('pacman-key', '--gpgdir', fresh, '--init')
        helper.require(helper.PRIMARY_FINGERPRINT.encode() not in command(
            'gpg', '--homedir', fresh, '--with-colons', '--list-keys').stdout, 'Fresh trust DB is not fresh')
        command('pacman-key', '--gpgdir', fresh, '--populate', 'omarchy-mac')
        attempt('populated-keyring-install', True, ring=fresh, runnable=True)
    print('PASS supplemental signature/bootstrap mechanics only; no fresh install, upgrade or reboot qualification')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--retained-candidate', type=Path)
    mode.add_argument('--acquire-retained', type=Path)
    args = parser.parse_args()
    if args.acquire_retained:
        acquire_retained(args.acquire_retained)
    elif args.retained_candidate:
        retained_candidate(args.retained_candidate)
    else:
        fixture()


if __name__ == '__main__':
    main()
