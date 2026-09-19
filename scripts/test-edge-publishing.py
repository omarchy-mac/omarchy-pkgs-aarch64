#!/usr/bin/env python3
"""Offline actual archive/DB/fixture-key edge transition and rolling publisher tests."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result

base = load('bootstrap_tests', 'test-bootstrap-rc.py')
boot, Fixture, Remote = base.boot, base.Fixture, base.Remote
edge = load('edge_mode', 'edge-mode.py')
smoke = load('smoke_select', 'smoke-select.py')


class EdgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Fixture.setUpClass()
        cls.root = Fixture.root
        (Fixture.source / 'version').write_text('4.0.3\n')
        boot.bundle.run('git', '-C', Fixture.source, 'add', 'version')
        Fixture.commit('Final fixture')
        cls.source = boot.bundle.run('git', '-C', Fixture.source, 'rev-parse', 'HEAD').decode().strip()
        candidates = cls.root / 'edge-candidates'; shutil.copytree(Fixture.candidates, candidates)
        for name in ('omarchy', 'omarchy-settings'):
            next(candidates.glob(name + '-4.0.3rc1-*')).unlink()
            Fixture.make_package(candidates, name, '4.0.3-1')
        Fixture.write_build_inputs(candidates, cls.source, '4.0.3')
        cls.bundle = cls.root / 'edge-bundle'
        Fixture.stage(cls.bundle, candidates, release='4.0.3', commit=cls.source)
        cls.sha = boot.bundle.digest(cls.bundle / 'manifest.json')
        cls.manifest = boot.validate(cls.bundle, cls.sha, cls.source, Fixture.keys.policy, channel='stable')
        cls.unsigned = Path(str(cls.bundle) + '.unsigned')

    @classmethod
    def tearDownClass(cls):
        Fixture.tearDownClass()

    def args(self, execute=True):
        return argparse.Namespace(bundle=self.bundle, manifest_sha256=self.sha, source_commit=self.source,
            lane='edge', publisher_commit='a'*40, expected_rc_db=boot.bundle.digest(self.unsigned/'assets'/f'{boot.DB}.db'),
            execute=execute, accept_mutable_alias_window=execute, accept_client_trust_bootstrap=True,
            trust_policy=Fixture.keys.policy, scratch=Path(tempfile.mkdtemp(dir=self.root)))

    def remote(self):
        remote = Remote()
        remote.releases['edge'] = {'draft': False, 'commit': 'b'*40,
                                  'assets': {p.name:p.read_bytes() for p in (self.unsigned/'assets').iterdir()}}
        return remote

    def publish(self, args, remote, manifest=None):
        return boot.publish_checked(args, manifest or self.manifest, remote, edge_conversion=True)

    def test_01_conversion_order_and_exact_retry(self):
        remote = self.remote(); args = self.args()
        plan = self.publish(args, remote)
        self.assertEqual(plan['lane'], 'edge')
        events = remote.events
        marker = next(i for i,e in enumerate(events) if e[:3] == ('upload','edge','edge-signing.json'))
        public = [i for i,e in enumerate(events) if e[:2] == ('read',plan['snapshot_tag']) and e[-1] is True]
        self.assertLess(max(i for i in public if i < marker), marker)
        self.assertTrue(all(i > marker for i,e in enumerate(events) if e[:2] == ('upload','edge') and e[2].endswith('.sig')))
        archives_before = {p['filename']: p['sha256'] for p in self.manifest['packages']}
        for name, digest in archives_before.items():
            self.assertEqual(__import__('hashlib').sha256(remote.releases['edge']['assets'][name]).hexdigest(), digest)
        before = len([e for e in events if e[0] == 'upload'])
        self.publish(args, remote)
        self.assertEqual(before, len([e for e in events if e[0] == 'upload']))
        self.assertFalse(any(e[1] in ('rc','stable') for e in events))

    def test_02_interrupted_conversion_never_unsigned(self):
        remote = self.remote(); args = self.args()
        signature = next(p.name for p in (self.bundle/'assets').glob('*.pkg.tar.*.sig'))
        remote.fail_upload = ('edge', signature)
        self.assertRaises(ValueError, self.publish, args, remote)
        self.assertIn('edge-signing.json', remote.releases['edge']['assets'])
        names = args.scratch/'names'; names.write_text('\n'.join(remote.releases['edge']['assets']))
        self.assertEqual(edge.mode(self.unsigned/'assets'/f'{boot.DB}.db', names), 'strict')
        remote.fail_upload = None
        self.assertIn('PASS', self.publish(args, remote)['result'])

    def test_03_guards_before_mutations(self):
        for change in ('trust','absent','draft','rc','mismatch','public'):
            remote = self.remote(); args = self.args(False); manifest = self.manifest
            if change == 'trust': args.accept_client_trust_bootstrap = False
            if change == 'absent': args.expected_rc_db = 'absent'
            if change == 'draft': remote.releases['edge']['draft'] = True
            if change == 'rc': manifest = copy.deepcopy(manifest); manifest['channel'] = 'rc'
            if change == 'mismatch':
                remote.releases['edge']['assets'][next(iter(p['filename'] for p in manifest['packages']))] = b'wrong'
            if change == 'public': remote.bad_read = ('edge', f'{boot.DB}.db')
            self.assertRaises(ValueError, self.publish, args, remote, manifest)
            self.assertFalse(any(e[0] in ('upload','create','expose','delete') for e in remote.events))

    def test_04_edge_state_and_smoke_selection(self):
        scratch = Path(tempfile.mkdtemp(dir=self.root)); names = scratch/'names'
        database = self.unsigned/'assets'/f'{boot.DB}.db'
        for extra, expected in [('', 'legacy'), ('edge-signing.json','strict'), ('orphan.sig','strict')]:
            names.write_text(f'{boot.DB}.db\n'+extra)
            self.assertEqual(edge.mode(database,names),expected)
        names.write_text(''); self.assertRaises(ValueError,edge.mode,database,names)
        names.write_text(f'{boot.DB}.db\n')
        self.assertEqual(edge.mode(self.bundle/'assets'/f'{boot.DB}.db',names),'strict')
        targets = smoke.select(database,scratch/'small')
        rows = boot.bundle.database(database)
        self.assertEqual(len(targets),1)
        self.assertEqual(int(boot.bundle.field(rows[targets[0][0]],'CSIZE')), min(int(boot.bundle.field(r,'CSIZE')) for r in rows.values()))
        local = scratch/'local'; local.mkdir()
        for name in ('omarchy','omarchy-settings'):
            filename = boot.bundle.field(rows[name],'FILENAME'); shutil.copyfile(self.unsigned/'assets'/filename,local/filename)
        targets = smoke.select(database,scratch/'selected',local,requested='omarchy')
        self.assertEqual([x[0] for x in targets],['omarchy'])
        self.assertEqual(len(list((scratch/'selected').iterdir())),1)
        self.assertEqual(len(smoke.select(database,scratch/'full',full=True)),len(rows))

    def test_05_zstd_packager_equivalence_and_functional_difference(self):
        scratch = Path(tempfile.mkdtemp(dir=self.root)); tree = scratch/'tree'; tree.mkdir()
        (tree/'payload').write_bytes(b'functional payload')
        archives=[]
        for i, packager in enumerate(('Builder One','Builder Two')):
            (tree/'.PKGINFO').write_text(f'pkgname = fixture\npkgver = 1-1\narch = any\npackager = {packager}\nbuilddate = {i}\n')
            path=scratch/f'fixture{i}.pkg.tar.zst'; boot.bundle.run('bsdtar','--zstd','-cf',path,'-C',tree,'.'); archives.append(path)
        self.assertEqual(boot.functional_payload(archives[0]),boot.functional_payload(archives[1]))
        (tree/'payload').write_bytes(b'changed'); changed=scratch/'changed.pkg.tar.zst'; boot.bundle.run('bsdtar','--zstd','-cf',changed,'-C',tree,'.')
        self.assertNotEqual(boot.functional_payload(archives[0]),boot.functional_payload(changed))
        changed.write_bytes(b'invalid'); self.assertRaises((ValueError,__import__('tarfile').ReadError),boot.functional_payload,changed)

    def test_06_dynamic_general_inventory_and_workflows(self):
        extra = copy.deepcopy(self.manifest); extra['packages'].append(dict(extra['packages'][0],name='new-configured-package'))
        inventory = {'packages':[{'name':p['name']} for p in extra['packages']]}
        with patch.object(boot.bundle,'check',return_value=extra), patch.object(Path,'read_text',return_value=json.dumps(inventory)):
            result=boot.validate(self.bundle,self.sha,self.source,Fixture.keys.policy,channel='stable')
            self.assertEqual({p['name'] for p in result['packages']},
                             {p['name'] for p in inventory['packages']})
            self.assertEqual(len(result['packages']),len(self.manifest['packages'])+1)
        import yaml
        for name in ('update-packages.yml','update-omarchy-mac.yml'):
            data=yaml.safe_load((boot.ROOT/'.github/workflows'/name).read_text())
            job=data['jobs']['publish']; self.assertEqual(job['environment'],'package-signing-edge')
            self.assertIn("github.ref == 'refs/heads/main'",job['if'])
        data=yaml.safe_load((boot.ROOT/'.github/workflows/convert-edge-signing.yml').read_text())
        self.assertEqual(set(data.get('on',data.get(True))),{'workflow_dispatch'})
        self.assertEqual(data['jobs']['bootstrap']['environment'],'package-signing')
        self.assertEqual(data['concurrency']['group'],'edge-publish')
        data=yaml.safe_load((boot.ROOT/'.github/workflows/prepare-rc-baseline.yml').read_text())
        self.assertEqual(data['concurrency'],{'group':'rc-baseline-producer','cancel-in-progress':False})
        record=next(p for p in json.loads((boot.ROOT/'packages.json').read_text())['packages'] if p['name']=='omarchy-mac-keyring')
        self.assertTrue(record['skip']); self.assertEqual(record['source'],'omarchy-mac')

    def test_07_real_rolling_unsigned_and_missing_signature_retry(self):
        scratch = Path(tempfile.mkdtemp(dir=self.root)); repo = scratch/'repo'; (repo/'scripts').mkdir(parents=True)
        for name in ('common.sh','publish.sh','package-signing.py','release-bundle.py','edge-mode.py','bootstrap-rc.py'):
            shutil.copyfile(boot.ROOT/'scripts'/name, repo/'scripts'/name)
        shutil.copyfile(boot.ROOT/'packages.json',repo/'packages.json')
        policy = repo/'pkgbuilds/omarchy-mac-keyring'; policy.mkdir(parents=True)
        shutil.copyfile(Fixture.keys.public,policy/'omarchy-mac.gpg')
        shutil.copyfile(Fixture.keys.policy,policy/'signing-policy.json')
        fakebin=scratch/'bin'; fakebin.mkdir()
        fake=fakebin/'gh'
        fake.write_text(FAKE_GH); fake.chmod(0o755)
        incoming=scratch/'incoming'; incoming.mkdir()
        package=next(p for p in self.manifest['packages'] if p['name']=='omarchy')
        filename=package['filename']; shutil.copyfile(self.bundle/'assets'/filename,incoming/filename)
        Fixture.make_package(incoming,'omarchy-mac-keyring','20260913-1',builddate=777)
        extra=next(p for p in self.manifest['packages'] if p['name']=='omarchy-mac-keyring')
        rebuilt_digest=boot.bundle.digest(incoming/extra['filename'])
        self.assertNotEqual(rebuilt_digest,extra['sha256'])
        env=dict(os.environ, PATH=str(fakebin)+os.pathsep+os.environ['PATH'], GH_REPO=boot.REPO, PKGDIR=str(incoming), REPO_TAG='edge', EVENT_LOG=str(scratch/'events'))
        for strict in (False, True):
            remote=scratch/('strict' if strict else 'legacy'); shutil.copytree((self.bundle if strict else self.unsigned)/'assets',remote)
            env['FAKE_REMOTE']=str(remote)
            env['DB_OUT']=str(scratch/('strict-output' if strict else 'legacy-output'))
            if strict: (remote/(filename+'.sig')).unlink()
            runenv=dict(env)
            if not strict:
                for name in list(runenv):
                    if name.startswith('PACMAN_SIGNING_'): del runenv[name]
            result=subprocess.run(['bash','scripts/publish.sh'],cwd=repo,env=runenv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self.assertEqual(result.returncode,0,result.stdout.decode())
            self.assertEqual(boot.bundle.digest(remote/filename),package['sha256'])
            self.assertEqual((remote/(filename+'.sig')).exists(),strict)
            self.assertEqual(boot.bundle.digest(remote/extra['filename']),extra['sha256'])
            self.assertEqual(boot.bundle.digest(Path(env['DB_OUT'])/'smoke-packages'/extra['filename']),extra['sha256'])
            self.assertEqual(boot.bundle.digest(incoming/extra['filename']),rebuilt_digest)
            if strict:
                ring=boot.bundle.signing.Keyring(Fixture.keys.public,Fixture.keys.policy)
                try:
                    ring.verify(remote/filename)
                    for path in boot.bundle.signing.databases(remote): ring.verify(path)
                finally: ring.close()
                signature=(remote/(filename+'.sig')).read_bytes()
                result=subprocess.run(['bash','scripts/publish.sh'],cwd=repo,env=runenv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                self.assertEqual(result.returncode,0,result.stdout.decode())
                self.assertEqual((remote/(filename+'.sig')).read_bytes(),signature)
                Fixture.make_package(incoming,'omarchy-mac-keyring','20260913-1',content='functional drift')
                result=subprocess.run(['bash','scripts/publish.sh'],cwd=repo,env=runenv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(b'functional payload differs',result.stdout)
                Fixture.make_package(incoming,'omarchy-mac-keyring','20260913-1',builddate=777)
                (remote/filename).write_bytes(b'collision')
                result=subprocess.run(['bash','scripts/publish.sh'],cwd=repo,env=runenv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(b'remote filename collision',result.stdout)

    def test_08_conversion_producer_reuses_exact_archive_inventory(self):
        scratch=Path(tempfile.mkdtemp(dir=self.root)); capture=scratch/'capture'
        with patch.object(boot,'GitHub',return_value=self.remote()):
            boot.capture(argparse.Namespace(lane='edge',output=capture,
                database_sha256=boot.bundle.digest(self.unsigned/'assets'/f'{boot.DB}.db')),Fixture.keys.policy)
        built=scratch/'built'; shutil.copytree(self.root/'edge-candidates',built)
        args=argparse.Namespace(capture=capture,capture_manifest_sha256=boot.bundle.digest(capture/'capture-manifest.json'),built=built,candidates=scratch/'candidate',source=Fixture.source,
                                source_commit=self.source,output=scratch/'output',edge_conversion=True,pkgrel='1')
        boot.stage_input(args,Fixture.keys.policy)
        output=boot.bundle.check(args.output,Fixture.keys.policy)
        self.assertEqual([(p['name'],p['sha256']) for p in output['packages']],[(p['name'],p['sha256']) for p in self.manifest['packages']])
        Fixture.make_package(built,'omarchy','4.0.3-1',content='changed runtime')
        args.candidates=scratch/'bad';args.output=scratch/'bad-output'
        self.assertRaisesRegex(ValueError,'payload differs',boot.stage_input,args,Fixture.keys.policy)



FAKE_GH = r'''#!/usr/bin/env python3
import json,os,sys,shutil
from pathlib import Path
args=sys.argv[1:]; root=Path(os.environ['FAKE_REMOTE'])
with open(os.environ['EVENT_LOG'],'a') as out: out.write(json.dumps(args)+'\n')
assert args[:1]==['release'] and args[2]=='edge',args
if args[1]=='view':
    names=sorted(p.name for p in root.iterdir())
    print('\n'.join(names) if '--jq' in args else json.dumps({'assets':[{'name':n} for n in names]}))
elif args[1]=='download':
    target=Path(args[args.index('--dir')+1]); target.mkdir(parents=True,exist_ok=True)
    patterns=[args[i+1] for i,x in enumerate(args) if x=='--pattern']
    for pattern in patterns:
        matches=list(root.glob(pattern)); assert matches,pattern
        for path in matches: shutil.copyfile(path,target/path.name)
elif args[1]=='upload':
    path=Path(args[3]); target=root/path.name
    assert '--clobber' in args or not target.exists()
    shutil.copyfile(path,target)
elif args[1]=='delete-asset': (root/args[3]).unlink()
else: raise AssertionError(args)
'''


if __name__ == '__main__': unittest.main()
