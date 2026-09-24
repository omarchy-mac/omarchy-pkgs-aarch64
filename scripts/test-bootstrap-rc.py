#!/usr/bin/env python3
"""Real signed 52-package fixture, in-memory GitHub recorder, zero network writes."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('bootstrap',Path(__file__).with_name('bootstrap-rc.py'))
boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)
spec=importlib.util.spec_from_file_location('bundle_tests',Path(__file__).with_name('test-release-bundle.py'))
fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
spec=importlib.util.spec_from_file_location('unsigned_publisher',Path(__file__).with_name('publish-unsigned-lane.py'))
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)

# Reuse the real archive/DB/signing fixture helpers without inheriting their tests.
class Fixture:pass
for name,value in fixtures.ReleaseBundleTests.__dict__.items():
    if isinstance(value,classmethod):setattr(Fixture,name,value)
original_stage=Fixture.stage.__func__
@classmethod
def stage_inventory(cls,*args,**kwargs):
    if not getattr(cls,'expanded',False):
        for path in cls.base.glob('fixture-app-*'):path.unlink()
        present=set(boot.bundle.archives(cls.base))
        wanted={p['name'] for p in json.loads((boot.ROOT/'packages.json').read_text())['packages']}
        for name in sorted(wanted-present-{'omarchy-mac-keyring'}):cls.make_package(cls.base,name,'1-1')
        boot.bundle.build_db(cls.base)
        shutil.copyfile(cls.base/'omarchy-aarch64.db',cls.base_db)
        for path in list(cls.base.iterdir()):
            if '.pkg.tar.' not in path.name:path.unlink()
        cls.expanded=True
    return original_stage(cls,*args,**kwargs)
Fixture.stage=stage_inventory

class Remote:
    def __init__(self):self.releases={};self.events=[];self.fail_upload=None;self.bad_read=None;self.next_id=1;self.tags={};self.fail_after_delete=None
    def release(self,tag,require_prerelease=True):
        self.events.append(('view',tag))
        if tag not in self.releases:return None
        r=self.releases[tag]
        return {'tag_name':tag,'prerelease':tag != 'stable','draft':r['draft'],'target_commitish':r['commit'],
                'asset_map':{name:{'size':len(data),'id':i+1} for i,(name,data) in enumerate(r['assets'].items())}}
    def read(self,release,name,public=False,destination=None):
        tag=release['tag_name'];self.events.append(('read',tag,name,public))
        data=self.releases[tag]['assets'][name]
        if destination is not None:destination.write_bytes(data)
        if self.bad_read==(tag,name):return 'f'*64
        return __import__('hashlib').sha256(data).hexdigest()
    def tag_commit(self,tag):return self.tags.get(tag)
    def create(self,tag,commit,body):
        self.events.append(('create',tag));assert tag in ('edge','rc','stable') or tag.startswith(('rc-baseline-','rc4-old-trust-','edge-signed-baseline-','edge-unsigned-','rc-unsigned-','stable-unsigned-'));assert tag not in self.releases
        assert self.tags.get(tag) in (None,commit);self.tags[tag]=commit
        self.releases[tag]={'draft':True,'commit':commit,'assets':{}}
    def upload(self,tag,path,clobber=False):
        self.events.append(('upload',tag,path.name,clobber))
        if self.fail_upload==(tag,path.name):raise ValueError('injected upload interruption')
        assets=self.releases[tag]['assets'];assert clobber or path.name not in assets
        if self.fail_after_delete==(tag,path.name):
            assert clobber;del assets[path.name];raise ValueError('interrupted after clobber deletion')
        assets[path.name]=path.read_bytes()
    def expose(self,tag):self.events.append(('expose',tag));self.releases[tag]['draft']=False
    def mark_latest(self,tag):self.events.append(('latest',tag));assert tag=='stable'
    def delete(self,tag,name):self.events.append(('delete',tag,name));del self.releases[tag]['assets'][name]

class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # RC4 was a one-shot 52-package transition. Exercise its historical
        # catalog even as packages.json grows; EdgeTests reuses Fixture with
        # the live catalog and does not install this scoped mock.
        inventory = (Path(__file__).parent/'fixtures/rc4/packages.json').read_text()
        read_text = Path.read_text
        def historical_catalog(path, *args, **kwargs):
            if path == boot.ROOT/'packages.json':
                return inventory
            return read_text(path, *args, **kwargs)
        catalog_patch = patch.object(Path, 'read_text', historical_catalog)
        catalog_patch.start()
        cls.addClassCleanup(catalog_patch.stop)
        Fixture.setUpClass();cls.bundle=Fixture.rc
        cls.sha=boot.bundle.digest(cls.bundle/'manifest.json');cls.source=Fixture.rc_commit
        cls.manifest=boot.validate(cls.bundle,cls.sha,cls.source,Fixture.keys.policy)
        source4=Fixture.root/'source4'
        boot.bundle.run('git','clone','--quiet','--no-hardlinks',Fixture.source,source4)
        (source4/'version').write_text('4.0.3rc4\n')
        boot.bundle.run('git','-C',source4,'add','version')
        boot.bundle.run('git','-C',source4,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','Fixture RC4')
        cls.source4=boot.bundle.run('git','-C',source4,'rev-parse','HEAD').decode().strip()
        candidates4=Fixture.root/'candidates4';shutil.copytree(Fixture.candidates,candidates4)
        for name in ('omarchy','omarchy-settings'):
            next(candidates4.glob(name+'-4.0.3rc1-*')).unlink()
            Fixture.make_package(candidates4,name,'4.0.3rc4-1')
        Fixture.write_build_inputs(candidates4,cls.source4,'4.0.3rc4')
        cls.bundle4=Fixture.root/'rc4-unsigned'
        boot.bundle.stage(argparse.Namespace(base_db=Fixture.base_db,base_packages=Fixture.base,candidates=candidates4,source=source4,source_git=None,source_commit=cls.source4,release='4.0.3rc4',output=cls.bundle4))
        cls.sha4=boot.bundle.digest(cls.bundle4/'manifest.json')
        spec=importlib.util.spec_from_file_location('transition',Path(__file__).with_name('publish-rc4-transition.py'))
        cls.transition=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.transition)

    @classmethod
    def tearDownClass(cls):Fixture.tearDownClass()
    def args(self,execute=True):
        scratch=Path(__import__('tempfile').mkdtemp(dir=Fixture.root))
        return argparse.Namespace(bundle=self.bundle,manifest_sha256=self.sha,source_commit=self.source,
                                  lane='rc',publisher_commit='a'*40,expected_rc_db='absent',execute=execute,
                                  accept_mutable_alias_window=execute,scratch=scratch)
    def publish(self,args,remote):return boot.publish_checked(args,self.manifest,remote)
    def test_versioned_keyring_bootstrap_eligibility_before_signing(self):
        # Native archive/vercmp fixture; run only in hosted Arch CI.
        for installed, accepted in [('20260914-2', True), ('20260914-1', False)]:
            with self.subTest(installed=installed):
                candidates = Fixture.root / ('eligibility-candidates-' + installed)
                shutil.copytree(Fixture.candidates, candidates)
                for name in ('omarchy', 'omarchy-mac-keyring'):
                    boot.bundle.archives(candidates)[name][0].unlink()
                Fixture.make_package(candidates, 'omarchy', '4.0.3rc1-1',
                                     keyring_dependency='omarchy-mac-keyring>=20260914-2')
                Fixture.make_package(candidates, 'omarchy-mac-keyring', installed)
                unsigned = Fixture.root / ('eligibility-unsigned-' + installed)
                boot.bundle.stage(argparse.Namespace(base_db=Fixture.base_db, base_packages=Fixture.base,
                    candidates=candidates, source=Fixture.source, source_git=None, source_commit=self.source,
                    release='4.0.3rc1', output=unsigned))
                checksum = boot.bundle.digest(unsigned / 'manifest.json')
                argv = ['bootstrap-rc.py', 'check-eligibility', '--input', str(unsigned),
                        '--manifest-sha256', checksum, '--source-commit', self.source,
                        '--trust-policy', str(Fixture.keys.policy)]
                before = {p.relative_to(unsigned).as_posix(): boot.bundle.digest(p)
                          for p in unsigned.rglob('*') if p.is_file()}
                output = Fixture.root / ('eligibility-signed-' + installed)
                with patch.object(boot.bundle.signing, 'Keyring', side_effect=AssertionError('signer reached')) as signer, \
                     patch.object(boot.bundle.tempfile, 'mkdtemp', side_effect=AssertionError('staging reached')) as staging, \
                     patch('sys.argv', argv), patch.object(boot, 'guard'):
                    if accepted:
                        boot.main()
                    else:
                        with self.assertRaisesRegex(ValueError, 'does not satisfy'):
                            boot.main()
                        args = argparse.Namespace(input=unsigned, output=output, manifest_sha256=checksum,
                            source_commit=self.source, trust_policy=Fixture.keys.policy, public_key=Fixture.keys.public)
                        with self.assertRaisesRegex(ValueError, 'does not satisfy'):
                            boot.prepare(args)
                    signer.assert_not_called()
                    staging.assert_not_called()
                self.assertFalse(output.exists())
                self.assertEqual(before, {p.relative_to(unsigned).as_posix(): boot.bundle.digest(p)
                                          for p in unsigned.rglob('*') if p.is_file()})
                if accepted:
                    with patch.object(boot, 'guard'):
                        boot.prepare(argparse.Namespace(input=unsigned, output=output, manifest_sha256=checksum,
                            source_commit=self.source, trust_policy=Fixture.keys.policy, public_key=Fixture.keys.public))
                    boot.validate(output, boot.bundle.digest(output / 'manifest.json'), self.source, Fixture.keys.policy)

    def test_signed_retry_preflight_verifies_publicly_without_derivation(self):
        # Hosted-only: real signed archives, actual check()/validate()/CLI and
        # public crypto. No mock check() and no secret authority during preflight.
        ring_type = boot.bundle.signing.Keyring
        original_init, original_verify = ring_type.__init__, ring_type.verify
        initialized, verified = [], []
        def public_init(ring, public=boot.bundle.signing.PUBLIC,
                        policy_path=boot.bundle.signing.POLICY, secret=False):
            self.assertFalse(secret, 'preflight requested secret initialization')
            initialized.append(Path(public))
            original_init(ring, public, policy_path, secret=False)
        def public_verify(ring, path):
            verified.append(Path(path))
            return original_verify(ring, path)
        before = {p.relative_to(self.bundle).as_posix(): boot.bundle.digest(p)
                  for p in self.bundle.rglob('*') if p.is_file()}
        argv = ['bootstrap-rc.py', 'check-eligibility', '--input', str(self.bundle),
                '--manifest-sha256', self.sha, '--source-commit', self.source,
                '--trust-policy', str(Fixture.keys.policy)]
        with patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                    if not k.startswith('PACMAN_SIGNING_')}, clear=True), \
             patch.object(ring_type, '__init__', public_init), \
             patch.object(ring_type, 'verify', public_verify), \
             patch.object(ring_type, 'sign', side_effect=AssertionError('sign reached')) as sign, \
             patch.object(boot.bundle.signing, 'normalize_credentials', side_effect=AssertionError('credentials reached')) as credentials, \
             patch.object(boot.bundle, 'seal', side_effect=AssertionError('seal reached')) as seal, \
             patch.object(boot, 'prepare', side_effect=AssertionError('prepare reached')) as prepare, \
             patch.object(boot.bundle, 'copy_file', side_effect=AssertionError('copy reached')) as copy_file, \
             patch.object(boot.bundle, 'build_db', side_effect=AssertionError('database derivation reached')) as build_db, \
             patch('sys.argv', argv):
            boot.main()
            for forbidden in (sign, credentials, seal, prepare, copy_file, build_db):
                forbidden.assert_not_called()
        self.assertTrue(initialized, 'actual public key initialization must run')
        expected = {path for directory in ('assets', 'rollback')
                    for path in boot.bundle.signing.packages(self.bundle / directory)
                    + boot.bundle.signing.databases(self.bundle / directory)}
        self.assertTrue(expected)
        self.assertEqual(set(verified), expected)
        self.assertEqual(before, {p.relative_to(self.bundle).as_posix(): boot.bundle.digest(p)
                                  for p in self.bundle.rglob('*') if p.is_file()})

    def test_01_exact_signed_inventory(self):
        self.assertEqual(len(self.manifest['packages']),52)
        for change in ('missing', 'extra', 'substituted', 'duplicate'):
            with self.subTest(change=change):
                changed=copy.deepcopy(self.manifest)
                if change == 'missing':changed['packages'].pop()
                elif change == 'extra':changed['packages'].append(dict(changed['packages'][0],name='future-package'))
                elif change == 'substituted':changed['packages'][0]['name']='future-package'
                else:changed['packages'][0]['name']=changed['packages'][1]['name']
                with patch.object(boot.bundle,'check',return_value=changed):
                    self.assertRaisesRegex(ValueError,'Complete exact configured package inventory',
                                           boot.validate,self.bundle,self.sha,self.source,Fixture.keys.policy)
        for digest,source in [('0'*64,self.source),(self.sha,'0'*40)]:
            self.assertRaises(ValueError,boot.validate,self.bundle,digest,source,Fixture.keys.policy)
        unsigned=Path(str(self.bundle)+'.unsigned')
        self.assertRaises(ValueError,boot.validate,unsigned,boot.bundle.digest(unsigned/'manifest.json'),self.source,Fixture.keys.policy)
    def test_02_dry_run_and_guards(self):
        remote=Remote();args=self.args(False);self.assertEqual(self.publish(args,remote)['mode'],'dry-run')
        self.assertTrue(all(e[0]=='view' for e in remote.events))
        for lane in ['edge','stable']:
            args.lane=lane;self.assertRaises(ValueError,self.publish,args,remote)
        args=self.args();args.accept_mutable_alias_window=False;self.assertRaises(ValueError,self.publish,args,remote)
    def test_03_snapshot_before_rc_and_complete_readback(self):
        remote=Remote();result=self.publish(self.args(),remote);self.assertIn('PASS',result['result'])
        snapshot=result['snapshot_tag'];events=remote.events
        public_snapshot=[i for i,e in enumerate(events) if e[:2]==('read',snapshot) and e[-1] is True]
        first_rc_create=events.index(('create','rc'));self.assertLess(max(public_snapshot),first_rc_create)
        uploads=[(i,e) for i,e in enumerate(events) if e[:2]==('upload','rc')]
        last_package=max(i for i,e in uploads if '.pkg.tar.' in e[2]);first_db=min(i for i,e in uploads if e[2].startswith('omarchy-aarch64.'))
        self.assertLess(last_package,first_db)
        self.assertEqual(len(remote.releases['rc']['assets']),len(list((self.bundle/'assets').iterdir())))
        self.assertFalse(remote.releases['rc']['draft']);self.assertFalse(any(e[0]=='delete' for e in events))
    def test_04_interruption_retry_exact_signed_bytes(self):
        remote=Remote();remote.fail_upload=('rc','omarchy-aarch64.db.sig');args=self.args()
        self.assertRaises(ValueError,self.publish,args,remote)
        self.assertNotIn('omarchy-aarch64.db',set(remote.releases['rc']['assets']))
        remote.fail_upload=None;result=self.publish(args,remote);self.assertIn('PASS',result['result'])
        before=len([e for e in remote.events if e[0]=='upload']);self.publish(args,remote)
        self.assertEqual(before,len([e for e in remote.events if e[0]=='upload']))
    def test_05_collision_and_readback_fail_closed(self):
        remote=Remote();remote.create('rc','a'*40,'');name=next((self.bundle/'assets').glob('omarchy-*.pkg.tar.*')).name
        remote.releases['rc']['assets'][name]=b'wrong';before=len(remote.events)
        self.assertRaises(ValueError,self.publish,self.args(),remote);self.assertFalse(any(e[0]=='upload' for e in remote.events[before:]))
        remote=Remote();tag=f'rc-baseline-{self.manifest["version"]}-{self.sha[:16]}'
        remote.bad_read=(tag,'manifest.json');self.assertRaises(ValueError,self.publish,self.args(),remote)
        self.assertNotIn('rc',remote.releases)
    def test_06_superseded_proven_inventory_cleanup_and_retry(self):
        remote=Remote();remote.create('rc','b'*40,'');remote.releases['rc']['draft']=False
        old=Fixture.base_db.read_bytes();remote.releases['rc']['assets']['omarchy-aarch64.db']=old
        for path in Fixture.base.iterdir():remote.releases['rc']['assets'][path.name]=path.read_bytes()
        args=self.args();args.expected_rc_db=boot.bundle.digest(Fixture.base_db)
        result=self.publish(args,remote);self.assertIn('PASS',result['result'])
        deleted=[e for e in remote.events if e[0]=='delete'];self.assertTrue(deleted)
        first_delete=next(i for i,e in enumerate(remote.events) if e[0]=='delete')
        self.assertTrue(any(e[:2]==('read','rc') and e[-1] is True for e in remote.events[:first_delete]))
        self.publish(args,remote) # old DB authorization is recovered from immutable snapshot
    def test_06b_existing_database_deleted_during_clobber_retry(self):
        remote=Remote();remote.create('rc','b'*40,'');remote.releases['rc']['draft']=False
        remote.releases['rc']['assets']['omarchy-aarch64.db']=Fixture.base_db.read_bytes()
        for path in Fixture.base.iterdir():remote.releases['rc']['assets'][path.name]=path.read_bytes()
        args=self.args();args.expected_rc_db=boot.bundle.digest(Fixture.base_db)
        remote.fail_after_delete=('rc','omarchy-aarch64.db')
        self.assertRaises(ValueError,self.publish,args,remote)
        self.assertNotIn('omarchy-aarch64.db',set(remote.releases['rc']['assets']))
        remote.fail_after_delete=None
        saved=remote.releases['rc']['assets'].pop('omarchy-aarch64.db.sig')
        before=len(remote.events);self.assertRaises(ValueError,self.publish,args,remote)
        self.assertFalse(any(e[0] in ('upload','delete','expose','create') for e in remote.events[before:]))
        remote.releases['rc']['assets']['omarchy-aarch64.db.sig']=saved
        self.assertIn('PASS',self.publish(args,remote)['result'])

    def test_06c_orphan_and_changed_snapshot_tags_refused(self):
        args=self.args();snapshot=f'rc-baseline-{self.manifest["version"]}-{self.sha[:16]}'
        for tag in ('rc',snapshot):
            remote=Remote();remote.tags[tag]='b'*40
            self.assertRaises(ValueError,self.publish,args,remote)
            self.assertFalse(any(e[0]=='create' for e in remote.events))
        remote=Remote();self.publish(args,remote);remote.tags[snapshot]='b'*40
        before=len(remote.events);self.assertRaises(ValueError,self.publish,args,remote)
        self.assertFalse(any(e[0] in ('upload','delete','expose','create') for e in remote.events[before:]))

    def test_07_unknown_old_asset_preserved(self):
        remote=Remote();remote.create('rc','a'*40,'');remote.releases['rc']['assets']['administrator-note.txt']=b'preserve'
        self.assertRaises(ValueError,self.publish,self.args(),remote)
        self.assertFalse(any(e[0]=='delete' for e in remote.events))
    def test_08_local_drift_after_validation_rejected(self):
        copied=Fixture.root/'drift';shutil.copytree(self.bundle,copied);args=self.args();args.bundle=copied
        next((copied/'assets').glob('omarchy-*.pkg.tar.*')).write_bytes(b'drift')
        remote=Remote();self.assertRaises(ValueError,self.publish,args,remote);self.assertFalse(any(e[0]=='create' for e in remote.events))

    def test_stage_requires_external_capture_approval_before_mutation(self):
        remote,args,overlay=self.overlay_capture_fixture('stage-approval')
        self.assert_overlay_capture(remote,args,overlay)
        capture=args.output
        approval=boot.bundle.digest(capture/'capture-manifest.json')
        for index,value in enumerate([None, '', 'INVALID', '0'*64, approval]):
            stage=argparse.Namespace(capture=capture,built=Fixture.candidates,
                candidates=Fixture.root/f'approval-inputs-{index}',source=Fixture.source,
                source_commit=self.source,output=Fixture.root/f'approval-output-{index}',pkgrel='1')
            if value is not None:stage.capture_manifest_sha256=value
            if value==approval:(capture/'catalog.json').write_text('{}')
            with patch.object(boot,'GitHub',side_effect=AssertionError('offline only')):
                with self.assertRaisesRegex(ValueError,'[Cc]apture|approval'):
                    boot.stage_input(stage,Fixture.keys.policy)
            self.assertFalse(stage.candidates.exists())
            self.assertFalse(stage.output.exists())
            command=['python3',boot.__file__,'stage-input','--capture',str(capture),
                '--built',str(stage.built),'--candidates',str(stage.candidates),
                '--source',str(stage.source),'--source-commit',stage.source_commit,
                '--output',str(stage.output),'--pkgrel','1']
            if value is not None:command+=['--capture-manifest-sha256',value]
            result=__import__('subprocess').run(command,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('capture',result.stderr.lower())
            self.assertNotIn('unrecognized arguments',result.stderr)
            self.assertFalse(stage.candidates.exists())
            self.assertFalse(stage.output.exists())

    def test_09_producer_capture_and_stage_complete_artifact(self):
        remote=Remote();remote.releases['edge']={'draft':False,'commit':'b'*40,'assets':{}}
        remote.releases['edge']['assets']['omarchy-aarch64.db.tar.zst']=Fixture.base_db.read_bytes()
        remote.releases['edge']['assets']['omarchy-aarch64.db']=Fixture.base_db.read_bytes()
        for path in Fixture.base.iterdir():remote.releases['edge']['assets'][path.name]=path.read_bytes()
        original=boot.GitHub;boot.GitHub=lambda scratch:remote
        capture=Fixture.root/'producer-capture'
        try:boot.capture(argparse.Namespace(database_sha256=boot.bundle.digest(Fixture.base_db),output=capture))
        finally:boot.GitHub=original
        output=Fixture.root/'producer-bundle'
        approval=boot.bundle.digest(capture/'capture-manifest.json')
        read_text=Path.read_text
        def offline(path,*args,**kwargs):
            if path==boot.ROOT/'packages.json':raise AssertionError('live catalog forbidden')
            return read_text(path,*args,**kwargs)
        with patch.object(Path,'read_text',offline), patch.object(boot,'GitHub',side_effect=AssertionError('transport forbidden')):
            boot.stage_input(argparse.Namespace(capture=capture,capture_manifest_sha256=approval,built=Fixture.candidates,candidates=Fixture.root/'producer-inputs',source=Fixture.source,source_commit=self.source,output=output,pkgrel='1'),Fixture.keys.policy)
            manifest=boot.validate(output,boot.bundle.digest(output/'manifest.json'),self.source,Fixture.keys.policy,signed=False)
            self.assertEqual(manifest['capture_manifest_sha256'],approval)
            self.assertEqual((output/'provenance/catalog.json').read_bytes(),(capture/'catalog.json').read_bytes())
            signed=Fixture.root/'producer-signed'
            boot.prepare(argparse.Namespace(input=output,output=signed,manifest_sha256=boot.bundle.digest(output/'manifest.json'),source_commit=self.source,trust_policy=Fixture.keys.policy,public_key=Fixture.keys.public))
            self.assertEqual(boot.bundle.check(signed,Fixture.keys.policy)['capture_manifest_sha256'],approval)
            for label,change in [('approval',lambda m:m.pop('capture_manifest_sha256')),
                                 ('wrong',lambda m:m.update(capture_manifest_sha256='0'*64)),
                                 ('baseline',lambda m:m.update(baseline_db_sha256='0'*64))]:
                damaged=Fixture.root/('derived-'+label);shutil.copytree(signed,damaged)
                metadata=json.loads((damaged/'manifest.json').read_text());change(metadata)
                boot.bundle.write_json(damaged/'manifest.json',metadata)
                self.assertRaises(ValueError,boot.bundle.check,damaged,Fixture.keys.policy)
        with patch.object(Path,'read_text',lambda path,*a,**kw: '{"packages":[]}' if path==boot.ROOT/'packages.json' else read_text(path,*a,**kw)):
            boot.validate(output,boot.bundle.digest(output/'manifest.json'),self.source,Fixture.keys.policy,signed=False)
        self.assertEqual(len(manifest['packages']),52)
        self.assertFalse(any(e[0] in ('upload','expose','delete') for e in remote.events))

    def overlay_capture_fixture(self, label, version='20251027-1'):
        remote=Remote()
        baseline={'omarchy-aarch64.db':Fixture.base_db.read_bytes(),
                  'omarchy-aarch64.db.tar.zst':Fixture.base_db.read_bytes()}
        baseline.update({path.name:path.read_bytes() for path in Fixture.base.iterdir()})
        remote.releases['edge']={'draft':False,'commit':'b'*40,'assets':baseline}
        overlay=Fixture.root/(label+'-overlay');overlay.mkdir()
        # Deliberately partial RC: the complete inventory must come from edge.
        Fixture.make_package(overlay,'omarchy-keyring',version,content='approved RC bytes',builddate=2)
        Fixture.make_package(overlay,'omarchy-mac-keyring','20260913-1')
        boot.bundle.build_db(overlay)
        remote.releases['rc']={'draft':False,'commit':'c'*40,
                               'assets':{path.name:path.read_bytes() for path in overlay.iterdir()}}
        args=argparse.Namespace(lane='edge',database_sha256=boot.bundle.digest(Fixture.base_db),
                                overlay_lane='rc',overlay_database_sha256=boot.bundle.digest(overlay/'omarchy-aarch64.db'),
                                output=Fixture.root/(label+'-capture'))
        return remote,args,overlay

    def assert_overlay_capture(self, remote, args, overlay):
        baseline=boot.bundle.database(Fixture.base_db)
        approved=boot.bundle.database(overlay/'omarchy-aarch64.db')
        with patch.object(boot,'GitHub',return_value=remote):
            boot.capture(args,Fixture.keys.policy)
        records=boot.bundle.database(args.output/'omarchy-aarch64.db.tar.zst')
        archives=boot.bundle.archives(args.output/'packages')
        expected=dict(baseline);expected.update(approved)
        self.assertEqual(set(records),set(expected))
        self.assertEqual(len(records),52)
        boot.bundle.validate_inventory(records,archives)
        expected_filenames={boot.bundle.field(row,'FILENAME') for row in expected.values()}
        self.assertEqual({p.name for p in (args.output/'packages').iterdir()},expected_filenames)
        for name,row in expected.items():
            filename=boot.bundle.field(row,'FILENAME')
            source=overlay if name in approved else Fixture.base
            self.assertEqual((args.output/'packages'/filename).read_bytes(),(source/filename).read_bytes())
            self.assertEqual(boot.bundle.field(records[name],'SHA256SUM'),boot.bundle.field(row,'SHA256SUM'))
        receipt=json.loads((args.output/'capture.json').read_text())
        self.assertEqual(receipt['lane_database_sha256'],args.database_sha256)
        self.assertEqual(receipt['overlay_database_sha256'],args.overlay_database_sha256)
        self.assertEqual(receipt['overlay_lane'],'rc')
        self.assertEqual(receipt['archives'],52)
        self.assertEqual(receipt['database_sha256'],boot.bundle.digest(args.output/'omarchy-aarch64.db.tar.zst'))
        self.assertIn(('read','rc','omarchy-aarch64.db.tar.zst',False),remote.events)
        self.assertFalse(any(e[0] in ('create','upload','expose','delete') for e in remote.events))
        self.assertFalse((args.output/'.overlay.db.tar.zst').exists())
        self.assertFalse((args.output/'.overlay-packages').exists())

    def test_capture_catalog_extras_are_not_adopted(self):
        remote,args,overlay=self.overlay_capture_fixture('extras')
        extra_base=Fixture.root/'extras-base';shutil.copytree(Fixture.base,extra_base)
        Fixture.make_package(extra_base,'excluded-edge-package','1-1')
        Fixture.make_package(overlay,'excluded-rc-package','1-1')
        for lane,directory in [('edge',extra_base),('rc',overlay)]:
            boot.bundle.build_db(directory)
            remote.releases[lane]['assets']={p.name:p.read_bytes() for p in directory.iterdir()}
        args.database_sha256=boot.bundle.digest(extra_base/'omarchy-aarch64.db')
        args.overlay_database_sha256=boot.bundle.digest(overlay/'omarchy-aarch64.db')
        with patch.object(boot,'GitHub',return_value=remote):boot.capture(args,Fixture.keys.policy)
        evidence=boot.check_capture(args.output,boot.bundle.digest(args.output/'capture-manifest.json'))
        self.assertEqual(evidence['excluded_catalog_extras'],{'edge':['excluded-edge-package'],'rc':['excluded-rc-package']})
        self.assertEqual(evidence['filtered_extras'],['excluded-edge-package','excluded-rc-package'])
        self.assertEqual(evidence['archives'],52)
        self.assertFalse(any(e[0]=='read' and e[2].startswith('excluded-') for e in remote.events))
        self.assertFalse(any(e[0] in ('create','upload','expose','delete') for e in remote.events))

    def test_capture_rejects_false_remote_verification(self):
        remote,args,overlay=self.overlay_capture_fixture('classification')
        remote.releases['rc']['assets']['orphan.pkg.tar.xz']=b'unknown'
        self.assert_overlay_capture(remote,args,overlay)
        evidence=json.loads((args.output/'capture.json').read_text())
        evidence['remote_assets']['rc']['orphan.pkg.tar.xz'].update(verification='downloaded-verified',sha256='0'*64,path='packages/missing')
        boot.bundle.write_json(args.output/'capture.json',evidence)
        manifest=json.loads((args.output/'capture-manifest.json').read_text())
        manifest['files']['capture.json']=boot.bundle.digest(args.output/'capture.json')
        boot.bundle.write_json(args.output/'capture-manifest.json',manifest)
        self.assertRaises(ValueError,boot.check_capture,args.output,boot.bundle.digest(args.output/'capture-manifest.json'))

    def test_capture_end_drift_has_no_success_manifest(self):
        for lane in ('edge','rc'):
            remote,args,overlay=self.overlay_capture_fixture('drift-'+lane)
            read=remote.read
            def drifting(release,name,public=False,destination=None):
                result=read(release,name,public,destination)
                if release['tag_name']=='rc' and name.endswith('.pkg.tar.gz'):
                    remote.releases[lane]['assets']['omarchy-aarch64.db']=b'changed selection'
                return result
            with patch.object(remote,'read',side_effect=drifting), patch.object(boot,'GitHub',return_value=remote):
                self.assertRaisesRegex(ValueError,'database changed during capture',boot.capture,args,Fixture.keys.policy)
            self.assertFalse((args.output/'capture-manifest.json').exists())
            self.assertFalse(any(e[0] in ('create','upload','expose','delete') for e in remote.events))

    def test_capture_offline_approval(self):
        remote,args,overlay=self.overlay_capture_fixture('offline')
        self.assert_overlay_capture(remote,args,overlay)
        digest=boot.bundle.digest(args.output/'capture-manifest.json')
        remote.releases.clear()
        with patch.object(boot,'ROOT',Fixture.root/'no-live-catalog'), patch.object(boot,'GitHub',side_effect=AssertionError('offline')):
            checked=boot.check_capture(args.output,digest)
        self.assertEqual(checked['archives'],52)
        result=boot.bundle.run('python3',Path(boot.__file__),'check-capture','--capture',args.output,'--manifest-sha256',digest)
        self.assertEqual(json.loads(result)['manifest_sha256'],digest)
        self.assertRaises(ValueError,boot.check_capture,args.output,'0'*64)
        for change in ('corrupt','missing','extra','symlink','directory-symlink'):
            with self.subTest(change=change):
                target=Fixture.root/('offline-'+change);shutil.copytree(args.output,target)
                file=next((target/'packages').iterdir())
                if change=='corrupt':file.write_bytes(b'corrupt')
                elif change=='missing':file.unlink()
                elif change=='extra':(target/'extra').write_bytes(b'extra')
                elif change=='symlink':
                    file.unlink();file.symlink_to(next((args.output/'packages').iterdir()))
                else:(target/'linked').symlink_to(args.output,target_is_directory=True)
                self.assertRaises(ValueError,boot.check_capture,target,digest)
        for change in ('schema','unsafe','identity','catalog'):
            target=Fixture.root/('offline-'+change);shutil.copytree(args.output,target)
            manifest=json.loads((target/'capture-manifest.json').read_text())
            if change=='schema':manifest['schema']=2
            elif change=='unsafe':manifest['files']['../escape']='a'*64
            else:
                name='capture.json' if change=='identity' else 'catalog.json'
                data=json.loads((target/name).read_text())
                if change=='identity':data['selected']['omarchy-keyring']['lane']='edge'
                else:data['packages'].append({'name':'new-required-package'})
                boot.bundle.write_json(target/name,data)
                manifest['files'][name]=boot.bundle.digest(target/name)
            boot.bundle.write_json(target/'capture-manifest.json',manifest)
            self.assertRaises(ValueError,boot.check_capture,target,boot.bundle.digest(target/'capture-manifest.json'))

    def test_capture_offline_rejects_baseline_only_overlay_keyring(self):
        remote,args,overlay=self.overlay_capture_fixture('offline-baseline-keyring')
        self.assert_overlay_capture(remote,args,overlay)
        evidence=json.loads((args.output/'capture.json').read_text())
        keyring='omarchy-mac-keyring'
        filename=evidence['selected'][keyring]['filename']
        baseline=Fixture.root/'offline-keyring-baseline';shutil.copytree(Fixture.base,baseline)
        shutil.copyfile(args.output/'packages'/filename,baseline/filename)
        partial=Fixture.root/'offline-keyring-overlay';partial.mkdir()
        for archive in overlay.glob('*.pkg.tar.*'):
            if archive.name != filename:shutil.copyfile(archive,partial/archive.name)
        # Keep all retained bytes and evidence consistent, but move the trust
        # anchor to the baseline only. Reapproval must not bypass overlay policy.
        observation=evidence['remote_assets']['rc'].pop(filename)
        observation['metadata']['id']=max(item['metadata']['id'] for item in evidence['remote_assets']['edge'].values())+1
        evidence['remote_assets']['edge'][filename]=observation
        evidence['selected'][keyring]['lane']='edge'
        for lane,directory,hash_field in [('edge',baseline,'lane_database_sha256'),('rc',partial,'overlay_database_sha256')]:
            boot.bundle.build_db(directory)
            source=args.output/'sources'/f'{lane}.db'
            shutil.copyfile(directory/'omarchy-aarch64.db',source)
            evidence[hash_field]=boot.bundle.digest(source)
            for name,item in evidence['remote_assets'][lane].items():
                item['metadata']['size']=(directory/name).stat().st_size
                if item.get('path') == f'sources/{lane}.db':item['sha256']=evidence[hash_field]
        self.assertIn(keyring,boot.bundle.database(args.output/'sources/edge.db'))
        self.assertNotIn(keyring,boot.bundle.database(args.output/'sources/rc.db'))
        boot.bundle.write_json(args.output/'capture.json',evidence)
        manifest_path=args.output/'capture-manifest.json'
        old_approval=boot.bundle.digest(manifest_path)
        manifest=json.loads(manifest_path.read_text())
        manifest['files']={name:boot.bundle.digest(args.output/name) for name in manifest['files']}
        boot.bundle.write_json(manifest_path,manifest)
        approval=boot.bundle.digest(manifest_path)
        self.assertNotEqual(approval,old_approval)
        with patch.object(boot,'ROOT',Fixture.root/'no-live-catalog'), patch.object(boot,'GitHub',side_effect=AssertionError('offline')):
            self.assertRaisesRegex(ValueError,'Overlay must include the installed trust anchor',boot.check_capture,args.output,approval)

    def test_capture_retains_frozen_evidence(self):
        remote,args,overlay=self.overlay_capture_fixture('frozen')
        remote.releases['rc']['assets']['build-inputs.txt']=b'known provenance\n'
        remote.releases['rc']['assets']['orphan.pkg.tar.xz']=b'not selected'
        self.assert_overlay_capture(remote,args,overlay)
        self.assertEqual((args.output/'sources/edge.db').read_bytes(),Fixture.base_db.read_bytes())
        self.assertEqual((args.output/'sources/rc.db').read_bytes(),(overlay/'omarchy-aarch64.db').read_bytes())
        self.assertEqual(json.loads((args.output/'catalog.json').read_text()),json.loads((boot.ROOT/'packages.json').read_text()))
        self.assertEqual((args.output/'sources/rc-build-inputs.txt').read_bytes(),b'known provenance\n')
        evidence=json.loads((args.output/'capture.json').read_text())
        self.assertEqual(evidence['selected']['omarchy-keyring']['lane'],'rc')
        orphan=evidence['remote_assets']['rc']['orphan.pkg.tar.xz']
        self.assertEqual(orphan['classification'],'unreferenced')
        self.assertEqual(orphan['verification'],'metadata-only')
        self.assertNotIn('sha256',orphan)
        self.assertFalse(any(e[:3]==('read','rc','orphan.pkg.tar.xz') for e in remote.events))
        manifest=json.loads((args.output/'capture-manifest.json').read_text())
        self.assertEqual(manifest['schema'],1)
        self.assertEqual(set(manifest['files']),{p.relative_to(args.output).as_posix() for p in args.output.rglob('*') if p.is_file()}-{'capture-manifest.json'})
        for name,digest in manifest['files'].items():
            self.assertEqual(boot.bundle.digest(args.output/name),digest)

    def test_09a_partial_overlay_preserves_same_filename_approved_bytes(self):
        remote,args,overlay=self.overlay_capture_fixture('same-filename')
        name='omarchy-keyring-20251027-1-any.pkg.tar.gz'
        self.assertNotEqual((Fixture.base/name).read_bytes(),(overlay/name).read_bytes())
        self.assert_overlay_capture(remote,args,overlay)

    def test_09b_partial_overlay_replaces_different_version_by_package_name(self):
        remote,args,overlay=self.overlay_capture_fixture('different-version',version='20260919-1')
        self.assert_overlay_capture(remote,args,overlay)
        self.assertFalse((args.output/'packages/omarchy-keyring-20251027-1-any.pkg.tar.gz').exists())

    def test_09c_overlay_capture_rejects_stale_or_incomplete_inputs(self):
        cases=[('stale-baseline','Published selected database differs'),
               ('incomplete-baseline','missing required baseline packages'),
               ('missing-baseline-archive','Baseline archive is absent'),
               ('stale-overlay','Published overlay database differs'),
               ('changed-overlay-archive','Captured overlay archive differs')]
        for kind,message in cases:
            with self.subTest(kind=kind):
                remote,args,overlay=self.overlay_capture_fixture(kind)
                edge_assets=remote.releases['edge']['assets']
                rc_assets=remote.releases['rc']['assets']
                name='omarchy-keyring-20251027-1-any.pkg.tar.gz'
                if kind=='stale-baseline':
                    args.database_sha256='0'*64
                elif kind=='incomplete-baseline':
                    incomplete=Fixture.root/'incomplete-db';incomplete.mkdir()
                    for path in Fixture.base.iterdir():
                        if path.name!=name:shutil.copyfile(path,incomplete/path.name)
                    boot.bundle.build_db(incomplete)
                    for suffix in ('db','db.tar.zst'):
                        edge_assets['omarchy-aarch64.'+suffix]=(incomplete/('omarchy-aarch64.'+suffix)).read_bytes()
                    args.database_sha256=boot.bundle.digest(incomplete/'omarchy-aarch64.db')
                elif kind=='missing-baseline-archive':
                    del edge_assets[name]
                elif kind=='stale-overlay':
                    args.overlay_database_sha256='0'*64
                else:
                    rc_assets[name]+=b'changed after approval'
                with patch.object(boot,'GitHub',return_value=remote):
                    with self.assertRaisesRegex(ValueError,message):
                        boot.capture(args,Fixture.keys.policy)
                self.assertFalse((args.output/'capture.json').exists())
                self.assertFalse(any(e[0] in ('create','upload','expose','delete') for e in remote.events))

    def test_10_stage_input_requires_explicit_pkgrel_and_matching_identity(self):
        remote=Remote();remote.releases['edge']={'draft':False,'commit':'b'*40,'assets':{}}
        remote.releases['edge']['assets']['omarchy-aarch64.db.tar.zst']=Fixture.base_db.read_bytes()
        remote.releases['edge']['assets']['omarchy-aarch64.db']=Fixture.base_db.read_bytes()
        for path in Fixture.base.iterdir():remote.releases['edge']['assets'][path.name]=path.read_bytes()
        original=boot.GitHub;boot.GitHub=lambda scratch:remote
        capture=Fixture.root/'pkgrel-capture'
        try:boot.capture(argparse.Namespace(database_sha256=boot.bundle.digest(Fixture.base_db),output=capture))
        finally:boot.GitHub=original
        missing=argparse.Namespace(capture=capture,capture_manifest_sha256=boot.bundle.digest(capture/'capture-manifest.json'),built=Fixture.candidates,candidates=Fixture.root/'pkgrel-missing',source=Fixture.source,source_commit=self.source,output=Fixture.root/'pkgrel-missing-bundle')
        with self.assertRaisesRegex(ValueError,'Explicit package release number required'):boot.stage_input(missing,Fixture.keys.policy)
        mismatch=copy.copy(missing); mismatch.pkgrel='2'; mismatch.candidates=Fixture.root/'pkgrel-mismatch'; mismatch.output=Fixture.root/'pkgrel-mismatch-bundle'
        with self.assertRaisesRegex(ValueError,'identity must match explicit pkgrel'):boot.stage_input(mismatch,Fixture.keys.policy)

    def transition_args(self,execute=True):
        args=self.args(execute);args.bundle=self.bundle4;args.manifest_sha256=self.sha4;args.source_commit=self.source4
        args.accept_final_old_trust_publication=True
        return args
    def transition_publish(self,args,remote):
        manifest=self.transition.validate(args,Fixture.keys.policy)
        return boot.publish_checked(args,manifest,remote,old_trust_transition=True)
    def test_12_old_trust_dry_run_explicit_acceptance_and_version_guards(self):
        args=self.transition_args(False);remote=Remote()
        self.assertEqual(self.transition_publish(args,remote)['mode'],'dry-run')
        self.assertFalse(any(e[0] in ('create','upload','expose','delete') for e in remote.events))
        args.accept_final_old_trust_publication=False
        self.assertRaises(ValueError,self.transition_publish,args,remote)
        args=self.args();args.accept_final_old_trust_publication=True
        self.assertRaises(ValueError,self.transition_publish,args,Remote()) # strict signed input
        manifest=json.loads((self.bundle4/'manifest.json').read_text())
        for version in ('4.0.3rc5-1','4.0.3-1','4.0.3rc40-1'):
            changed=copy.deepcopy(manifest);changed['version']=version
            self.assertRaises(ValueError,boot.publish_checked,self.transition_args(),changed,Remote(),old_trust_transition=True)
        args=self.transition_args();args.lane='edge'
        self.assertRaises(ValueError,self.transition_publish,args,Remote())
        args=self.transition_args();args.accept_mutable_alias_window=False
        self.assertRaises(ValueError,self.transition_publish,args,Remote())
    def test_13_old_trust_existing_assets_readback_and_deleted_db_retry(self):
        remote=Remote();remote.create('rc','b'*40,'');remote.releases['rc']['draft']=False
        remote.releases['rc']['assets']['omarchy-aarch64.db']=Fixture.base_db.read_bytes()
        for path in Fixture.base.iterdir():remote.releases['rc']['assets'][path.name]=path.read_bytes()
        args=self.transition_args();args.expected_rc_db=boot.bundle.digest(Fixture.base_db)
        remote.fail_after_delete=('rc','omarchy-aarch64.db')
        self.assertRaises(ValueError,self.transition_publish,args,remote)
        self.assertNotIn('omarchy-aarch64.db',set(remote.releases['rc']['assets']))
        remote.fail_after_delete=None
        proof=remote.releases['rc']['assets'].pop('omarchy-aarch64.db.tar.zst')
        before=len(remote.events);self.assertRaises(ValueError,self.transition_publish,args,remote)
        self.assertFalse(any(e[0] in ('create','upload','delete','expose') for e in remote.events[before:]))
        remote.releases['rc']['assets']['omarchy-aarch64.db.tar.zst']=proof
        result=self.transition_publish(args,remote);self.assertIn('PASS',result['result'])
        self.assertTrue(result['snapshot_tag'].startswith('rc4-old-trust-'))
        self.assertFalse(any(name.endswith('.sig') for name in remote.releases['rc']['assets']))
        self.assertTrue(any(e[0]=='delete' for e in remote.events))
        self.transition_publish(args,remote)
    def test_13b_old_trust_rejects_newer_actual_database(self):
        newer=Fixture.root/'newer-rc';newer.mkdir()
        for name in ('omarchy','omarchy-settings'):Fixture.make_package(newer,name,'4.0.3rc5-1')
        boot.bundle.build_db(newer)
        remote=Remote();remote.create('rc','b'*40,'')
        remote.releases['rc']['assets']['omarchy-aarch64.db']=(newer/'omarchy-aarch64.db').read_bytes()
        args=self.transition_args();args.expected_rc_db=boot.bundle.digest(newer/'omarchy-aarch64.db')
        before=len(remote.events);self.assertRaises(ValueError,self.transition_publish,args,remote)
        self.assertFalse(any(e[0] in ('create','upload','delete','expose') for e in remote.events[before:]))

    def test_14_old_trust_refuses_signed_lane_and_wrong_anchor(self):
        remote=Remote();remote.create('rc','b'*40,'')
        remote.releases['rc']['assets']['omarchy-aarch64.db.sig']=b'already-signed'
        before=len(remote.events);self.assertRaises(ValueError,self.transition_publish,self.transition_args(),remote)
        self.assertFalse(any(e[0] in ('upload','delete','expose') for e in remote.events[before:]))
        policy=Fixture.root/'wrong-transition-policy.json'
        wrong=json.loads(Fixture.keys.policy.read_text());wrong['public_key_sha256']='0'*64;policy.write_text(json.dumps(wrong))
        self.assertRaises(ValueError,self.transition.validate,self.transition_args(),policy)

    def test_15_old_trust_revocation_and_embedded_signatures_refused(self):
        for kind,revoked in [('revoked',Fixture.keys.primary+'\n'),('missing-revoked',None)]:
            candidates=Fixture.root/(kind+'-candidates');shutil.copytree(Fixture.root/'candidates4',candidates)
            Fixture.make_package(candidates,'omarchy-mac-keyring','20260913-1',revoked=revoked)
            output=Fixture.root/(kind+'-bundle')
            boot.bundle.stage(argparse.Namespace(base_db=Fixture.base_db,base_packages=Fixture.base,candidates=candidates,source=Fixture.root/'source4',source_git=None,source_commit=self.source4,release='4.0.3rc4',output=output))
            args=self.transition_args();args.bundle=output;args.manifest_sha256=boot.bundle.digest(output/'manifest.json')
            self.assertRaises((ValueError,__import__('subprocess').CalledProcessError),self.transition_publish,args,Remote())
        output=Fixture.root/'embedded-signature';shutil.copytree(self.bundle4,output)
        extracted=Fixture.root/'embedded-db';extracted.mkdir()
        boot.bundle.run('bsdtar','-xf',output/'assets/omarchy-aarch64.db','-C',extracted)
        desc=next(extracted.glob('omarchy-*/desc'));desc.write_text(desc.read_text()+'%PGPSIG%\nRklYVFVSRQ==\n\n')
        boot.bundle.run('bsdtar','--zstd','-cf',output/'assets/omarchy-aarch64.db.tar.zst','-C',extracted,*sorted(p.name for p in extracted.iterdir()))
        shutil.copyfile(output/'assets/omarchy-aarch64.db.tar.zst',output/'assets/omarchy-aarch64.db')
        manifest=json.loads((output/'manifest.json').read_text())
        for name in ('omarchy-aarch64.db','omarchy-aarch64.db.tar.zst'):manifest['files']['assets/'+name]=boot.bundle.digest(output/'assets'/name)
        boot.bundle.write_json(output/'manifest.json',manifest)
        args=self.transition_args();args.bundle=output;args.manifest_sha256=boot.bundle.digest(output/'manifest.json')
        boot.validate(output,args.manifest_sha256,args.source_commit,Fixture.keys.policy,signed=False)
        self.assertRaisesRegex(ValueError,'Embedded package signatures',self.transition_publish,args,Remote())

    def test_16_rc4_capture_to_rc5_reuses_exact_keyring_before_signing(self):
        remote=Remote();remote.releases['rc']={'draft':False,'commit':'b'*40,'assets':{}}
        for path in (self.bundle4/'assets').iterdir():remote.releases['rc']['assets'][path.name]=path.read_bytes()
        original=boot.GitHub;boot.GitHub=lambda scratch:remote
        capture=Fixture.root/'rc4-capture'
        approved=boot.bundle.digest(self.bundle4/'assets/omarchy-aarch64.db.tar.zst')
        selected=remote.releases['rc']['assets']['omarchy-aarch64.db']
        try:
            remote.releases['rc']['draft']=True
            self.assertRaisesRegex(ValueError,'already be published',boot.capture,argparse.Namespace(lane='rc',database_sha256=approved,output=Fixture.root/'draft-capture'),Fixture.keys.policy)
            remote.releases['rc']['draft']=False
            del remote.releases['rc']['assets']['omarchy-aarch64.db']
            self.assertRaisesRegex(ValueError,'selected database',boot.capture,argparse.Namespace(lane='rc',database_sha256=approved,output=Fixture.root/'absent-selected-capture'),Fixture.keys.policy)
            remote.releases['rc']['assets']['omarchy-aarch64.db']=b'different selected DB'
            self.assertRaisesRegex(ValueError,'selected database',boot.capture,argparse.Namespace(lane='rc',database_sha256=approved,output=Fixture.root/'different-selected-capture'),Fixture.keys.policy)
            remote.releases['rc']['assets']['omarchy-aarch64.db']=selected
            boot.capture(argparse.Namespace(lane='rc',database_sha256=approved,output=capture),Fixture.keys.policy)
        finally:boot.GitHub=original
        source=Fixture.root/'source5';boot.bundle.run('git','clone','--quiet','--no-hardlinks',Fixture.root/'source4',source)
        (source/'version').write_text('4.0.3rc5\n');boot.bundle.run('git','-C',source,'add','version')
        boot.bundle.run('git','-C',source,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','Fixture RC5')
        commit=boot.bundle.run('git','-C',source,'rev-parse','HEAD').decode().strip()
        built=Fixture.root/'built5';shutil.copytree(Fixture.root/'candidates4',built)
        for name in ('omarchy','omarchy-settings'):
            next(built.glob(name+'-4.0.3rc4-*')).unlink();Fixture.make_package(built,name,'4.0.3rc5-1')
        rebuilt=Fixture.make_package(built,'omarchy-mac-keyring','20260913-1',builddate=2)
        previous=capture/'packages'/rebuilt.name
        self.assertNotEqual(boot.bundle.digest(rebuilt),boot.bundle.digest(previous))
        Fixture.write_build_inputs(built,commit,'4.0.3rc5')
        args=argparse.Namespace(capture=capture,capture_manifest_sha256=boot.bundle.digest(capture/'capture-manifest.json'),built=built,candidates=Fixture.root/'inputs5',source=source,source_commit=commit,output=Fixture.root/'unsigned5',pkgrel='1')
        wrong=copy.copy(args);wrong.candidates=Fixture.root/'inputs5-wrong'
        receipt=(capture/'capture.json').read_text();changed=json.loads(receipt);changed['lane']='edge'
        (capture/'capture.json').write_text(json.dumps(changed))
        try:self.assertRaisesRegex(ValueError,'Capture file changed',boot.stage_input,wrong,Fixture.keys.policy)
        finally:(capture/'capture.json').write_text(receipt)
        correct=rebuilt.read_bytes();Fixture.make_package(built,'omarchy-mac-keyring','20260913-1',content='changed payload',builddate=2)
        wrong.candidates=Fixture.root/'inputs5-payload'
        try:self.assertRaisesRegex(ValueError,'Fork keyring payload differs',boot.stage_input,wrong,Fixture.keys.policy)
        finally:rebuilt.write_bytes(correct)
        boot.stage_input(args,Fixture.keys.policy)
        self.assertEqual(boot.bundle.digest(args.output/'assets'/rebuilt.name),boot.bundle.digest(previous))
        signed=Fixture.root/'signed5'
        boot.bundle.seal(argparse.Namespace(bundle=args.output,output=signed,public_key=Fixture.keys.public,trust_policy=Fixture.keys.policy))
        self.assertEqual(boot.bundle.digest(signed/'assets'/rebuilt.name),boot.bundle.digest(previous))
        self.assertTrue((signed/'assets'/(rebuilt.name+'.sig')).is_file())
        self.assertEqual(boot.bundle.check(signed,Fixture.keys.policy)['signature_policy'],boot.bundle.STRICT_POLICY)
        self.assertFalse(any(e[0] in ('create','upload','delete','expose') for e in remote.events))

    def test_17_unsigned_rc_and_stable_publication(self):
        rc_manifest=boot.validate(self.bundle4,self.sha4,self.source4,Fixture.keys.policy,signed=False)
        rc_args=self.transition_args()
        rc_args.accept_unsigned_publication=True
        rc_args.trust_policy=Fixture.keys.policy
        rc=Remote()
        result=boot.publish_checked(rc_args,rc_manifest,rc,unsigned_publication=True)
        self.assertIn('PASS',result['result'])
        self.assertTrue(result['snapshot_tag'].startswith('rc-unsigned-'))
        self.assertFalse(any(name.endswith('.sig') for name in rc.releases['rc']['assets']))

        (Fixture.root/'source4/version').write_text('4.0.3\n')
        boot.bundle.run('git','-C',Fixture.root/'source4','add','version')
        boot.bundle.run('git','-C',Fixture.root/'source4','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','Fixture final')
        commit=boot.bundle.run('git','-C',Fixture.root/'source4','rev-parse','HEAD').decode().strip()
        candidates=Fixture.root/'unsigned-final-candidates';shutil.copytree(Fixture.root/'candidates4',candidates)
        for name in ('omarchy','omarchy-settings'):
            next(candidates.glob(name+'-4.0.3rc4-*')).unlink()
            Fixture.make_package(candidates,name,'4.0.3-1')
        Fixture.write_build_inputs(candidates,commit,'4.0.3')
        final=Fixture.root/'unsigned-final'
        boot.bundle.stage(argparse.Namespace(base_db=Fixture.base_db,base_packages=Fixture.base,candidates=candidates,
                                              source=Fixture.root/'source4',source_git=None,source_commit=commit,
                                              release='4.0.3',output=final))
        final_manifest=boot.validate(final,boot.bundle.digest(final/'manifest.json'),commit,Fixture.keys.policy,
                                     signed=False,channel='stable')
        boot.verify_final_lineage(rc_manifest,final_manifest)
        changed=copy.deepcopy(final_manifest)
        changed['source']['files']['build-packages.sh']['sha256']='0'*64
        self.assertRaisesRegex(ValueError,'only in version',boot.verify_final_lineage,rc_manifest,changed)
        rc_receipt=Fixture.make_receipt(self.bundle4,'unsigned-rc')
        final_receipt=Fixture.make_receipt(final,'unsigned-final')
        final_data=json.loads(final_receipt.read_text())
        final_data.update(released_upgrade_from='4.0.2-2',
                          hardware_checks={'m1_reboot_runtime':'pass','m2_reboot_runtime':'pass'})
        final_receipt.write_text(json.dumps(final_data))
        evidence=argparse.Namespace(rc_bundle=self.bundle4,rc_validation=rc_receipt,
                                    rc_manifest_sha256=self.sha4,rc_source_commit=self.source4,
                                    trust_policy=Fixture.keys.policy)
        publisher.require_final_evidence(evidence,final_manifest,final_data)
        missing=dict(final_data,hardware_checks={'m1_reboot_runtime':'pass'})
        self.assertRaisesRegex(ValueError,'M1 and M2',publisher.require_final_evidence,evidence,final_manifest,missing)
        for lane in ('stable',):
            args=self.transition_args();args.bundle=final;args.manifest_sha256=boot.bundle.digest(final/'manifest.json')
            args.source_commit=commit;args.lane=lane;args.accept_unsigned_publication=True
            args.trust_policy=Fixture.keys.policy
            args.expected_edge_db=boot.bundle.digest(final/'assets'/'omarchy-aarch64.db')
            remote=Remote()
            remote.releases['edge']={'draft':False,'commit':'a'*40,
                                     'assets':{path.name:path.read_bytes() for path in (final/'assets').iterdir()}}
            remote.releases['edge']['assets']['omarchy-steam-fex-extra.pkg.tar.zst']=b'edge-only'
            dry=argparse.Namespace(bundle=final,expected_db=args.expected_edge_db,execute=False,
                                   accept_mutable_alias_window=False,scratch=Fixture.root/'edge-dry-run',
                                   evidence_dir=Fixture.root/'edge-evidence',
                                   manifest_sha256=args.manifest_sha256)
            dry.scratch.mkdir()
            original_run=publisher.subprocess.run
            edge_calls=[]
            def run_edge_only(argv,**kwargs):
                if argv[0]=='bash' and str(argv[1]).endswith('/scripts/publish.sh'):
                    edge_calls.append((argv,kwargs))
                    return __import__('subprocess').CompletedProcess(argv,0)
                return original_run(argv,**kwargs)
            with patch.object(publisher.subprocess,'run',side_effect=run_edge_only):
                edge_plan=publisher.publish_edge(dry,final_manifest,remote)
            self.assertEqual(edge_plan['mode'],'dry-run')
            self.assertEqual(edge_calls[0][1]['env']['DRY_RUN'],'1')
            self.assertNotIn('PRESERVE_SUPERSEDED',edge_calls[0][1]['env'])
            self.assertEqual(boot.bundle.digest(dry.evidence_dir/'previous-edge.db'),args.expected_edge_db)
            result=boot.publish_checked(args,final_manifest,remote,unsigned_publication=True)
            self.assertIn('PASS',result['result'])
            self.assertTrue(result['snapshot_tag'].startswith(lane+'-unsigned-'))
            self.assertFalse(remote.release(lane)['prerelease'] if lane=='stable' else False)
            self.assertFalse(any(name.endswith('.sig') for name in remote.releases[lane]['assets']))
            self.assertIn(('latest','stable'),remote.events)
            self.assertIn('omarchy-steam-fex-extra.pkg.tar.zst',remote.releases['edge']['assets'])
            desktop=next(p for p in final_manifest['packages'] if p['name']=='omarchy')
            remote.releases['edge']['assets'][desktop['filename']]=b'changed edge bytes'
            self.assertRaisesRegex(ValueError,'Public edge omarchy archive differs',
                                   boot.publish_checked,args,final_manifest,remote,unsigned_publication=True)
            remote.releases['edge']['assets'][desktop['filename']]=(final/'assets'/desktop['filename']).read_bytes()
            remote.releases[lane]['assets']['omarchy-aarch64.db.sig']=b'signed'
            self.assertRaises(ValueError,boot.publish_checked,args,final_manifest,remote,unsigned_publication=True)

    def test_18_unsigned_publication_rejects_newer_dependency_before_writes(self):
        previous=Fixture.root/'newer-dependency-lane'
        shutil.copytree(self.bundle4/'assets',previous)
        package=next(item for item in self.manifest['packages'] if item['name']=='ttf-jetbrains-mono-nerd-basic')
        (previous/package['filename']).unlink()
        newer=Fixture.make_package(previous,package['name'],'99-1')
        boot.bundle.run('repo-add','--quiet','--prevent-downgrade',f'{boot.DB}.db.tar.zst',newer.name,cwd=previous)
        (previous/f'{boot.DB}.db').unlink()
        shutil.copyfile(previous/f'{boot.DB}.db.tar.zst',previous/f'{boot.DB}.db')
        manifest=boot.validate(self.bundle4,self.sha4,self.source4,Fixture.keys.policy,signed=False)
        for lane in ('rc','edge'):
            remote=Remote()
            remote.releases[lane]={'draft':False,'commit':'a'*40,
                                   'assets':{path.name:path.read_bytes() for path in previous.iterdir()}}
            expected=boot.bundle.digest(previous/f'{boot.DB}.db')
            if lane=='rc':
                args=self.transition_args()
                args.accept_unsigned_publication=True
                args.trust_policy=Fixture.keys.policy
                args.expected_rc_db=expected
                with self.assertRaisesRegex(ValueError,'cannot downgrade ttf-jetbrains-mono-nerd-basic'):
                    boot.publish_checked(args,manifest,remote,unsigned_publication=True)
            else:
                args=argparse.Namespace(bundle=self.bundle4,expected_db=expected,execute=True,
                                        accept_mutable_alias_window=True,scratch=Fixture.root/'edge-newer-scratch',
                                        evidence_dir=None,manifest_sha256=self.sha4)
                args.scratch.mkdir()
                original_run=publisher.subprocess.run
                def reject_publish(argv,**kwargs):
                    if argv[0]=='bash':
                        self.fail('edge publisher ran before downgrade preflight')
                    return original_run(argv,**kwargs)
                with patch.object(publisher.subprocess,'run',side_effect=reject_publish):
                    with self.assertRaisesRegex(ValueError,'newer ttf-jetbrains-mono-nerd-basic'):
                        publisher.publish_edge(args,manifest,remote)
            self.assertFalse(any(event[0] in ('create','upload','delete','expose') for event in remote.events))

    def test_19_edge_allows_newer_non_candidate_without_changing_it(self):
        previous=Fixture.root/'newer-unrelated-edge'
        shutil.copytree(self.bundle4/'assets',previous)
        package=next(item for item in self.manifest['packages'] if item['name']=='1password')
        newer=Fixture.make_package(previous,package['name'],'2-1')
        boot.bundle.run('repo-add','--quiet','--prevent-downgrade',f'{boot.DB}.db.tar.zst',newer.name,cwd=previous)
        (previous/f'{boot.DB}.db').unlink()
        shutil.copyfile(previous/f'{boot.DB}.db.tar.zst',previous/f'{boot.DB}.db')
        expected=boot.bundle.digest(previous/f'{boot.DB}.db')
        remote=Remote()
        remote.releases['edge']={'draft':False,'commit':'a'*40,
                                 'assets':{path.name:path.read_bytes() for path in previous.iterdir()}}
        manifest=boot.validate(self.bundle4,self.sha4,self.source4,Fixture.keys.policy,signed=False)
        args=argparse.Namespace(bundle=self.bundle4,expected_db=expected,execute=False,
                                accept_mutable_alias_window=False,scratch=Fixture.root/'edge-unrelated-scratch',
                                evidence_dir=None,manifest_sha256=self.sha4)
        args.scratch.mkdir()
        original_run=publisher.subprocess.run
        calls=[]
        def run_edge(argv,**kwargs):
            if argv[0]=='bash':
                calls.append((argv,kwargs))
                return __import__('subprocess').CompletedProcess(argv,0)
            return original_run(argv,**kwargs)
        with patch.object(publisher.subprocess,'run',side_effect=run_edge):
            plan=publisher.publish_edge(args,manifest,remote)
        self.assertEqual(plan['mode'],'dry-run')
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][1]['env']['DRY_RUN'],'1')
        self.assertEqual(boot.bundle.field(boot.bundle.database(previous/f'{boot.DB}.db')['1password'],
                                           'VERSION'),'2-1')
        self.assertEqual(remote.releases['edge']['assets'][newer.name],newer.read_bytes())
        self.assertFalse(any(event[0] in ('create','upload','delete','expose') for event in remote.events))
        rc=Remote()
        rc.releases['rc']={'draft':False,'commit':'a'*40,
                           'assets':{path.name:path.read_bytes() for path in previous.iterdir()}}
        rc_args=self.transition_args()
        rc_args.accept_unsigned_publication=True
        rc_args.trust_policy=Fixture.keys.policy
        rc_args.expected_rc_db=expected
        with self.assertRaisesRegex(ValueError,'cannot downgrade 1password'):
            boot.publish_checked(rc_args,manifest,rc,unsigned_publication=True)
        self.assertFalse(any(event[0] in ('create','upload','delete','expose') for event in rc.events))

    def test_10_api_errors_are_not_release_absence(self):
        transport=boot.GitHub(Fixture.root)
        original=boot.bundle.run
        def failure(*args,**kwargs):raise __import__('subprocess').CalledProcessError(1,args)
        boot.bundle.run=failure
        try:self.assertRaises(__import__('subprocess').CalledProcessError,transport.release,'rc')
        finally:boot.bundle.run=original
    def test_11_workflows_are_manual_and_protected(self):
        import yaml
        for name in ['bootstrap-signed-rc.yml','prepare-rc-baseline.yml','publish-rc4-old-trust.yml','publish-unsigned-lane.yml']:
            data=yaml.safe_load((boot.ROOT/'.github/workflows'/name).read_text())
            triggers=data.get('on',data.get(True));self.assertEqual(set(triggers),{'workflow_dispatch'})
            for job in data['jobs'].values():self.assertEqual(job['environment'],'package-signing')
            for job in data['jobs'].values():
                for step in job['steps']:
                    if 'uses' in step:self.assertRegex(step['uses'],r'@[a-f0-9]{40}$')
        producer=(boot.ROOT/'.github/workflows/prepare-rc-baseline.yml').read_text()
        self.assertNotIn('PACMAN_SIGNING_SUBKEY_B64',producer)
        self.assertNotIn('contents: write',producer)
        transition=(boot.ROOT/'.github/workflows/publish-rc4-old-trust.yml').read_text()
        self.assertNotIn('PACMAN_SIGNING_SUBKEY_B64',transition)
        self.assertIn('accept_final_old_trust_publication',transition)

if __name__=='__main__':unittest.main()
