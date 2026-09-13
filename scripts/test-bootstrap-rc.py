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

spec=importlib.util.spec_from_file_location('bootstrap',Path(__file__).with_name('bootstrap-rc.py'))
boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)
spec=importlib.util.spec_from_file_location('bundle_tests',Path(__file__).with_name('test-release-bundle.py'))
fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)

# Reuse the real archive/DB/signing fixture helpers without inheriting their tests.
class Fixture:pass
for name,value in fixtures.ReleaseBundleTests.__dict__.items():
    if isinstance(value,classmethod):setattr(Fixture,name,value)
original_stage=Fixture.stage.__func__
@classmethod
def stage52(cls,*args,**kwargs):
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
Fixture.stage=stage52

class Remote:
    def __init__(self):self.releases={};self.events=[];self.fail_upload=None;self.bad_read=None;self.next_id=1;self.tags={};self.fail_after_delete=None
    def release(self,tag,require_prerelease=True):
        self.events.append(('view',tag))
        if tag not in self.releases:return None
        r=self.releases[tag]
        return {'tag_name':tag,'prerelease':True,'draft':r['draft'],'target_commitish':r['commit'],
                'asset_map':{name:{'size':len(data),'id':i+1} for i,(name,data) in enumerate(r['assets'].items())}}
    def read(self,release,name,public=False,destination=None):
        tag=release['tag_name'];self.events.append(('read',tag,name,public))
        data=self.releases[tag]['assets'][name]
        if destination is not None:destination.write_bytes(data)
        if self.bad_read==(tag,name):return 'f'*64
        return __import__('hashlib').sha256(data).hexdigest()
    def tag_commit(self,tag):return self.tags.get(tag)
    def create(self,tag,commit,body):
        self.events.append(('create',tag));assert tag=='rc' or tag.startswith('rc-baseline-');assert tag not in self.releases
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
    def delete(self,tag,name):self.events.append(('delete',tag,name));del self.releases[tag]['assets'][name]

class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Fixture.setUpClass();cls.bundle=Fixture.rc
        cls.sha=boot.bundle.digest(cls.bundle/'manifest.json');cls.source=Fixture.rc_commit
        cls.manifest=boot.validate(cls.bundle,cls.sha,cls.source,Fixture.keys.policy)
    @classmethod
    def tearDownClass(cls):Fixture.tearDownClass()
    def args(self,execute=True):
        scratch=Path(__import__('tempfile').mkdtemp(dir=Fixture.root))
        return argparse.Namespace(bundle=self.bundle,manifest_sha256=self.sha,source_commit=self.source,
                                  lane='rc',publisher_commit='a'*40,expected_rc_db='absent',execute=execute,
                                  accept_mutable_alias_window=execute,scratch=scratch)
    def publish(self,args,remote):return boot.publish_checked(args,self.manifest,remote)
    def test_01_exact_signed_inventory(self):
        self.assertEqual(len(self.manifest['packages']),52)
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
        self.assertNotIn('omarchy-aarch64.db',remote.releases['rc']['assets'])
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
        self.assertNotIn('omarchy-aarch64.db',remote.releases['rc']['assets'])
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

    def test_09_producer_capture_and_stage_complete_artifact(self):
        remote=Remote();remote.releases['edge']={'draft':False,'commit':'b'*40,'assets':{}}
        remote.releases['edge']['assets']['omarchy-aarch64.db.tar.zst']=Fixture.base_db.read_bytes()
        for path in Fixture.base.iterdir():remote.releases['edge']['assets'][path.name]=path.read_bytes()
        original=boot.GitHub;boot.GitHub=lambda scratch:remote
        capture=Fixture.root/'producer-capture'
        try:boot.capture(argparse.Namespace(database_sha256=boot.bundle.digest(Fixture.base_db),output=capture))
        finally:boot.GitHub=original
        output=Fixture.root/'producer-bundle'
        boot.stage_input(argparse.Namespace(capture=capture,built=Fixture.candidates,candidates=Fixture.root/'producer-inputs',source=Fixture.source,source_commit=self.source,output=output))
        manifest=boot.validate(output,boot.bundle.digest(output/'manifest.json'),self.source,Fixture.keys.policy,signed=False)
        self.assertEqual(len(manifest['packages']),52)
        self.assertFalse(any(e[0] in ('upload','expose','delete') for e in remote.events))

    def test_10_api_errors_are_not_release_absence(self):
        transport=boot.GitHub(Fixture.root)
        original=boot.bundle.run
        def failure(*args,**kwargs):raise __import__('subprocess').CalledProcessError(1,args)
        boot.bundle.run=failure
        try:self.assertRaises(__import__('subprocess').CalledProcessError,transport.release,'rc')
        finally:boot.bundle.run=original
    def test_11_workflows_are_manual_and_protected(self):
        import yaml
        for name in ['bootstrap-signed-rc.yml','prepare-rc-baseline.yml']:
            data=yaml.safe_load((boot.ROOT/'.github/workflows'/name).read_text())
            triggers=data.get('on',data.get(True));self.assertEqual(set(triggers),{'workflow_dispatch'})
            for job in data['jobs'].values():self.assertEqual(job['environment'],'package-signing')
            for job in data['jobs'].values():
                for step in job['steps']:
                    if 'uses' in step:self.assertRegex(step['uses'],r'@[a-f0-9]{40}$')
        producer=(boot.ROOT/'.github/workflows/prepare-rc-baseline.yml').read_text()
        self.assertNotIn('PACMAN_SIGNING_SUBKEY_B64',producer)
        self.assertNotIn('contents: write',producer)

if __name__=='__main__':unittest.main()
