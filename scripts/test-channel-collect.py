#!/usr/bin/python3
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from unittest import mock

spec = importlib.util.spec_from_file_location('collect', Path(__file__).with_name('collect-channel.py'))
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    baseline, upstream, overlay, sync = [root / name for name in ('baseline', 'upstream', 'overlay', 'sync')]
    for path in (baseline, upstream, overlay, sync):
        path.mkdir()
    def package(directory, name, signed=False):
        path = directory / (name + '-1-1-aarch64.pkg.tar.xz')
        data = f'pkgname = {name}\npkgver = 1-1\narch = aarch64\n'.encode()
        with tarfile.open(path, 'w:xz') as archive:
            member = tarfile.TarInfo('.PKGINFO')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if signed:
            path.with_name(path.name + '.sig').write_bytes(b'signature fixture')
        return path
    old = [package(baseline, name) for name in ('omarchy', 'omarchy-settings', 'overlay-tool', 'omarchy-keyring')]
    imported = [package(upstream, name, True) for name in ('hyprland', 'hyprtoolkit', 'hyprland-guiutils', 'aquamarine')]
    for name in ('omarchy-dev', 'omarchy-settings-dev', 'omarchy-keyring'):
        package(overlay, name)
    subprocess.run(['repo-add', '--quiet', str(baseline / 'base.db.tar.zst'), *map(str, old)], check=True)
    subprocess.run(['repo-add', '--quiet', str(sync / 'omarchy.db.tar.zst'), *map(str, imported)], check=True)
    plan = root / 'plan'
    plan.write_text(''.join(f'omarchy|{p.name.split("-1-1")[0]}|1-1|{p.as_uri()}\n' for p in imported))
    real_run = collect.run
    def run(*args):
        if args[0] == 'gpgv':
            return ''
        return real_run(*args)
    argv = ['collect-channel.py', '--base-url', baseline.as_uri(), '--base-db', str(baseline / 'base.db.tar.zst'),
            '--import-plan', str(plan), '--sync-db-dir', str(sync), '--overlay', str(overlay),
            '--output', str(root / 'collected'), '--channel', 'edge']
    with mock.patch.object(sys, 'argv', argv), mock.patch.object(collect, 'run', side_effect=run):
        collect.main()
    output = root / 'collected'
    inventory = json.loads((output / 'inventory.json').read_text())
    assert set(inventory) == {'overlay-tool', 'omarchy-keyring', 'hyprland', 'hyprtoolkit', 'hyprland-guiutils', 'aquamarine'}
    assert (output / 'omarchy-keyring-1-1-aarch64.pkg.tar.xz').read_bytes() == (baseline / 'omarchy-keyring-1-1-aarch64.pkg.tar.xz').read_bytes()
    assert not list(output.glob('omarchy-1-*'))
    assert list(output.glob('omarchy-dev-*')) and list(output.glob('omarchy-settings-dev-*'))
    for path in imported:
        assert (output / path.name).read_bytes() == path.read_bytes()
        assert (output / (path.name + '.sig')).read_bytes() == path.with_name(path.name + '.sig').read_bytes()
    assert 'aquamarine' in json.loads((output / 'signed-inventory.json').read_text())
    assert json.loads((output / 'input-provenance.json').read_text())['import_database_sha256']
print('channel collector preserves complete baseline, frozen ABI provider and signatures PASS')
