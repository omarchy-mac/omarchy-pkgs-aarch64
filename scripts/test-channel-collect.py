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
    # A second dependency collection carries the exact development pair and its provenance.
    for name in ('omarchy-dev', 'omarchy-settings-dev'):
        (output / (name + '-1-1-aarch64.pkg.tar.xz.sig')).write_bytes(b'desktop signature fixture')
    archives = sorted(output.glob('*.pkg.tar.xz'))
    db = output / 'omarchy-aarch64.db.tar.zst'
    subprocess.run(['repo-add', '--quiet', str(db), *map(str, archives)], check=True)
    import base64
    # repo-add ignores synthetic non-OpenPGP signatures; embed the fixture bytes
    # as an actual signed repository would, then exercise collector verification.
    members = []
    raw_database = subprocess.run(['bsdtar', '-c', '--format=ustar', '-f', '-', '@' + str(db)], check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(raw_database), mode='r:') as archive:
        for member in archive:
            data = archive.extractfile(member).read() if member.isfile() else None
            if member.name.endswith('/desc'):
                text = data.decode()
                filename = text.split('%FILENAME%\n', 1)[1].splitlines()[0]
                signature = output / (filename + '.sig')
                if signature.exists() and '%PGPSIG%' not in text:
                    data += b'%PGPSIG%\n' + base64.b64encode(signature.read_bytes()) + b'\n\n'
                    member.size = len(data)
            members.append((member, data))
    with tarfile.open(db, 'w') as archive:
        for member, data in members:
            archive.addfile(member, io.BytesIO(data) if data is not None else None)
    rows = []
    for name, metadata in collect.entries(db).items():
        row = dict(name=name, version=metadata['%VERSION%'], filename=metadata['%FILENAME%'], sha256=metadata['%SHA256SUM%'])
        signature = output / (row['filename'] + '.sig')
        if signature.exists():
            row['signature_sha256'] = collect.sha(signature)
        rows.append(row)
    build = dict(source_sha='a' * 40, recipe_sha='b' * 40, publisher_sha='c' * 40)
    manifest = dict(schema=1, client_protocol=1, channel='edge', packages=rows,
                    desktop_build=build, databases={'omarchy-aarch64.db.tar.zst': collect.sha(db)}, **build)
    manifest_path = root / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest))
    empty = root / 'empty'
    empty.mkdir()
    empty_plan = root / 'empty-plan'
    empty_plan.write_text('')
    reuse_argv = ['collect-channel.py', '--base-url', output.as_uri(), '--base-db', str(db),
                  '--import-plan', str(empty_plan), '--sync-db-dir', str(sync), '--overlay', str(empty),
                  '--output', str(root / 'reused'), '--channel', 'edge', '--reuse-edge-manifest', str(manifest_path),
                  '--source-sha', build['source_sha'], '--recipe-sha', build['recipe_sha']]
    with mock.patch.object(sys, 'argv', reuse_argv), mock.patch.object(collect, 'run', side_effect=run):
        collect.main()
    reused = root / 'reused'
    for name in ('omarchy-dev', 'omarchy-settings-dev'):
        filename = name + '-1-1-aarch64.pkg.tar.xz'
        for suffix in ('', '.sig'):
            assert (reused / (filename + suffix)).read_bytes() == (output / (filename + suffix)).read_bytes()
    assert json.loads((reused / 'input-provenance.json').read_text())['desktop_build'] == build
    def reject(arguments, message):
        with mock.patch.object(sys, 'argv', arguments), mock.patch.object(collect, 'run', side_effect=run):
            try:
                collect.main()
            except ValueError as error:
                assert message in str(error), str(error)
            else:
                raise AssertionError('Unsafe reuse accepted')
    changed = reuse_argv.copy()
    changed[changed.index('--output') + 1] = str(root / 'wrong-source')
    changed[changed.index('--source-sha') + 1] = 'e' * 40
    reject(changed, 'identical source')
    changed = reuse_argv.copy()
    changed[changed.index('--output') + 1] = str(root / 'overlay-pair')
    changed[changed.index('--overlay') + 1] = str(overlay)
    reject(changed, 'new desktop overlay')
    manifest['packages'][0]['sha256'] = 'f' * 64
    manifest_path.write_text(json.dumps(manifest))
    changed = reuse_argv.copy()
    changed[changed.index('--output') + 1] = str(root / 'wrong-manifest')
    reject(changed, 'differs from reuse manifest')
print('channel collector preserves complete baseline, frozen ABI provider and signatures PASS')
