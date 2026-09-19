#!/usr/bin/python3
"""Audit exact candidate payloads, then rehearse pacman ownership in scratch roots.

Run as the normal build user. Pacman runs under fakeroot with scriptlets and all
shipped hooks disabled. This proves file ownership, not a bootable installation.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
import shutil
import json


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def inspect(package):
    metadata = run('bsdtar', '-xOf', str(package), '.PKGINFO')
    fields = {}
    for line in metadata.splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            fields.setdefault(key, []).append(value)
    paths = {p.removeprefix('./') for p in run('bsdtar', '-tf', str(package)).splitlines()
             if not p.endswith('/') and not p.startswith('.')}
    return fields, paths


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('artifacts', nargs=3, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--baseline', nargs=2, required=True, type=Path)
    args = parser.parse_args()
    packages = {}
    owners = {}
    for artifact in args.artifacts:
        fields, paths = inspect(artifact)
        name = fields['pkgname'][0]
        assert name not in packages
        packages[name] = (artifact.resolve(), fields, paths)
        for path in paths:
            assert path not in owners, (path, owners.get(path), name)
            owners[path] = name
    assert set(packages) == {'omarchy', 'omarchy-settings', 'omarchy-mac'}
    addon, fields, paths = packages['omarchy-mac']
    assert not fields.get('provides') and not fields.get('replaces')
    assert not any('linux-' in d for d in fields['depend'])
    assert not any(p.startswith(('etc/', 'boot/')) for p in paths)
    for path in ('usr/bin/omarchy-wifi-resume-fix', 'usr/bin/omarchy-audio-asahi-mic-map',
                 'usr/lib/systemd/user/omarchy-asahi-mic.service'):
        assert owners[path] == 'omarchy-mac'
    source = run('bsdtar', '-xOf', str(addon), 'usr/share/omarchy-mac/source-revision')
    for name in ('omarchy', 'omarchy-settings'):
        assert run('bsdtar', '-xOf', str(packages[name][0]), f'usr/share/doc/{name}/source-revision') == source
    # The installed host supplies the dependency availability check only.
    # No package-management operation below addresses the host database.
    dependencies = fields['depend']
    run('pacman', '-T', *dependencies)
    with tempfile.TemporaryDirectory(prefix='omarchy-mac-transaction-') as directory:
        work = Path(directory)
        old = [p.resolve() for p in args.baseline]
        assert {inspect(p)[0]['pkgname'][0] for p in old} == {'omarchy', 'omarchy-settings'}
        for mode in ('fresh', 'upgrade'):
            root = work/mode
            db = root/'var/lib/pacman'
            db.mkdir(parents=True)
            # Seed the installed base package database, excluding the desktop
            # pair. Dependency resolution stays enabled in the real transaction.
            local = db/'local'
            local.mkdir()
            for record in Path('/var/lib/pacman/local').iterdir():
                if record.is_dir():
                    desc = (record/'desc').read_text()
                    name = desc.split('%NAME%\n', 1)[1].splitlines()[0]
                    if name not in ('omarchy', 'omarchy-dev', 'omarchy-settings', 'omarchy-settings-dev', 'omarchy-mac'):
                        shutil.copytree(record, local/record.name)
                elif record.name == 'ALPM_DB_VERSION':
                    shutil.copyfile(record, local/record.name)
            cache = work/(mode+'-cache')
            cache.mkdir()
            hooks = work/(mode+'-hooks')
            hooks.mkdir()
            for path in owners:
                if path.startswith('usr/share/libalpm/hooks/'):
                    (hooks/Path(path).name).symlink_to('/dev/null')
            config = work/(mode+'.conf')
            config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Never\nHookDir = '+str(hooks)+'\n')
            command = ['fakeroot', 'pacman', '--config', str(config), '--root', str(root),
                       '--dbpath', str(db), '--logfile', str(work/(mode+'.log')),
                       '--cachedir', str(cache), '--noscriptlet', '--noconfirm', '-U']
            if mode == 'upgrade':
                run(*command, *(str(p) for p in old))
            run(*command, *(str(v[0]) for v in packages.values()))
            # Real pacman database owns each transferred file exactly once.
            for path in ('usr/bin/omarchy-wifi-resume-fix', 'usr/bin/omarchy-audio-asahi-mic-map',
                         'usr/lib/systemd/user/omarchy-asahi-mic.service'):
                result = run('pacman', '--config', str(config), '--root', str(root), '--dbpath', str(db), '-Qqo', str(root/path))
                assert result == 'omarchy-mac', (path, result)
            # A repeat install must also avoid overlap/overwrite escape hatches.
            run(*command, *(str(v[0]) for v in packages.values()))
    args.output.write_text(json.dumps(dict(source_revision=source, owners=owners,
        dependencies=dependencies, transactions=['fresh with installed base dependency database', 'upgrade from full baseline pair', 'repeat'],
        limits='Scriptlets/hooks are disabled in scratch transactions. Dependencies are resolved against the installed base database and candidate set. Physical boot, signed repository selection and install hooks remain release gates.'), indent=2)+'\n')
    print('ok - pinned payloads, dependencies, unique ownership and scratch pacman transactions')


if __name__ == '__main__':
    main()
