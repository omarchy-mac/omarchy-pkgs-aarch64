#!/usr/bin/python3
"""Build/audit an unsigned Aurora set. No keyring, installation, or publication."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'scripts/aurora-candidate-inputs.json'
NAMES = {'linux-aurora', 'linux-aurora-headers', 'm1n1-aurora'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def output(*args, **kwargs):
    return subprocess.check_output([str(x) for x in args], text=True, **kwargs).strip()


def fields(text):
    result = {}
    for line in text.splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            result.setdefault(key, []).append(value)
    return result


def inputs(root=ROOT):
    lock = json.loads((root / 'scripts/aurora-candidate-inputs.json').read_text())
    require(lock['schema'] == 1 and lock['kind'] == 'aurora-candidate-inputs', 'Invalid input lock')
    require(set(lock['packages']) == NAMES, 'Unexpected package set')
    for name, sha in lock['files'].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts, 'Unsafe input path')
        f = root / path
        require(f.is_file() and not f.is_symlink() and digest(f) == sha, f'Input changed: {name}')
    return lock


def inspect(archive):
    names = output('bsdtar', '-tf', archive).splitlines()
    require(len(names) == len(set(names)), 'Duplicate package member')
    for name in names:
        p = PurePosixPath(name)
        require(not p.is_absolute() and '..' not in p.parts, 'Unsafe package member')
    info = fields(output('bsdtar', '-xOf', archive, '.PKGINFO'))
    build = fields(output('bsdtar', '-xOf', archive, '.BUILDINFO'))
    return info, build, {n.removeprefix('./') for n in names if not n.endswith('/')}


def validate_records(records, lock, installed):
    require(set(records) == NAMES, 'Incomplete or unexpected package set')
    owners = {}
    for name, (info, build, members) in records.items():
        require(info.get('pkgname') == [name] and info.get('pkgver') == [lock['packages'][name]],
                f'Wrong package identity: {name}')
        require(info.get('arch') == ['aarch64'], f'Wrong architecture: {name}')
        recipe = 'm1n1-aurora' if name == 'm1n1-aurora' else 'linux-aurora'
        require(build.get('pkgbuild_sha256sum') == [lock['files'][f'pkgbuilds/{recipe}/PKGBUILD']],
                f'Wrong recipe provenance: {name}')
        require(set(build.get('installed', [])) == set(installed) and installed,
                f'Build dependency inventory differs: {name}')
        require(not any(d.split('=')[0] == 'omarchy' or d.startswith('omarchy-')
                        for d in info.get('depend', [])), 'Desktop dependency in reusable package')
        for member in members - {'.PKGINFO', '.BUILDINFO', '.MTREE'}:
            require(member not in owners, f'Conflicting file ownership: {member}')
            owners[member] = name
    kernel, headers, m1n1 = [records[n] for n in ('linux-aurora', 'linux-aurora-headers', 'm1n1-aurora')]
    images = [m for m in kernel[2] if re.fullmatch(r'usr/lib/modules/[^/]+/vmlinuz', m)]
    require(len(images) == 1, 'Expected one kernel image')
    prefix = images[0].rsplit('/', 1)[0]
    require(prefix + '/pkgbase' in kernel[2], 'Missing kernel identity')
    require(any(m.startswith(prefix + '/dtbs/') and re.fullmatch(r't[0-9]+-j[0-9]+[a-z]*\.dtb', PurePosixPath(m).name) for m in kernel[2]),
            'Missing Apple device trees')
    require(prefix + '/build/Makefile' in headers[2], 'Headers do not match kernel release')
    require('linux-asahi' in kernel[0].get('conflict', []), 'Missing Asahi replacement conflict')
    require('linux-asahi-headers' in headers[0].get('conflict', []), 'Missing headers conflict')
    require('usr/lib/asahi-boot/m1n1.bin' in m1n1[2], 'Missing m1n1 binary')
    require('m1n1' in m1n1[0].get('conflict', []) and
            any(x.startswith('m1n1=') for x in m1n1[0].get('provides', [])), 'Missing m1n1 replacement contract')
    require('asahi-scripts>=20260127.1' in m1n1[0].get('depend', []), 'Missing boot-script dependency')
    return prefix.rsplit('/', 1)[1]


def audit(directory, lock, provenance):
    archives = sorted(directory.glob('*.pkg.tar.*'))
    require(len(archives) == 3 and all(p.is_file() and not p.is_symlink() for p in archives),
            'Expected exactly three unsigned package archives')
    records, packages = {}, []
    for archive in archives:
        info, build, members = inspect(archive)
        name = info.get('pkgname', [''])[0]
        require(name not in records, 'Duplicate package name')
        records[name] = info, build, members
        packages.append({'name': name, 'version': info.get('pkgver', [''])[0],
                         'filename': archive.name, 'sha256': digest(archive),
                         'dependencies': info.get('depend', []),
                         'provides': info.get('provides', []), 'conflicts': info.get('conflict', [])})
    release = validate_records(records, lock, provenance['installed_dependencies'])
    return {'schema': 1, 'kind': 'aurora-unsigned-candidate', 'candidate_only': True,
            'signing': 'none', 'publication': 'none', 'hardware_qualification': [],
            'runtime_dependency_qualification': False, 'kernel_release': release,
            'inputs': lock, 'provenance': provenance, 'packages': sorted(packages, key=lambda p: p['name'])}


def build(destination):
    lock = inputs()
    require(os.geteuid() != 0, 'Run makepkg as an unprivileged container user')
    require(os.uname().machine == 'aarch64', 'Native aarch64 required')
    require(not destination.exists(), 'Refuse to replace an existing candidate attempt')
    require(not output('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal'), 'Source tree is dirty')
    image = os.environ.get('AURORA_BUILD_IMAGE', '')
    require(re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', image), 'Resolved builder image digest required')
    destination.mkdir(parents=True)
    artifacts = destination / 'artifacts'
    artifacts.mkdir()
    logs = destination / 'logs'
    logs.mkdir()
    inventory = output('pacman', '-Q')
    installed = ['-'.join(line.split(' ', 1)) for line in inventory.splitlines()]
    provenance = {'recipe_revision': output('git', '-C', ROOT, 'rev-parse', 'HEAD'),
                  'builder_image': image, 'installed_dependencies': installed,
                  'runner': output('uname', '-a'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
                  'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
                  'limitations': ['Repository dependencies resolved at build time, not a reproducible snapshot.',
                                 'Rustup downloads not vendored; toolchain content recorded after build.',
                                 'Build success is not runtime dependency, boot, or hardware qualification.']}
    (artifacts / 'inputs.json').write_text(json.dumps(lock, indent=2) + '\n')
    (artifacts / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    provenance['dependency_archives'] = {p.name: digest(p)
                                         for p in sorted(Path('/var/cache/pacman/pkg').glob('*.pkg.tar.*'))
                                         if p.is_file() and not p.name.endswith('.sig')}
    source_epoch = output('git', '-C', ROOT, 'show', '-s', '--format=%ct', 'HEAD')
    for recipe in ('linux-aurora', 'm1n1-aurora'):
        work = destination / recipe
        shutil.copytree(ROOT / 'pkgbuilds' / recipe, work)
        # Runtime dependencies are intentionally not installed in the builder.
        # Verify all declared make/check dependencies before --nodeps.
        deps = output('bash', '-c', 'source ./PKGBUILD; printf "%s\\n" "${makedepends[@]}" "${checkdepends[@]}"', cwd=work).splitlines()
        subprocess.run(['pacman', '-T', *filter(None, deps)], check=True)
        env = dict(os.environ, SOURCE_DATE_EPOCH=source_epoch, PKGDEST=str(artifacts),
                   MAKEFLAGS=f'-j{os.environ.get("OMARCHY_BUILD_JOBS", "4")}')
        with (logs / f'{recipe}.log').open('w') as log:
            subprocess.run(['makepkg', '--nodeps', '--noconfirm', '--cleanbuild', '--log', '--nosign'],
                           cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        provenance.setdefault('source_archives', {})[recipe] = {
            p.name: digest(p) for p in work.glob('*.tar.gz') if p.is_file()}
    provenance['rust_toolchains'] = output('rustup', 'toolchain', 'list')
    toolchains = Path.home() / '.rustup/toolchains'
    provenance['rust_toolchain_files'] = {str(p.relative_to(toolchains)): digest(p)
                                        for p in sorted(toolchains.rglob('*')) if p.is_file()}
    manifest = audit(artifacts, lock, provenance)
    (artifacts / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    (artifacts / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Unsigned candidate verified: {artifacts}; not qualified for installation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check-inputs')
    build_parser = sub.add_parser('build')
    build_parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    if args.command == 'check-inputs':
        inputs()
        print('Pinned Aurora recipe inputs match')
    else:
        build(args.destination.resolve())


if __name__ == '__main__':
    main()
