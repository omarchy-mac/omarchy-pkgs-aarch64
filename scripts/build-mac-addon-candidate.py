#!/usr/bin/python3
"""Build an unsigned add-on candidate from recorded source and recipe commits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def output(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('commit')
    parser.add_argument('destination', type=Path)
    parser.add_argument('run_id', type=int)
    parser.add_argument('attempt', type=int)
    args = parser.parse_args()
    if os.geteuid() == 0 or os.uname().machine != 'aarch64':
        parser.error('run as a non-root user on native aarch64')
    if not re.fullmatch('[0-9a-f]{40}', args.commit) or min(args.run_id, args.attempt) < 1:
        parser.error('use a full source commit and positive run/attempt IDs')
    if not args.destination.is_absolute() or args.destination.exists():
        parser.error('use a new absolute output directory')
    source = args.source.resolve()
    recipes = Path(__file__).resolve().parents[1]
    recipe_commit = output('git', 'rev-parse', 'HEAD', cwd=recipes)
    assert output('git', 'rev-parse', args.commit + '^{commit}', cwd=source) == args.commit
    version = output('git', 'show', args.commit + ':packages/omarchy-mac/version', cwd=source)
    assert re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}(?:rc[0-9]+)?', version), version
    recipe = output('git', 'show', recipe_commit + ':pkgbuilds/omarchy-mac/PKGBUILD', cwd=recipes) + '\n'
    base_release = re.search(r'^pkgrel=([0-9]+)$', recipe, re.M).group(1)
    release = f'{base_release}.{args.run_id}.{args.attempt}'
    for key, value in {'pkgver': version, 'pkgrel': release, '_commit': args.commit}.items():
        recipe, count = re.subn(r'^' + key + r'=.*$', key + '=' + value, recipe, flags=re.M)
        assert count == 1, key
    build = args.destination / 'build'
    artifacts = args.destination / 'artifacts'
    build.mkdir(parents=True)
    artifacts.mkdir()
    (build / 'PKGBUILD').write_text(recipe)
    env = dict(os.environ, PKGDEST=str(artifacts), LC_ALL='C.UTF-8')
    with (args.destination / 'build.log').open('w') as log:
        # Runtime Omarchy is deliberately absent from the generic build image.
        # Tests run normally; this does not qualify runtime dependency delivery.
        subprocess.run(['makepkg', '--nodeps', '--nosign', '--cleanbuild'], cwd=build, env=env,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    archives = list(artifacts.glob('*.pkg.tar.*'))
    assert len(archives) == 1, archives
    archive = archives[0]
    metadata = output('bsdtar', '-xOf', str(archive), '.PKGINFO')
    for field in ['pkgname = omarchy-mac', f'pkgver = {version}-{release}', 'arch = aarch64']:
        assert field in metadata.splitlines(), field
    assert output('bsdtar', '-xOf', str(archive), 'usr/share/omarchy-mac/source-revision') == args.commit
    paths = output('bsdtar', '-tf', str(archive)).splitlines()
    assert not any(p.removeprefix('./').startswith(('etc/', 'boot/')) for p in paths)
    shutil.copy2(build / 'PKGBUILD', artifacts / 'PKGBUILD')
    shutil.copy2(args.destination / 'build.log', artifacts / 'build.log')
    (artifacts / '.SRCINFO').write_text(output('makepkg', '--printsrcinfo', cwd=build) + '\n')
    (artifacts / 'BUILDINFO').write_text(output('bsdtar', '-xOf', str(archive), '.BUILDINFO') + '\n')
    (artifacts / 'manifest.json').write_text(json.dumps({
        'candidate_only': True, 'source_repository': 'omacom/omarchy-mac',
        'source_revision': args.commit, 'recipe_revision': recipe_commit,
        'version': f'{version}-{release}', 'run_id': args.run_id, 'attempt': args.attempt,
        'build_image': os.environ.get('CANDIDATE_BUILD_IMAGE', 'local native aarch64'),
        'archive': archive.name, 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'standalone_tests': 'passed', 'runtime_dependency_resolution': 'not performed',
        'publication': 'none',
    }, indent=2) + '\n')
    files = sorted(p for p in artifacts.iterdir() if p.is_file())
    (artifacts / 'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
    print(f'Built {archive.name} from {args.commit}; no packages installed or published.')


if __name__ == '__main__':
    main()
