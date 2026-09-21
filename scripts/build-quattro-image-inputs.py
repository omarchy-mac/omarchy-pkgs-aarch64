#!/usr/bin/python3
"""Build an unsigned, unpublished desktop and video dependency candidate set."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


DESKTOP_PACKAGES = ('omarchy', 'omarchy-settings', 'omarchy-mac')
VIDEO_PACKAGES = ('avd-fw', 'libva-v4l2_request-avd')
PACKAGES = DESKTOP_PACKAGES + VIDEO_PACKAGES
TRANSFERRED = (
    'usr/bin/omarchy-wifi-resume-fix',
    'usr/bin/omarchy-audio-asahi-mic-map',
    'usr/lib/systemd/user/omarchy-asahi-mic.service',
)


def output(*args, cwd=None, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def revision(repository, ref):
    require(bool(re.fullmatch('[0-9a-f]{40}', ref)), 'use a full source commit')
    require(output('git', 'rev-parse', ref + '^{commit}', cwd=repository) == ref,
            'source revision is not a commit')
    return ref


def archive(repository, commit, destination, *paths):
    destination.mkdir(parents=True)
    # Export committed objects; dirty source checkouts are never build inputs.
    with subprocess.Popen(['git', 'archive', commit, *paths], cwd=repository,
                          stdout=subprocess.PIPE) as process:
        subprocess.run(['tar', '-x', '-C', str(destination)], stdin=process.stdout, check=True)
        process.stdout.close()
        require(process.wait() == 0, 'git archive failed')


def replace_assignment(recipe, key, value):
    recipe, count = re.subn(r'^' + re.escape(key) + r'=.*$', key + '=' + value,
                            recipe, flags=re.M)
    require(count == 1, f'expected one {key} assignment')
    return recipe


def prepare_recipe(recipe, name, commit, version, release):
    require(bool(re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z.+_]*', version)), 'unsafe package version')
    for key, value in {'pkgver': version, 'pkgrel': release, '_commit': commit}.items():
        recipe = replace_assignment(recipe, key, value)
    if name != 'omarchy-mac':
        recipe = replace_assignment(recipe, '_tag', "''")
        anchor = '  cd "$srcdir/omarchy"\n'
        require(recipe.count(anchor) == 1, 'desktop package entrypoint changed')
        recipe = recipe.replace(anchor, anchor +
            f'  install -Dm644 /dev/stdin "$pkgdir/usr/share/doc/{name}/source-revision" <<\'REVISION\'\n'
            f'{commit}\nREVISION\n')
    return recipe


def prepare_video_recipe(recipe, name, revision, release):
    require(name in VIDEO_PACKAGES, 'unexpected video package')
    require(re.fullmatch('[0-9a-f]{40}', revision), 'invalid recipe revision')
    recipe = replace_assignment(recipe, 'pkgrel', release)
    recipe += "\noptions+=('!debug')\n"
    anchor = 'package() {\n'
    require(recipe.count(anchor) == 1, 'video package entrypoint changed')
    return recipe.replace(anchor, anchor +
        f'  install -Dm644 /dev/stdin "$pkgdir/usr/share/doc/{name}/source-revision" <<\'REVISION\'\n'
        f'{revision}\nREVISION\n')


def inspect_package(path):
    fields = {}
    for line in output('bsdtar', '-xOf', str(path), '.PKGINFO').splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            fields.setdefault(key, []).append(value)
    paths = {p.removeprefix('./') for p in output('bsdtar', '-tf', str(path)).splitlines()
             if not p.endswith('/') and not p.removeprefix('./').startswith('.')}
    name = fields['pkgname'][0]
    revision_path = ('usr/share/omarchy-mac/source-revision' if name == 'omarchy-mac'
                     else f'usr/share/doc/{name}/source-revision')
    source = output('bsdtar', '-xOf', str(path), revision_path)
    return fields, paths, source


def verify_packages(records, commit, versions, recipe_commit):
    require(set(records) == set(PACKAGES), 'candidate must contain exactly five packages')
    owners = {}
    for name, (fields, paths, source) in records.items():
        require(fields.get('pkgname') == [name], f'wrong package name: {name}')
        require(fields.get('arch') == ['any' if name == 'avd-fw' else 'aarch64'], f'wrong architecture: {name}')
        require(fields.get('pkgver') == [versions[name]], f'wrong version: {name}')
        require(source == (recipe_commit if name in VIDEO_PACKAGES else commit), f'mixed source revisions: {name}')
        for path in paths:
            require(path not in owners, f'duplicate file owner: {path}')
            owners[path] = name
    for path in TRANSFERRED:
        require(owners.get(path) == 'omarchy-mac', f'wrong transferred file owner: {path}')
    require(owners.get('usr/bin/omarchy-hw-apple') == 'omarchy', 'missing legacy hardware detector')
    pair_version = versions['omarchy'].rsplit('-', 1)[0]
    require(versions['omarchy'] == versions['omarchy-settings'], 'desktop pair versions differ')
    dependencies = records['omarchy'][0].get('depend', [])
    require(f'omarchy-settings={pair_version}' in dependencies, 'desktop settings pin is missing')
    require('snapper' in dependencies, 'ARM snapshot dependency is missing')
    require(not any(d.startswith(('linux-', 'limine')) for d in dependencies),
            'desktop candidate selects an incompatible boot stack')
    addon, addon_paths, _ = records['omarchy-mac']
    require(not addon.get('provides') and not addon.get('replaces'), 'add-on replaces desktop packages')
    require('omarchy' in addon.get('depend', []), 'add-on runtime dependency is missing')
    require(not any(d.startswith('linux-') for d in addon.get('depend', [])), 'add-on selects a kernel')
    require(not any(p.startswith(('etc/', 'boot/')) for p in addon_paths), 'add-on owns administrator files')
    return owners


def test_environment(env, source, recipes, iso, test_tools):
    env = dict(env, LANG='C.UTF-8', PATH=f'{source / "bin"}:{test_tools}:{env.get("PATH", "/usr/bin")}',
               OMARCHY_PATH=str(source), OMARCHY_PKGS_PATH=str(recipes),
               OMARCHY_ISO_PATH=str(iso))
    # These are headless source tests. About tests deliberately exercise both
    # colour modes; an inherited NO_COLOR must not change their starting state.
    # The update helper tests also exercise forwarding an explicitly set
    # LC_ALL, starting from the normal unset state.
    for key in ('LC_ALL', 'NO_COLOR', 'WAYLAND_DISPLAY', 'HYPRLAND_INSTANCE_SIGNATURE'):
        env.pop(key, None)
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('commit')
    parser.add_argument('upstream_recipes', type=Path)
    parser.add_argument('upstream_iso', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('run_id', type=int)
    parser.add_argument('attempt', type=int)
    args = parser.parse_args()
    require(os.geteuid() != 0 and os.uname().machine == 'aarch64', 'run as a non-root user on native aarch64')
    require(args.destination.is_absolute() and not args.destination.exists(), 'use a new absolute output directory')
    require(args.run_id > 0 and 1 <= args.attempt <= 9999, 'use a positive run ID and attempt 1..9999')
    repository = Path(__file__).resolve().parents[1]
    recipe_commit = output('git', 'rev-parse', 'HEAD', cwd=repository)
    require(not output('git', 'status', '--porcelain', '--untracked-files=normal', cwd=repository),
            'commit candidate build changes before building; package repository must be clean')
    commit = revision(args.source, args.commit)
    upstream_commit = (repository / 'scripts/quattro-image-inputs-recipes-revision').read_text().strip()
    revision(args.upstream_recipes, upstream_commit)
    iso_commit = (repository / 'scripts/quattro-image-inputs-iso-revision').read_text().strip()
    revision(args.upstream_iso, iso_commit)
    destination = args.destination
    source = destination / 'source'
    recipes = destination / 'recipes'
    iso = destination / 'iso-tests'
    artifacts = destination / 'artifacts'
    logs = destination / 'logs'
    archive(args.source, commit, source)
    archive(args.upstream_recipes, upstream_commit, recipes, 'pkgbuilds/omarchy', 'pkgbuilds/omarchy-settings',
            'pkgbuilds/omarchy-dev', 'pkgbuilds/omarchy-settings-dev')
    archive(args.upstream_iso, iso_commit, iso)
    artifacts.mkdir()
    logs.mkdir()
    test_tools = destination / 'test-tools'
    test_tools.mkdir()
    # Steam's --prepare command is now owned by its independent package. Stage
    # its real helper solely for the desktop suite; it is not an image artifact.
    helper = test_tools / 'omarchy-launch-steam'
    helper.write_text(output('git', 'show', f'{recipe_commit}:pkgbuilds/omarchy-steam-fex/omarchy-launch-steam', cwd=repository) + '\n')
    helper.chmod(0o755)
    test_patch = repository / 'patches/quattro-desktop-test-fixtures.patch'
    # Exports can be nested below the Actions checkout. Prevent git apply from
    # discovering that parent repository and silently ignoring paths outside it.
    patch_env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(destination))
    patch_paths = output('git', 'apply', '--numstat', str(test_patch), cwd=source, env=patch_env).splitlines()
    require(len(patch_paths) == 2 and {line.split('\t')[-1] for line in patch_paths} == {
        'test/shell.d/system-sleep-ownership-migration-test.sh',
        'test/shell.d/hermes-remove-test.sh',
    }, 'test patch may not change runtime source')
    subprocess.run(['git', 'apply', '--check', str(test_patch)], cwd=source, env=patch_env, check=True)
    subprocess.run(['git', 'apply', str(test_patch)], cwd=source, env=patch_env, check=True)
    with (logs / 'recipe-preparation.log').open('w') as log:
        subprocess.run(['bash', str(repository / 'scripts/prepare-omarchy-recipes.sh'), str(recipes)],
                       env=patch_env, stdout=log, stderr=subprocess.STDOUT, check=True)
    stamp = output('git', 'show', '-s', '--format=%ct', commit, cwd=args.source)
    version = (source / 'version').read_text().strip()
    addon_version = (source / 'packages/omarchy-mac/version').read_text().strip()
    desktop_version = f'{version}.quattro.r{stamp}.g{commit[:12]}'
    run = f'{args.run_id}{args.attempt:04d}'
    addon_recipe = output('git', 'show', f'{recipe_commit}:pkgbuilds/omarchy-mac/PKGBUILD', cwd=repository) + '\n'
    addon_release = re.search(r'^pkgrel=([0-9]+)$', addon_recipe, re.M)
    require(addon_release is not None, 'expected integer add-on pkgrel')
    releases = {'omarchy': f'1.{run}', 'omarchy-settings': f'1.{run}',
                'omarchy-mac': f'{addon_release[1]}.{run}'}
    versions = {name: f'{addon_version if name == "omarchy-mac" else desktop_version}-{releases[name]}'
                for name in DESKTOP_PACKAGES}
    for name in VIDEO_PACKAGES:
        archive(repository, recipe_commit, destination / name, f"pkgbuilds/{name}")
        shutil.copytree(destination / name / "pkgbuilds" / name, recipes / "pkgbuilds" / name)
        recipe = (recipes / "pkgbuilds" / name / "PKGBUILD").read_text()
        version = re.search(r"^pkgver=([0-9A-Za-z.+_]+)$", recipe, re.M)
        release = re.search(r"^pkgrel=([0-9]+)$", recipe, re.M)
        require(version and release, "expected literal video version/release")
        releases[name] = f"{release[1]}.{run}"
        versions[name] = f"{version[1]}-{releases[name]}"
    env = dict(os.environ, LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1',
               PKGDEST=str(artifacts), SOURCE_DATE_EPOCH=stamp)
    print('Running the headless desktop aggregate suite...', flush=True)
    with (logs / 'desktop-tests.log').open('w') as log:
        subprocess.run(['bash', 'test/all'], cwd=source, env=test_environment(env, source, recipes, iso, test_tools), stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    for name in PACKAGES:
        print(f'Building {name}...', flush=True)
        build = recipes / 'pkgbuilds' / name
        build.mkdir(exist_ok=True)
        recipe_path = build / 'PKGBUILD'
        text = addon_recipe if name == 'omarchy-mac' else recipe_path.read_text()
        if name in VIDEO_PACKAGES:
            recipe_path.write_text(prepare_video_recipe(text, name, recipe_commit, releases[name]))
        else:
            recipe_path.write_text(prepare_recipe(text, name, commit,
                addon_version if name == 'omarchy-mac' else desktop_version, releases[name]))
        package_env = dict(env)
        package_env.pop('OMARCHY_SRC', None)
        if name in ('omarchy', 'omarchy-settings'):
            package_env['OMARCHY_SRC'] = str(source)
        with (logs / f'{name}.log').open('w') as log:
            # Build dependencies are provisioned in the disposable CI container.
            # Runtime dependencies belong to the later image assembly check.
            command = ['makepkg', '--nodeps', '--nosign', '--cleanbuild']
            if name == 'omarchy-mac':
                command.append('--check')  # Do not inherit a local BUILDENV=(!check).
            subprocess.run(command, cwd=build, env=package_env, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
        evidence = artifacts / 'recipes' / name
        evidence.mkdir(parents=True)
        for path in build.iterdir():
            if path.is_file() and path.name != '.SRCINFO':
                shutil.copy2(path, evidence / path.name)
        (evidence / '.SRCINFO').write_text(output('makepkg', '--printsrcinfo', cwd=build, env=package_env) + '\n')
    records = {}
    packages = []
    for path in sorted(artifacts.glob('*.pkg.tar.*')):
        record = inspect_package(path)
        name = record[0]['pkgname'][0]
        require(name not in records, f'duplicate package: {name}')
        records[name] = record
        packages.append(dict(name=name, version=record[0]['pkgver'][0], filename=path.name,
                             sha256=digest(path), dependencies=record[0].get('depend', [])))
    owners = verify_packages(records, commit, versions, recipe_commit)
    (artifacts / 'ownership.json').write_text(json.dumps(owners, indent=2, sort_keys=True) + '\n')
    for name in ('omarchy-base.packages', 'omarchy-apple.packages'):
        shutil.copy2(source / 'install' / name, artifacts / name)
    shutil.copytree(logs, artifacts / 'logs')
    shutil.copy2(test_patch, artifacts / test_patch.name)
    shutil.copytree(test_tools, artifacts / 'test-tools')
    shutil.copy2(repository / 'patches/omarchy-first-run-packages.patch',
                 artifacts / 'recipes/omarchy-first-run-packages.patch')
    (artifacts / 'manifest.json').write_text(json.dumps(dict(
        schema=2, candidate_only=True, source_repository='omacom/omarchy-mac', source_revision=commit,
        package_repository_revision=recipe_commit, upstream_recipe_revision=upstream_commit,
        desktop_test_iso_revision=iso_commit,
        recipe_patch='patches/omarchy-first-run-packages.patch',
        desktop_test_patch=test_patch.name,
        desktop_test_tools='omarchy-steam-fex helper from package_repository_revision',
        build_image=os.environ.get('CANDIDATE_BUILD_IMAGE', 'local native aarch64'),
        run_id=args.run_id, attempt=args.attempt, packages=packages,
        validation=dict(desktop_tests='passed', addon_tests='passed', payload_ownership='passed',
                        runtime_dependencies='not tested', install_hooks='not tested', boot='not tested'),
        signing='none', publication='none',
    ), indent=2) + '\n')
    files = sorted(p for p in artifacts.rglob('*') if p.is_file())
    (artifacts / 'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(artifacts)}\n' for p in files))
    print(f'Built five unsigned image inputs from {commit}; no packages installed or published.')


if __name__ == '__main__':
    main()
