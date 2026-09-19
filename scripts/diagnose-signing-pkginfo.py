#!/usr/bin/env python3
"""Inspect fixed unsigned signing input; never execute package contents."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import tarfile

EXPECTED_MANIFEST = '8c01a64f784899b4bbc51e906d441f07e37ebfbb2280fd2ca8abf9a3ad8668ae'
EXPECTED_SOURCE = '79b074a8921ae2e195451991eda987445bcae962'
CANDIDATES = {'omarchy', 'omarchy-settings', 'omarchy-keyring', 'omarchy-mac-keyring', 'ttf-jetbrains-mono-nerd-basic'}

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def pkginfo(path):
    with tarfile.open(path, 'r:*') as archive:
        members = [m for m in archive.getmembers() if m.name in ('.PKGINFO', './.PKGINFO')]
        assert len(members) == 1, 'Expected exactly one .PKGINFO'
        member = members[0]
        assert member.isfile() and 0 < member.size <= 1024 * 1024, 'Invalid metadata member'
        stream = archive.extractfile(member)
        assert stream is not None
        text = stream.read().decode('utf-8')
    values = {}
    for line in text.splitlines():
        if line.startswith('#') or not line.strip():
            continue
        key, sep, value = line.partition(' = ')
        assert sep, 'Malformed .PKGINFO line'
        values.setdefault(key, []).append(value)
    return values

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('bundle', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    assert digest(args.bundle / 'manifest.json') == EXPECTED_MANIFEST, 'Unapproved input identity'
    manifest = json.loads((args.bundle / 'manifest.json').read_text())
    assert manifest['source']['commit'] == EXPECTED_SOURCE
    assert manifest['signature_policy'] == 'optional-existing-signatures; no signer authority asserted'
    records = {}
    for name in ('omarchy', 'omarchy-mac-keyring'):
        matching = [p for p in manifest['packages'] if p['name'] == name]
        assert len(matching) == 1
        item = matching[0]
        filename = item['filename']
        assert Path(filename).name == filename and filename not in ('.', '..')
        path = args.bundle / 'assets' / filename
        assert path.is_file() and not path.is_symlink()
        measured = digest(path)
        assert measured == item['sha256'] == manifest['files']['assets/' + filename]
        info = pkginfo(path)
        assert info['pkgname'] == [name] and info['pkgver'] == [item['version']]
        assert info.get('depend', []) == item['depends'], 'Manifest/archive dependencies disagree'
        records[name] = {'filename': filename, 'sha256': measured, 'pkginfo': info}
    source = Path(__file__).with_name('release-bundle.py')
    tree = ast.parse(source.read_text())
    check = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'check')
    call = next(n for n in ast.walk(check) if isinstance(n, ast.Call) and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant) and n.args[1].value == 'Strict feed requires the fork keyring package and dependency')
    dependencies = set(records['omarchy']['pkginfo'].get('depend', []))
    candidates = set(manifest['candidates'])
    guard = eval(compile(ast.Expression(call.args[0]), '<actual strict guard>', 'eval'), {'__builtins__': {}}, {'CANDIDATES': CANDIDATES, 'candidates': candidates, 'dependencies': dependencies})
    result = {'input_manifest_sha256': EXPECTED_MANIFEST, 'source_commit': EXPECTED_SOURCE,
              'validator_sha256': digest(source), 'candidate_set_complete': candidates == CANDIDATES,
              'candidates': sorted(candidates), 'packages': records, 'actual_strict_guard_accepts': guard,
              'scope': 'Metadata diagnosis only. No signing, build, publication, or full bundle requalification.'}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
