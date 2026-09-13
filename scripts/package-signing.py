#!/usr/bin/env python3
"""Sign only verified package/database bytes; never execute a build with a key loaded."""
import argparse, base64, hashlib, json, os, re, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / 'pkgbuilds/omarchy-mac-keyring/omarchy-mac.gpg'
POLICY = ROOT / 'pkgbuilds/omarchy-mac-keyring/signing-policy.json'
DB = 'omarchy-aarch64'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def run(*args, data=None, check=True):
    result = subprocess.run([str(x) for x in args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        # Do not echo commands, imported key material, passphrases or GnuPG diagnostics.
        raise ValueError('Signing/verification command failed: ' + str(args[0]))
    return result

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def policy(path=POLICY):
    p = json.loads(Path(path).read_text())
    require(set(p) == {'primary_fingerprint', 'signing_subkey_fingerprint', 'public_key_sha256'}, 'Malformed signing policy')
    for key in ('primary_fingerprint', 'signing_subkey_fingerprint'):
        require(re.fullmatch('[A-F0-9]{40}', p[key]), 'Missing or invalid signing fingerprint')
    require(p['primary_fingerprint'] != p['signing_subkey_fingerprint'], 'Primary cannot be the CI signer')
    require(re.fullmatch('[a-f0-9]{64}', p['public_key_sha256']), 'Missing public key digest')
    return p

def normalize_credentials(encoded, password):
    require(isinstance(encoded, str) and isinstance(password, str), 'Protected signing credentials missing')
    # Base64 commonly arrives wrapped by the export tool or GitHub secret input.
    compact = re.sub(r'[ \t\r\n\f\v]', '', encoded)
    if password.endswith('\r\n'):
        password = password[:-2]
    elif password.endswith('\n'):
        password = password[:-1]
    # Preserve significant spaces; only one terminal text-file newline is normalized.
    require(compact and password, 'Protected signing credentials missing')
    require('\n' not in password and '\r' not in password, 'Unsupported passphrase encoding')
    return base64.b64decode(compact, validate=True), (password + '\n').encode()

class Keyring:
    def __init__(self, public=PUBLIC, policy_path=POLICY, secret=False):
        self.public, self.policy = Path(public), policy(policy_path)
        require(self.public.is_file() and not self.public.is_symlink(), 'Public key must be a regular file')
        require(digest(self.public) == self.policy['public_key_sha256'], 'Public key differs from reviewed policy')
        location = Path(os.environ.get('TMPDIR', '/tmp')).resolve()
        fs = run('findmnt', '-n', '-o', 'FSTYPE', '-T', location).stdout.decode().strip()
        require(fs and fs not in ('tmpfs', 'ramfs'), 'GnuPG temporary storage must be disk-backed')
        self.temp = tempfile.TemporaryDirectory(prefix='package-signing-', dir=location)
        self.home = Path(self.temp.name)
        self.home.chmod(0o700)
        self.gpg = ['gpg', '--homedir', str(self.home), '--batch', '--no-tty', '--no-auto-key-retrieve']
        try:
            run(*self.gpg, '--import', data=self.public.read_bytes())
            records = run(*self.gpg, '--with-colons', '--list-keys').stdout.decode().splitlines()
            fingerprints = [line.split(':')[9] for line in records if line.startswith('fpr:')]
            require(fingerprints[0] == self.policy['primary_fingerprint'] and sum(x.startswith('pub:') for x in records) == 1,
                    'Public key must contain the exact single approved primary')
            require(self.policy['signing_subkey_fingerprint'] in fingerprints[1:], 'Approved signing subkey missing')
            self.password = None
            if secret:
                for env, field in [('PACMAN_SIGNING_PRIMARY_FPR', 'primary_fingerprint'),
                                   ('PACMAN_SIGNING_SUBKEY_FPR', 'signing_subkey_fingerprint')]:
                    require(os.environ.get(env) == self.policy[field], 'Protected signing fingerprint differs from reviewed policy')
                encoded = os.environ.get('PACMAN_SIGNING_SUBKEY_B64', '')
                password = os.environ.get('PACMAN_SIGNING_PASSPHRASE')
                raw, normalized_password = normalize_credentials(encoded, password)
                run(*self.gpg, '--import', data=raw)
                del raw
                records = run(*self.gpg, '--with-colons', '--list-secret-keys').stdout.decode().splitlines()
                sec = [line.split(':') for line in records if line.startswith('sec:')]
                require(len(sec) == 1 and len(sec[0]) > 14 and sec[0][14] == '#', 'CI must not contain usable primary secret material')
                usable = []
                pending = None
                for line in records:
                    fields = line.split(':')
                    if fields[0] in ('sec', 'ssb'):
                        pending = fields
                    elif fields[0] == 'fpr' and pending is not None:
                        if pending[0] == 'ssb' and len(pending) > 14 and pending[14] != '#':
                            require(pending[14] == '+' and 's' in pending[11], 'Unsupported or non-signing CI secret subkey')
                            usable.append(fields[9])
                        pending = None
                require(usable == [self.policy['signing_subkey_fingerprint']], 'CI must contain exactly the approved usable signing subkey')
                self.password = normalized_password
        except BaseException:
            self.close()
            raise

    def close(self):
        run('gpgconf', '--homedir', self.home, '--kill', 'gpg-agent', check=False)
        self.temp.cleanup()

    def verify(self, path):
        path = Path(path); sig = Path(str(path) + '.sig')
        require(path.is_file() and not path.is_symlink() and sig.is_file() and not sig.is_symlink(), 'Missing/unsafe signed artifact')
        result = run(*self.gpg, '--status-fd', '1', '--verify', sig, path, check=False)
        status = result.stdout.decode().splitlines()
        require(result.returncode == 0 and not any(re.search(r'\b(BADSIG|ERRSIG|REVKEYSIG|EXPKEYSIG|EXPSIG|KEYREVOKED|KEYEXPIRED|SIGEXPIRED)\b', x) for x in status),
                'Invalid, expired or revoked artifact signature')
        valid = [x.split() for x in status if x.startswith('[GNUPG:] VALIDSIG ')]
        require(len(valid) == 1 and valid[0][2] == self.policy['signing_subkey_fingerprint'] and valid[0][-1] == self.policy['primary_fingerprint'],
                'Artifact was not signed by the approved primary/subkey pair')

    def sign(self, path):
        require(self.password is not None, 'Signing credentials unavailable')
        path = Path(path); sig = Path(str(path) + '.sig')
        require(path.is_file() and not path.is_symlink(), 'Unsafe signing input')
        if sig.exists() or sig.is_symlink():
            self.verify(path)  # retries reuse identical signatures; never clobber one
            return
        before = digest(path)
        pending = sig.with_name(sig.name + '.pending')
        require(not pending.exists() and not pending.is_symlink(), 'Prior incomplete signature requires inspection')
        try:
            run(*self.gpg, '--pinentry-mode', 'loopback', '--passphrase-fd', '0', '--local-user',
                self.policy['signing_subkey_fingerprint'] + '!', '--digest-algo', 'SHA256',
                '--output', pending, '--detach-sign', path, data=self.password)
            require(digest(path) == before, 'Artifact changed during signing')
            pending.rename(sig)
            self.verify(path)
        finally:
            if pending.exists():
                pending.unlink()

def packages(directory):
    paths = sorted(p for p in Path(directory).iterdir() if '.pkg.tar.' in p.name and not p.name.endswith(('.sig', '.pending')))
    require(paths, 'No package archives')
    for path in paths:
        require(path.is_file() and not path.is_symlink(), 'Unsafe package archive')
    for path in Path(directory).glob('*.pkg.tar.*.sig'):
        require(Path(str(path)[:-4]) in paths, 'Orphan package signature')
    return paths

def databases(directory):
    return [Path(directory) / f'{DB}.{suffix}' for suffix in ('files.tar.zst', 'files', 'db.tar.zst', 'db')]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['sign-packages', 'verify-packages', 'sign-databases', 'verify-databases'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--public-key', type=Path, default=PUBLIC)
    parser.add_argument('--policy', type=Path, default=POLICY)
    args = parser.parse_args()
    paths = packages(args.directory) if args.operation.endswith('packages') else databases(args.directory)
    ring = Keyring(args.public_key, args.policy, secret=args.operation.startswith('sign-'))
    try:
        for path in paths:
            if args.operation.startswith('sign-'):
                ring.sign(path)
            else:
                ring.verify(path)
    finally:
        ring.close()
    print(f'PASS {args.operation}: {len(paths)} artifacts')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error))
