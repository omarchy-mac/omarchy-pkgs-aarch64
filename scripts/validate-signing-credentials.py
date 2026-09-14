#!/usr/bin/env python3
"""Validate a signing credential using a disposable, non-package challenge."""
import importlib.util
import os
from pathlib import Path
import secrets
import sys
import tempfile


def validate(signing, public, policy):
    with tempfile.TemporaryDirectory(prefix='credential-probe-', dir=os.environ['TMPDIR']) as temporary:
        challenge = Path(temporary) / 'credential-check.txt'
        original = b'Omarchy Mac credential validation only\n' + secrets.token_bytes(32)
        challenge.write_bytes(original)
        ring = signing.Keyring(public, policy, secret=True)
        try:
            ring.sign(challenge)
        finally:
            ring.close()

        # A separate GnuPG home imports only the pinned public certificate.
        ring = signing.Keyring(public, policy, secret=False)
        try:
            ring.verify(challenge)
            challenge.write_bytes(original + b'tampered')
            try:
                ring.verify(challenge)
            except ValueError:
                pass
            else:
                raise ValueError('Tampered challenge was accepted')
        finally:
            ring.close()

        # A fresh agent must reject an incorrect password: a successful correct
        # signature alone would not prove that the export is passphrase-protected.
        password = os.environ['PACMAN_SIGNING_PASSPHRASE']
        os.environ['PACMAN_SIGNING_PASSPHRASE'] = password + '-incorrect-' + secrets.token_hex(16)
        try:
            ring = signing.Keyring(public, policy, secret=True)
            try:
                rejected = Path(temporary) / 'incorrect-passphrase.txt'
                rejected.write_bytes(original)
                try:
                    ring.sign(rejected)
                except ValueError as error:
                    if str(error) != 'Signing/verification command failed: gpg':
                        raise
                else:
                    raise ValueError('Signing succeeded with an incorrect passphrase')
            finally:
                ring.close()
        finally:
            os.environ['PACMAN_SIGNING_PASSPHRASE'] = password
    print('PASS: approved subkey, real signing, public-only verification, tamper rejection, and passphrase protection')


if __name__ == '__main__':
    repository = Path(sys.argv[1]).resolve()
    spec = importlib.util.spec_from_file_location('signing', repository / 'scripts/package-signing.py')
    signing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signing)
    try:
        validate(signing, signing.PUBLIC, signing.POLICY)
    except Exception as error:
        # Do not emit exception arguments, secret values, key exports, or signatures.
        print('FAIL: credential validation (' + type(error).__name__ + ')', file=sys.stderr)
        raise SystemExit(1)
