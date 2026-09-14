#!/usr/bin/env python3
"""Validate a signing credential using a disposable, non-package challenge."""
import binascii
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import secrets
import sys
import tempfile


class ValidationFailure(Exception):
    """Contains only a constant stage label, never underlying diagnostics."""


IMPORT_FAILURES = {
    'Protected signing credentials missing': 'missing-credentials',
    'Unsupported passphrase encoding': 'passphrase-encoding',
    'Protected signing fingerprint differs from reviewed policy': 'fingerprint-mismatch',
    # The helper uses this same signal for GPG import and key-list commands.
    'Signing/verification command failed: gpg': 'gpg-command',
    # This check also rejects missing secret records, not just a usable primary.
    'CI must not contain usable primary secret material': 'primary-shape',
    'Unsupported or non-signing CI secret subkey': 'wrong-or-extra-subkey',
    'CI must contain exactly the approved usable signing subkey': 'wrong-or-extra-subkey',
    'Malformed signing policy': 'public-or-policy',
    'Missing or invalid signing fingerprint': 'public-or-policy',
    'Primary cannot be the CI signer': 'public-or-policy',
    'Missing public key digest': 'public-or-policy',
    'Public key must be a regular file': 'public-or-policy',
    'Public key differs from reviewed policy': 'public-or-policy',
    'Public key must contain the exact single approved primary': 'public-or-policy',
    'Approved signing subkey missing': 'public-or-policy',
    'GnuPG temporary storage must be disk-backed': 'temp-storage',
}


def import_substage(error):
    if isinstance(error, binascii.Error):
        return 'bad-base64'
    if type(error) is ValueError:
        return IMPORT_FAILURES.get(str(error), 'other')
    return 'other'


@contextmanager
def stage(label):
    try:
        yield
    except Exception as error:
        if label in ('import', 'wrong-password-import'):
            label += ':' + import_substage(error)
        raise ValidationFailure(label) from None


def validate(signing, public, policy):
    with tempfile.TemporaryDirectory(prefix='credential-probe-', dir=os.environ['TMPDIR']) as temporary:
        challenge = Path(temporary) / 'credential-check.txt'
        original = b'Omarchy Mac credential validation only\n' + secrets.token_bytes(32)
        challenge.write_bytes(original)
        with stage('import'):
            ring = signing.Keyring(public, policy, secret=True)
        try:
            with stage('sign'):
                ring.sign(challenge)
        finally:
            ring.close()

        # A separate GnuPG home imports only the pinned public certificate.
        with stage('verify-import'):
            ring = signing.Keyring(public, policy, secret=False)
        try:
            with stage('verify'):
                ring.verify(challenge)
            with stage('tamper'):
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
        # Match the publisher's single terminal newline normalization on strings.
        normalized_password = password
        if normalized_password.endswith('\r\n'):
            normalized_password = normalized_password[:-2]
        elif normalized_password.endswith('\n'):
            normalized_password = normalized_password[:-1]
        try:
            os.environ['PACMAN_SIGNING_PASSPHRASE'] = (
                normalized_password + '-incorrect-' + secrets.token_hex(16)
            )
            with stage('wrong-password-import'):
                ring = signing.Keyring(public, policy, secret=True)
            try:
                with stage('wrong-password'):
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
        label = str(error) if isinstance(error, ValidationFailure) else 'setup-or-cleanup'
        print('FAIL: credential validation [stage=' + label + ']', file=sys.stderr)
        raise SystemExit(1)
