#!/usr/bin/env python3
"""Launch the isolated RC4 signer with credentials only on its private stdin."""
import base64
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

SECRET_NAMES = ('RC4_SIGNING_SUBKEY_B64', 'RC4_SIGNING_PASSPHRASE')
EXPECTED_REPOSITORY = 'omarchy-mac/omarchy-pkgs-aarch64'
EXPECTED_REPOSITORY_ID = '1327386148'
CHILD_ENVIRONMENT_KEYS = ('HOME', 'LANG')


def require(condition):
    if not condition:
        raise ValueError('Protected signing credentials or execution identity missing or malformed')


def zero(value):
    if isinstance(value, bytearray):
        value[:] = b'\x00' * len(value)


def pop_credentials(environment):
    """Remove protected values before any validation, filesystem work, or child starts."""
    encoded = environment.pop(SECRET_NAMES[0], None)
    passphrase = environment.pop(SECRET_NAMES[1], None)
    key = password = None
    try:
        require(isinstance(encoded, str) and isinstance(passphrase, str) and passphrase and
                '\n' not in passphrase and '\r' not in passphrase)
        key = bytearray(base64.b64decode(''.join(encoded.split()), validate=True))
        password = bytearray(passphrase.encode())
        require(key and len(key) <= 1024 * 1024 and len(password) <= 16 * 1024)
        return key, password
    except BaseException:
        zero(key)
        zero(password)
        raise


def write_part(output, value):
    require(0 < len(value) <= 1024 * 1024)
    output.write(struct.pack('>I', len(value)))
    output.write(value)


def write_frame_from_environment(environment, output):
    """Fixture helper used by the synthetic frame parser tests."""
    key, password = pop_credentials(environment)
    try:
        write_part(output, key)
        write_part(output, password)
        output.flush()
    finally:
        key[:] = b'\x00' * len(key)
        password[:] = b'\x00' * len(password)


def write_all(file_descriptor, value):
    view = memoryview(value)
    try:
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError('Private signing pipe closed')
            view = view[written:]
    finally:
        view.release()


def write_fd_part(file_descriptor, value):
    header = struct.pack('>I', len(value))
    write_all(file_descriptor, header)
    write_all(file_descriptor, value)


def close_fd(file_descriptor):
    if file_descriptor is not None:
        try:
            os.close(file_descriptor)
        except OSError:
            pass


def launch_isolated_signer(environment, argv, credentials, popen_factory=subprocess.Popen):
    """Launch one sanitized child using already-popped mutable credentials."""
    key, password = credentials
    read_fd = write_fd = None
    process = None
    try:
        child_environment = {
            key: environment[key] for key in CHILD_ENVIRONMENT_KEYS
            if isinstance(environment.get(key), str) and environment[key]
        }
        require(not (set(SECRET_NAMES) & set(child_environment)))
        require(all(isinstance(value, str) and value for value in argv))
        read_fd, write_fd = os.pipe()
        process = popen_factory(
            list(argv), stdin=read_fd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=child_environment, close_fds=True,
        )
        close_fd(read_fd)
        read_fd = None
        write_fd_part(write_fd, key)
        write_fd_part(write_fd, password)
        close_fd(write_fd)
        write_fd = None
        status = process.wait()
        if status != 0:
            raise RuntimeError('isolated signer failed')
    except BaseException as error:
        close_fd(write_fd)
        write_fd = None
        close_fd(read_fd)
        read_fd = None
        if process is not None and process.returncode is None:
            status = process.wait()
            if status != 0:
                raise RuntimeError('isolated signer failed') from error
        raise
    finally:
        close_fd(write_fd)
        close_fd(read_fd)


def run_isolated_signer(environment, argv, popen_factory=subprocess.Popen):
    """Pop secrets, privately frame them to one sanitized child, and wait."""
    credentials = pop_credentials(environment)
    try:
        return launch_isolated_signer(environment, argv, credentials, popen_factory)
    finally:
        for value in credentials:
            zero(value)


def value(environment, name) -> str:
    result = environment.get(name)
    if not isinstance(result, str) or not result:
        raise ValueError('Protected signing credentials or execution identity missing or malformed')
    return result


def validate_repository(environment):
    require(value(environment, 'GITHUB_REPOSITORY') == EXPECTED_REPOSITORY)
    require(value(environment, 'OBSERVED_REPOSITORY_ID') == EXPECTED_REPOSITORY_ID)
    require(value(environment, 'EXPECTED_REPOSITORY_ID') == EXPECTED_REPOSITORY_ID)


def validate_first_attempt(environment):
    if value(environment, 'GITHUB_RUN_ATTEMPT') != '1':
        raise ValueError('Workflow run attempt must be 1')


def signer_argv(environment, docker_executable):
    """Construct the complete no-network signer command without secret values."""
    validate_repository(environment)
    validate_first_attempt(environment)
    docker_path = Path(docker_executable)
    require(docker_path.is_absolute() and docker_path.name == 'docker')
    workspace = Path(value(environment, 'GITHUB_WORKSPACE')).resolve()
    runner_temp = Path(value(environment, 'RUNNER_TEMP')).resolve()
    verified = runner_temp / 'rc4-sign/verified'
    output = runner_temp / 'rc4-sign/output'
    gnupg = runner_temp / 'rc4-sign/gnupg'
    image = ('ghcr.io/omarchy-mac/omarchy-pkgs-aarch64/rc4-fixture-signer@' +
             value(environment, 'INPUT_SIGNER_IMAGE_DIGEST'))
    return [
        str(docker_path), 'run', '-i', '--rm', '--network', 'none', '--pull', 'never', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--user', f'{os.getuid()}:{os.getgid()}',
        '-v', f'{workspace}:/w:ro', '-w', '/w',
        '-v', f'{verified}:/task/verified:ro',
        '-v', f'{output}:/task/output',
        '-v', f'{gnupg}:/task/gnupg',
        '-e', 'TMPDIR=/task/gnupg', '-e', 'TMP=/task/gnupg', '-e', 'TEMP=/task/gnupg',
        '-e', 'PYTHONDONTWRITEBYTECODE=1', image,
        'python3', 'scripts/rc4-sign-retain.py', 'sign-candidate',
        '--identity', 'scripts/rc4-sign-retain-inputs.json',
        '--identity-sha256', value(environment, 'INPUT_IDENTITY_SHA256'),
        '--metadata', '/task/verified/release-metadata.json',
        '--input', '/task/verified/input',
        '--unsigned-manifest', '/task/verified/unsigned-input-manifest.json',
        '--candidate', '/task/output/candidate',
        '--workflow-run-id', value(environment, 'GITHUB_RUN_ID'),
        '--workflow-run-attempt', value(environment, 'GITHUB_RUN_ATTEMPT'),
        '--workflow-head-sha', value(environment, 'GITHUB_SHA'),
        '--workflow-blob-sha', value(environment, 'INPUT_WORKFLOW_BLOB_SHA'),
        '--helper-blob-sha', value(environment, 'INPUT_HELPER_BLOB_SHA'),
        '--signer-blob-sha', value(environment, 'INPUT_SIGNER_BLOB_SHA'),
        '--feeder-blob-sha', value(environment, 'INPUT_FEEDER_BLOB_SHA'),
        '--policy-blob-sha', value(environment, 'INPUT_POLICY_BLOB_SHA'),
        '--public-key-blob-sha', value(environment, 'INPUT_PUBLIC_KEY_BLOB_SHA'),
        '--dockerfile-blob-sha', value(environment, 'INPUT_DOCKERFILE_BLOB_SHA'),
        '--base-image-digest', value(environment, 'INPUT_BASE_IMAGE_DIGEST'),
        '--signer-image-digest', value(environment, 'INPUT_SIGNER_IMAGE_DIGEST'),
    ]


def main():
    credentials = pop_credentials(os.environ)
    root = gnupg = output = None
    try:
        validate_repository(os.environ)
        validate_first_attempt(os.environ)
        docker_executable = shutil.which('docker')
        if not isinstance(docker_executable, str):
            raise ValueError('Reviewed Docker executable is unavailable')
        docker_executable = str(Path(docker_executable).resolve())
        argv = signer_argv(os.environ, docker_executable)
        runner_temp = Path(value(os.environ, 'RUNNER_TEMP')).resolve()
        root = runner_temp / 'rc4-sign'
        gnupg = root / 'gnupg'
        output = root / 'output'
        require(not gnupg.is_symlink() and not output.is_symlink())
        if gnupg.exists():
            shutil.rmtree(gnupg)
        gnupg.mkdir(parents=True, mode=0o700)
        output.mkdir(parents=True, exist_ok=True)
        try:
            launch_isolated_signer(os.environ, argv, credentials)
        finally:
            if gnupg.exists():
                shutil.rmtree(gnupg)
        require(not gnupg.exists())
    finally:
        for value_buffer in credentials:
            zero(value_buffer)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError):
        raise SystemExit('Signing credential transfer or isolated signer failed')
