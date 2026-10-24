#!/usr/bin/env python3
"""Stage an operator's qualification receipt and report for retention.

"Publish qualified unsigned lane" reads `qualification.json` and the report it
names from an artifact of a run in this repository. This writes exactly those
two files into OUTPUT, after checking that both match the operator-approved
SHA256s, that the receipt is for the approved bundle manifest, that every gate
release-bundle.py requires is recorded as "pass", and that the report name is
a plain file name next to the receipt. It does not judge the qualification
itself; the publisher re-checks the receipt against the bundle bytes.
"""
import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('bundle', Path(__file__).with_name('release-bundle.py'))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)

SHA256 = re.compile(r'[0-9a-f]{64}')
REPORT_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}')


def fail(message):
    raise SystemExit(f'error: {message}')


def decode(name, value, expected):
    try:
        data = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        fail(f'{name} is not base64')
    if not data:
        fail(f'{name} is empty')
    if hashlib.sha256(data).hexdigest() != expected:
        fail(f'{name} does not match its approved SHA256')
    return data


def stage(receipt_b64, receipt_sha256, report_b64, report_sha256, manifest_sha256, output):
    for name, value in (('receipt SHA256', receipt_sha256), ('report SHA256', report_sha256),
                        ('manifest SHA256', manifest_sha256)):
        if not SHA256.fullmatch(value):
            fail(f'{name} must be 64 lowercase hex digits')
    receipt_bytes = decode('qualification.json', receipt_b64, receipt_sha256)
    report_bytes = decode('report', report_b64, report_sha256)
    try:
        receipt = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail('qualification.json is not JSON')
    if not isinstance(receipt, dict):
        fail('qualification.json is not an object')
    if receipt.get('manifest_sha256') != manifest_sha256:
        fail('the receipt is for a different bundle manifest')
    if receipt.get('checks') != {name: 'pass' for name in bundle.CHECKS}:
        fail(f'the receipt must record exactly these gates as pass: {", ".join(sorted(bundle.CHECKS))}')
    report_name = receipt.get('report')
    if not isinstance(report_name, str) or not REPORT_NAME.fullmatch(report_name) or report_name == 'qualification.json':
        fail('the receipt must name its report as a plain file name')
    if receipt.get('report_sha256') != report_sha256:
        fail('the receipt names a different report SHA256')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'qualification.json').write_bytes(receipt_bytes)
    (output / report_name).write_bytes(report_bytes)
    print(f'staged qualification.json and {report_name} for manifest {manifest_sha256}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--receipt-b64', required=True)
    parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--report-b64', required=True)
    parser.add_argument('--report-sha256', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    stage(args.receipt_b64, args.receipt_sha256, args.report_b64, args.report_sha256,
          args.manifest_sha256, args.output)
