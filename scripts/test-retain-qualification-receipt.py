#!/usr/bin/env python3
"""Portable checks for retain-qualification-receipt.py."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('receipt', Path(__file__).with_name('retain-qualification-receipt.py'))
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)

MANIFEST = 'a' * 64


def encoded(data):
    return base64.b64encode(data).decode(), hashlib.sha256(data).hexdigest()


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.report = b'# Qualification\nVM upgrade from 4.0.3rc4-2 and 4.0.2-2.\n'
        self.receipt = {'manifest_sha256': MANIFEST,
                        'checks': {name: 'pass' for name in receipt.bundle.CHECKS},
                        'report': 'qualification-report.md',
                        'report_sha256': hashlib.sha256(self.report).hexdigest()}

    def stage(self, data=None, report=None, manifest=MANIFEST, output='out'):
        receipt_bytes = json.dumps(self.receipt if data is None else data).encode()
        r64, rsha = encoded(receipt_bytes)
        p64, psha = encoded(self.report if report is None else report)
        receipt.stage(r64, rsha, p64, psha, manifest, self.tmp / output)
        return self.tmp / output

    def test_stages_the_two_files_the_publisher_reads(self):
        out = self.stage()
        self.assertEqual(sorted(p.name for p in out.iterdir()), ['qualification-report.md', 'qualification.json'])
        self.assertEqual(json.loads((out / 'qualification.json').read_text()), self.receipt)
        self.assertEqual((out / 'qualification-report.md').read_bytes(), self.report)

    def test_staged_receipt_satisfies_the_publishers_check(self):
        out = self.stage()
        bundle_dir = self.tmp / 'bundle'
        bundle_dir.mkdir()
        manifest = bundle_dir / 'manifest.json'
        manifest.write_text('{}')
        self.receipt['manifest_sha256'] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        out = self.stage(manifest=self.receipt['manifest_sha256'], output='bound')
        receipt.bundle.receipt(bundle_dir, out / 'qualification.json')

    def test_rejects_a_changed_receipt(self):
        receipt_bytes = json.dumps(self.receipt).encode()
        r64, _ = encoded(receipt_bytes)
        p64, psha = encoded(self.report)
        with self.assertRaises(SystemExit):
            receipt.stage(r64, 'b' * 64, p64, psha, MANIFEST, self.tmp / 'x')

    def test_rejects_another_bundle(self):
        with self.assertRaises(SystemExit):
            self.stage(manifest='c' * 64)

    def test_rejects_a_missing_or_failed_gate(self):
        for checks in ({**self.receipt['checks'], 'review': 'fail'},
                       {k: v for k, v in self.receipt['checks'].items() if k != 'review'}):
            with self.assertRaises(SystemExit):
                self.stage(data={**self.receipt, 'checks': checks}, output=f'g{len(checks)}')

    def test_rejects_a_report_path_outside_the_artifact(self):
        for name in ('../report.md', 'sub/report.md', 'qualification.json', ''):
            with self.assertRaises(SystemExit):
                self.stage(data={**self.receipt, 'report': name}, output='p')

    def test_rejects_a_report_the_receipt_does_not_name(self):
        with self.assertRaises(SystemExit):
            self.stage(report=b'another report\n')

    def test_rejects_input_that_is_not_base64(self):
        with self.assertRaises(SystemExit):
            receipt.stage('not base64!', 'a' * 64, 'eA==', 'a' * 64, MANIFEST, self.tmp / 'b')


if __name__ == '__main__':
    unittest.main()
