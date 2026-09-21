#!/usr/bin/env python3
"""Catalog selection tests; no network or native package operations."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bootstrap', Path(__file__).with_name('bootstrap-rc.py'))
assert spec is not None and spec.loader is not None
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class InventoryAccepted(Exception):
    pass


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = self.root / 'selected.json'
        self.catalog.write_bytes((boot.ROOT / 'scripts/fixtures/rc4/packages.json').read_bytes())
        self.names = {p['name'] for p in json.loads(self.catalog.read_bytes())['packages']}
        self.assertEqual(len(self.names), 52)
        current = {p['name'] for p in json.loads((boot.ROOT / 'packages.json').read_text())['packages']}
        self.assertTrue({'omazed', 'zed'} <= current - self.names)
        self.args = argparse.Namespace(lane='rc', database_sha256='a' * 64,
            output=self.root / 'capture', catalog=self.catalog,
            catalog_sha256=hashlib.sha256(self.catalog.read_bytes()).hexdigest())

    def capture_to_inventory(self, names=None):
        names = self.names if names is None else names
        release = {'draft': False, 'asset_map': {'omarchy-aarch64.db': {}}}
        def guard(path, reserve=None):
            if reserve is not None:
                raise InventoryAccepted()
        with patch.object(boot, 'guard', guard), patch.object(boot, 'GitHub') as transport, \
             patch.object(boot.bundle, 'database', return_value={n: {'CSIZE': ['1']} for n in names}), \
             patch.object(boot.bundle, 'digest', return_value='a' * 64), patch.object(boot.bundle, 'copy_file'):
            transport.return_value.release.return_value = release
            transport.return_value.read.return_value = 'a' * 64
            boot.capture(self.args)

    def test_catalog_pin_rejected_before_remote_io(self):
        for path, checksum in [(self.catalog, 'b' * 64), (self.catalog, None),
                               (None, self.args.catalog_sha256), (self.catalog, '../escape')]:
            with self.subTest(path=path, checksum=checksum):
                self.args.catalog, self.args.catalog_sha256 = path, checksum
                with patch.object(boot, 'guard'), patch.object(boot, 'GitHub', side_effect=AssertionError('remote IO reached')) as remote:
                    with self.assertRaisesRegex(ValueError, 'catalog|Catalog'):
                        boot.capture(self.args)
                    remote.assert_not_called()
                self.assertFalse(self.args.output.exists())

    def test_default_still_rejects_missing_current_names(self):
        self.args.catalog = self.args.catalog_sha256 = None
        with self.assertRaisesRegex(ValueError, 'missing required baseline packages'):
            self.capture_to_inventory()

    def test_selected_catalog_still_requires_historical_member(self):
        with self.assertRaisesRegex(ValueError, 'missing required baseline packages'):
            self.capture_to_inventory(self.names - {'avd-fw'})

    def test_cli_accepts_paired_catalog_options(self):
        argv = ['bootstrap-rc.py', 'capture', '--database-sha256', 'a' * 64,
                '--output', str(self.args.output), '--catalog', str(self.catalog),
                '--catalog-sha256', self.args.catalog_sha256]
        with patch('sys.argv', argv), patch.object(boot, 'capture') as capture:
            boot.main()
            self.assertEqual(capture.call_args.args[0].catalog, self.catalog)
            self.assertEqual(capture.call_args.args[0].catalog_sha256, self.args.catalog_sha256)

    def test_selected_catalog_replaces_only_capture_inventory(self):
        with self.assertRaises(InventoryAccepted):
            self.capture_to_inventory()
        self.assertEqual((self.args.output / 'catalog.json').read_bytes(), self.catalog.read_bytes())


if __name__ == '__main__':
    unittest.main()
