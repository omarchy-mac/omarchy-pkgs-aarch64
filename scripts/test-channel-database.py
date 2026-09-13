#!/usr/bin/python3
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('collect', Path(__file__).with_name('collect-channel.py'))
collect = importlib.util.module_from_spec(spec); spec.loader.exec_module(collect)

class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
    def record(self, name='aquamarine', version='0.15.0-2', filename=None, digest='a' * 64):
        return ('%NAME%\n' + name + '\n\n%VERSION%\n' + version + '\n\n%FILENAME%\n' +
                (filename or name + '-' + version + '-aarch64.pkg.tar.zst') + '\n\n%SHA256SUM%\n' + digest + '\n\n').encode()
    def database(self, records):
        path = self.root / 'extra.db'
        with tarfile.open(path, 'w:gz') as archive:
            for name, data in records:
                member = tarfile.TarInfo(name); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return path
    def test_selected_transaction_ignores_unrelated_corrupt_upstream_record(self):
        db = self.database([('findnewest-0.3-4/desc', b'\0' * 1271), ('aquamarine-0.15.0-2/desc', self.record())])
        result = collect.entries(db, {'aquamarine': '0.15.0-2'})
        self.assertEqual(result['aquamarine']['%SHA256SUM%'], 'a' * 64)
        with self.assertRaisesRegex(ValueError, 'Malformed database record'):
            collect.entries(db)  # Complete managed baselines must still reject this.
    def test_selected_corruption_and_missing_record_fail(self):
        db = self.database([('aquamarine-0.15.0-2/desc', b'\0' * 1271)])
        with self.assertRaisesRegex(ValueError, 'Malformed database record'):
            collect.entries(db, {'aquamarine': '0.15.0-2'})
        with self.assertRaisesRegex(ValueError, 'missing'):
            collect.entries(db, {'missing': '1-1'})
    def test_duplicate_selected_record_fails(self):
        row = ('aquamarine-0.15.0-2/desc', self.record())
        db = self.database([row, row])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            collect.entries(db, {'aquamarine': '0.15.0-2'})
    def test_selected_identity_hash_and_filename_are_strict(self):
        for body in (self.record(name='other'), self.record(version='0.14.0-2'), self.record(filename='../bad'), self.record(digest='invalid'), b'%NAME%\naquamarine\n'):
            with self.subTest(body=body):
                db = self.database([('aquamarine-0.15.0-2/desc', body)])
                with self.assertRaises(ValueError):
                    collect.entries(db, {'aquamarine': '0.15.0-2'})
    def test_epoch_identity_remains_supported(self):
        db = self.database([('ffmpeg-2:9.0.1-4/desc', self.record(name='ffmpeg', version='2:9.0.1-4'))])
        self.assertEqual(collect.entries(db, {'ffmpeg': '2:9.0.1-4'})['ffmpeg']['%VERSION%'], '2:9.0.1-4')

if __name__ == '__main__': unittest.main()
