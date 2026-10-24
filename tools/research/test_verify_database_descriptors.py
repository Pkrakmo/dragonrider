import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from verify_database_descriptors import decode

SCRIPT = Path(__file__).with_name('verify_database_descriptors.py')


class DescriptorVerificationTests(unittest.TestCase):
    def test_decodes_names_with_spaces_and_duplicate_ids(self):
        self.assertEqual(decode(b'version 1\r\ndependencies 2\r\n3 path one\r\n3 other\r\n'),
                         [(3, b'path one'), (3, b'other')])

    def test_rejects_wrong_counts_and_truncation(self):
        for data in (b'version 1\r\ndependencies 1\r\n',
                     b'version 1\r\ndependencies 1\r\n1 name',
                     b'version 1\r\ndependencies 1\r\n2147483648 name\r\n'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode(data)

    def test_inspector_receives_hash_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'sample.db'
            data = b'version 1\r\ndependencies 1\r\n7 name\r\n'
            source.write_bytes(data)
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'files': [{
                'path': source.name,
                'size': len(data),
                'sha256': hashlib.sha256(data).hexdigest(),
            }]}), encoding='utf-8')
            inspector = root / 'inspector'
            inspector.write_text(
                '#!/usr/bin/env python3\n'
                'import pathlib, sys\n'
                f'expected = bytes.fromhex({data.hex()!r})\n'
                'sample = pathlib.Path(sys.argv[-1])\n'
                'assert sample.name == "verified-descriptor.db"\n'
                'assert sample.read_bytes() == expected\n'
                'print("Database descriptor version: 1")\n'
                'print("Dependencies: 1")\n'
                'print("Dependency 0: id=7 bytes=4 crc32=5e237e06")\n',
                encoding='utf-8')
            inspector.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), str(inventory), '--inspector', str(inspector)],
                capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'matched 1 hash-verified descriptors and 1 dependencies\n')


if __name__ == '__main__':
    unittest.main()
