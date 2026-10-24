import io
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_srsc_duplicate_payloads import (
    CHUNK, compare_groups, read_verified_records, same_bytes,
)


class DuplicateTests(unittest.TestCase):
    def test_comparison_across_chunk_boundary_and_truncation(self):
        payload = b'a' * CHUNK + b'z'
        stream = io.BytesIO(payload + payload)
        self.assertTrue(same_bytes(stream, (0, len(payload)), (len(payload), len(payload))))
        with self.assertRaises(ValueError):
            same_bytes(io.BytesIO(b'a'), (0, 2), (0, 2))
        self.assertFalse(same_bytes(stream, (0, 1), (1, 2)))

    def test_groups_compare_with_first_and_keep_other_selectors_separate(self):
        stream = io.BytesIO(b'abcabcabdxy')
        records = [(1, 2, 3, 0, 3), (1, 2, 3, 3, 3),
                   (1, 2, 3, 6, 3), (1, 2, 3, 9, 2),
                   (1, 2, 4, 0, 3)]
        result = compare_groups(records, stream)
        self.assertEqual(result['groups'], 1)
        self.assertEqual(result['occurrences_after_first'], 3)
        self.assertEqual(result['identical_bytes'], 1)
        self.assertEqual(result['different_bytes'], 2)
        self.assertEqual(result['different_length'], 1)

    def test_scan_and_reject_out_of_range(self):
        script = Path(__file__).with_name('measure_srsc_duplicate_payloads.py')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def run(second_length):
                payload = b'abcabc'
                table = 12 + len(payload)
                records = (struct.pack('<HHHII', 1, 2, 3, 12, 3) +
                           struct.pack('<HHHII', 1, 2, 3, 15, second_length))
                data = b'SRSC' + struct.pack('<HIH', 0x100, table, 2) + payload + records
                (root / 'sample').write_bytes(data)
                (root / 'inventory.json').write_text(json.dumps({'files': [{
                    'path': 'sample', 'status': 'examined', 'file_size': len(data),
                    'sha256': hashlib.sha256(data).hexdigest()}]}), encoding='utf-8')
                return subprocess.run([sys.executable, str(script), str(root), str(root / 'inventory.json')],
                                      capture_output=True, text=True, check=False)
            valid = run(3)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(json.loads(valid.stdout)['identical_bytes'], 1)
            invalid = run(4)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn('outside bounded pre-table range', invalid.stderr)

    def test_verified_snapshot_checks_hash_size_and_symlink_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = b'abc'
            table = 12 + len(payload)
            record = struct.pack('<HHHII', 1, 2, 3, 12, len(payload))
            data = b'SRSC' + struct.pack('<HIH', 0x100, table, 1) + payload + record
            path = root / 'sample'
            path.write_bytes(data)
            entry = {'path': path.name, 'status': 'examined', 'file_size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
            self.assertEqual(read_verified_records(root, entry), (data, [(1, 2, 3, 12, 3)]))
            with self.assertRaisesRegex(ValueError, 'size or hash'):
                read_verified_records(root, dict(entry, file_size=len(data) + 1))
            link = root / 'link'
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                read_verified_records(root, dict(entry, path=link.name))


if __name__ == '__main__':
    unittest.main()
