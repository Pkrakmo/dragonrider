import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_srsc_0102_prefix import classify


class PrefixTests(unittest.TestCase):
    def test_prefix_bounds(self):
        self.assertEqual(classify(b'\x01', 1, 0)['short_prefix'], 1)
        self.assertEqual(classify(b'\x05\x00abc', 5, 0)['prefix_exceeds_payload'], 1)
        with self.assertRaises(ValueError):
            classify(b'\x05\x00abc', 7, 0)
        self.assertEqual(classify(b'\x00\x00' + bytes(9), 11, 0)['following_fewer_than_10_bytes'], 1)

    def test_zero_length_prefix_and_exact_following_boundary(self):
        # Two skipped bytes, four-byte field, two-byte field, and two more
        # bytes are the ten bytes consumed after the length-prefixed label.
        exact = b'\x00\x00' + bytes(10)
        result = classify(exact, len(exact), 0)
        self.assertEqual(result['prefix_fits'], 1)
        self.assertEqual(result['prefix_zero'], 1)
        self.assertEqual(result['following_at_least_10_bytes'], 1)
        self.assertEqual(result['payload_high_zero'], 1)
        self.assertEqual(result['third_zero'], 1)
        self.assertEqual(result['payload_high_equals_third'], 1)
        self.assertNotIn('following_fewer_than_10_bytes', result)

    def test_label_classification_and_nonzero_comparison_counters(self):
        # A two-byte label ends in NUL; the first dword after the two skipped
        # bytes has high half 0x1234, matching the table's third word.
        payload = b'\x02\x00A\x00' + b'\xff\xee' + b'\x78\x56\x34\x12' + bytes(4)
        result = classify(payload, len(payload), 0x1234)
        self.assertEqual(result['prefix_printable_or_nul'], 1)
        self.assertEqual(result['prefix_trailing_nul'], 1)
        self.assertEqual(result['payload_high_equals_nonzero_third'], 1)

        non_printable = classify(b'\x01\x00\x01' + bytes(10), 13, 1)
        self.assertEqual(non_printable['prefix_printable_or_nul'], 0)
        self.assertEqual(non_printable['prefix_trailing_nul'], 0)

    def test_dword_high_and_selector_comparison(self):
        payload = b'\x02\x00X\x00' + b'\xaa\xbb' + b'\x34\x12\x78\x56' + bytes(4)
        result = classify(payload, len(payload), 0x5678)
        self.assertEqual(result['prefix_printable_or_nul'], 1)
        self.assertEqual(result['following_at_least_10_bytes'], 1)
        self.assertEqual(result['payload_high_equals_nonzero_third'], 1)
        self.assertEqual(classify(payload, len(payload), 0x1234)['payload_high_equals_third'], 0)
        with self.assertRaises(ValueError):
            classify(payload[:-1], len(payload), 0)

    def test_scan_and_reject_invalid_range(self):
        script = Path(__file__).with_name('measure_srsc_0102_prefix.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def run(extra_length):
                payload = b'\x00\x00' + bytes(10)
                table = 12 + len(payload)
                record = struct.pack('<HHHII', 0x0102, 1, 2, 12, len(payload) + extra_length)
                data = b'SRSC' + struct.pack('<HIH', 0x100, table, 1) + payload + record
                (root / 'sample').write_bytes(data)
                (root / 'inventory.json').write_text(json.dumps({'files': [{
                    'path': 'sample', 'status': 'examined',
                    'sha256': hashlib.sha256(data).hexdigest()}]}), encoding='utf-8')
                return subprocess.run([sys.executable, str(script), str(root), str(root / 'inventory.json')],
                                      capture_output=True, text=True, check=False)

            valid = run(0)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(json.loads(valid.stdout)['payload_high_zero'], 1)
            invalid = run(1)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn('outside pre-table range', invalid.stderr)

    def test_scan_rejects_stale_inventory_hash_and_unexamined_entry(self):
        script = Path(__file__).with_name('measure_srsc_0102_prefix.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b'\x00\x00' + bytes(10)
            table = 12 + len(payload)
            record = struct.pack('<HHHII', 0x0102, 1, 2, 12, len(payload))
            data = b'SRSC' + struct.pack('<HIH', 0x100, table, 1) + payload + record
            (root / 'sample').write_bytes(data)
            inventory_path = root / 'inventory.json'
            base_entry = {'path': 'sample', 'status': 'examined',
                          'sha256': hashlib.sha256(data).hexdigest()}

            stale = dict(base_entry, sha256='0' * 64)
            inventory_path.write_text(json.dumps({'files': [stale]}), encoding='utf-8')
            result = subprocess.run([sys.executable, str(script), str(root), str(inventory_path)],
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('inventory hash mismatch', result.stderr)

            unexamined = dict(base_entry, status='unexamined')
            inventory_path.write_text(json.dumps({'files': [unexamined]}), encoding='utf-8')
            result = subprocess.run([sys.executable, str(script), str(root), str(inventory_path)],
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unexamined files', result.stderr)


if __name__ == '__main__':
    unittest.main()
