import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_0302_followup import classify


def body(mode, size, tail):
    return struct.pack('<IHHIIIIII', 4, 3, 16, 4, 11, 12, 13, size, mode) + tail


class FollowupTests(unittest.TestCase):
    def test_zero_and_nonzero_mode_exact_tails(self):
        a = classify(b'\x02\0A\0' + body(0, 4, b'abcd'))
        self.assertEqual(a['mode_at_28_zero'], 1)
        self.assertEqual(a['zero_mode_size_exact'], 1)
        self.assertEqual(a['product_equals_size'], 0)
        self.assertEqual(a['cached_mode_nonzero'], 1)
        self.assertEqual(a['cached_stored_zero'], 1)
        self.assertEqual(a['cached_stored_exact'], 0)
        b = classify(b'\0\0' + body(1, 123, struct.pack('<I', 5) + b'abcde'))
        self.assertEqual(b['mode_at_28_one'], 1)
        self.assertEqual(b['nonzero_mode_length_exact'], 1)
        self.assertEqual(b['nonzero_mode_length_fits'], 1)
        self.assertEqual(b['cached_stored_one'], 1)
        self.assertEqual(b['cached_stored_fits'], 1)
        c = classify(b'\0\0' + body(2, 1, struct.pack('<I', 50) + b'a'))
        self.assertEqual(c['mode_at_28_other'], 1)
        self.assertEqual(c['nonzero_mode_length_fits'], 0)

    def test_short_prefix_headers_and_length(self):
        self.assertEqual(classify(b'\0')['short_prefix'], 1)
        self.assertEqual(classify(b'\x04\0x')['prefix_exceeds_record'], 1)
        self.assertEqual(classify(b'\0\0' + bytes(31))['less_than_32_after_prefix'], 1)
        self.assertEqual(classify(b'\0\0' + body(1, 0, b''))['nonzero_mode_length_missing'], 1)
        self.assertEqual(classify(b'\0\0' + body(1, 0, b''))['cached_mode_zero'], 1)
        with self.assertRaises(ValueError):
            classify(b'\0\0' + bytes(31), 100)

    def test_product_truncates_to_16_bits_before_the_second_product(self):
        fixed = struct.pack('<IHHIIIIII', 0, 65535, 24, 2, 0, 0, 0, 131066, 7)
        result = classify(b'\0\0' + fixed + struct.pack('<I', 0))
        self.assertEqual(result['product_equals_size'], 1)
        self.assertEqual(result['mode_at_28_other'], 1)
        self.assertEqual(result['nonzero_mode_length_exact'], 1)

    def test_inventory_rechecks_hash_and_payload_bounds(self):
        script = Path(__file__).with_name('measure_0302_followup.py')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = b'\0\0' + body(0, 4, b'abcd')

            def run(record_length, change_hash=False):
                table = 12 + len(payload)
                record = struct.pack('<HHHII', 0x302, 1, 4, 12, record_length)
                data = b'SRSC' + struct.pack('<HIH', 0x100, table, 1) + payload + record
                (root / 'sample').write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                if change_hash:
                    digest = '0' * 64
                (root / 'inventory.json').write_text(json.dumps({'files': [{
                    'path': 'sample', 'status': 'examined', 'sha256': digest}]}), encoding='utf-8')
                return subprocess.run([sys.executable, str(script), str(root), str(root / 'inventory.json')],
                                      capture_output=True, text=True, check=False)

            valid = run(len(payload))
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(json.loads(valid.stdout)['zero_mode_size_exact'], 1)
            invalid = run(len(payload) + 1)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn('outside pre-table range', invalid.stderr)
            changed = run(len(payload), change_hash=True)
            self.assertNotEqual(changed.returncode, 0)
            self.assertIn('inventory hash mismatch', changed.stderr)


if __name__ == '__main__':
    unittest.main()
