import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_srsc_0302_prefix import classify


class PrefixTests(unittest.TestCase):
    def test_truncation_and_budget(self):
        self.assertEqual(classify(b'\0')['short_prefix'], 1)
        self.assertEqual(classify(b'\x03\0ab')['prefix_exceeds_payload'], 1)
        self.assertEqual(classify(b'\0\0' + bytes(24))['following_at_least_24_bytes'], 1)
        self.assertEqual(classify(b'\0\0' + bytes(23))['following_at_least_24_bytes'], 0)
        self.assertEqual(classify(b'\0\0', 100000)['following_at_least_24_bytes'], 1)
        with self.assertRaises(ValueError):
            classify(b'\x04\0ab', 100)

    def test_printable_and_embedded_nul(self):
        result = classify(b'\x04\0a\0b\0' + bytes(24))
        self.assertEqual(result['prefix_fits'], 1)
        self.assertEqual(result['prefix_printable_or_nul'], 1)
        self.assertEqual(result['prefix_embedded_nul'], 1)
        self.assertEqual(result['prefix_trailing_nul'], 1)
        self.assertEqual(classify(b'\x01\0\xff')['prefix_printable_or_nul'], 0)

    def test_inventory_scan_and_reject_out_of_range(self):
        script = Path(__file__).with_name('measure_srsc_0302_prefix.py')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = b'\x02\0A\0' + bytes(24)
            def run(record_length):
                table = 12 + len(payload)
                record = struct.pack('<HHHII', 0x302, 1, 4, 12, record_length)
                data = b'SRSC' + struct.pack('<HIH', 0x100, table, 1) + payload + record
                (root / 'sample').write_bytes(data)
                (root / 'inventory.json').write_text(json.dumps({'files': [{
                    'path': 'sample', 'status': 'examined',
                    'sha256': hashlib.sha256(data).hexdigest()}]}), encoding='utf-8')
                return subprocess.run([sys.executable, str(script), str(root), str(root / 'inventory.json')],
                                      capture_output=True, text=True, check=False)
            valid = run(len(payload))
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(json.loads(valid.stdout)['following_at_least_24_bytes'], 1)
            invalid = run(len(payload) + 1)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn('outside pre-table range', invalid.stderr)


if __name__ == '__main__':
    unittest.main()
