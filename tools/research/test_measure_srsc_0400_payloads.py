import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_srsc_0400_payloads import classify


class TransformTests(unittest.TestCase):
    def test_empty_and_third_word(self):
        result = classify(b'', 7)
        self.assertEqual(result['empty'], 1)
        self.assertEqual(result['third_zero'], 0)
        self.assertEqual(result['transformed_printable'], 0)

    def test_traced_first_two_key_bytes(self):
        # First state bytes are 0x0d and 0x6a after a 32-bit left rotate by 3.
        result = classify(bytes((ord('A') ^ 0x0d, ord('B') ^ 0x6a)), 0)
        self.assertEqual(result['transformed_printable'], 1)
        self.assertEqual(result['third_zero'], 1)
        self.assertEqual(result['transformed_nul'], 0)

    def test_detect_transformed_terminal_nul(self):
        result = classify(bytes((0x0d,)), 0)
        self.assertEqual(result['transformed_nul'], 1)
        self.assertEqual(result['transformed_trailing_nul'], 1)

    def test_full_measurement_and_reject_payload_past_table(self):
        script = Path(__file__).with_name('measure_srsc_0400_payloads.py')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = bytes((ord('A') ^ 0x0d, ord('B') ^ 0x6a))
            def run(length):
                record = struct.pack('<HHHII', 0x400, 9, 0, 12, length)
                data = b'SRSC' + struct.pack('<HIH', 0x100, 14, 1) + payload + record
                (root / 'synthetic').write_bytes(data)
                inventory = {'files': [{'path': 'synthetic', 'status': 'examined',
                                         'sha256': hashlib.sha256(data).hexdigest()}]}
                (root / 'inventory.json').write_text(json.dumps(inventory), encoding='utf-8')
                return subprocess.run([sys.executable, str(script), str(root), str(root / 'inventory.json')],
                                      capture_output=True, text=True, check=False)
            valid = run(2)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(json.loads(valid.stdout)['transformed_printable'], 1)
            invalid = run(3)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn('bounded pre-table range', invalid.stderr)


if __name__ == '__main__':
    unittest.main()
