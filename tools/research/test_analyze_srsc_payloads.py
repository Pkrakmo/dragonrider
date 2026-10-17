import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


class PayloadMeasurementsTest(unittest.TestCase):
    def test_prefix_and_invalid_ranges(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'input'
            root.mkdir()
            output = Path(temporary) / 'private.json'
            payload = struct.pack('<IIII', 32, 96, 32, 8)
            entries = (struct.pack('<HIII', 0x40, 1, 12, 16)
                       + struct.pack('<HIII', 0x40, 2, 12, 15)
                       + struct.pack('<HIII', 0x40, 3, 27, 16)
                       + struct.pack('<HIII', 0x41, 4, 12, 16))
            (root / 'sample.txd').write_bytes(b'SRSC' + struct.pack('<HIH', 0x100, 28, 4) + payload + entries)
            script = Path(__file__).with_name('analyze_srsc_payloads.py')
            subprocess.run([sys.executable, str(script), str(root), str(output)],
                           check=True, capture_output=True, text=True)
            result = json.loads(output.read_text(encoding='utf-8'))
            summary = result['summary']
            self.assertEqual(summary['records'], 1)
            self.assertEqual(summary['invalid_ranges'], 2)
            self.assertEqual(summary['c_times_8_equals_a_times_d_low16'], 1)
            self.assertEqual(summary['both_power_of_two'], 0)
            self.assertEqual(summary['records_by_extension'], {'.txd': 1})
            self.assertEqual(result['files'][0]['records'][0]['b'], 96)


if __name__ == '__main__':
    unittest.main()
