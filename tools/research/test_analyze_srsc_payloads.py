import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from analyze_srsc_payloads import inspect_with_snapshot


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
            contents = b'SRSC' + struct.pack('<HIH', 0x100, 28, 4) + payload + entries
            sample = root / 'sample.txd'
            sample.write_bytes(contents)
            inspected, snapshot = inspect_with_snapshot(sample, root)
            self.assertEqual(snapshot, contents)
            self.assertEqual(inspected['sha256'], hashlib.sha256(snapshot).hexdigest())
            self.assertEqual(inspected['records'][0]['a'], 32)
            sample.write_bytes(b'changed')
            self.assertEqual(snapshot[12:28], payload)
            sample.write_bytes(contents)
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
