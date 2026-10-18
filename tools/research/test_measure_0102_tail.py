import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_0102_tail import measure
from test_measure_srsc_prefix_selector import fixture


def body(first, count, data=b'', tail=b''):
    return b'\x00\x00' + b'\x00' * 10 + struct.pack('<II', first, count) + data + tail


class TailTests(unittest.TestCase):
    def test_counts_valid_empty_nonempty_and_extra(self):
        data = fixture([(0x102, 0, 0, body(7, 0)),
                        (0x102, 0, 0, body(0, 2, struct.pack('<II', 0, 7), b'X')),
                        (0x301, 0, 0, b'')])
        counts, histogram, extra = measure(data)
        self.assertEqual(counts['records'], 2)
        self.assertEqual(counts['fits'], 2)
        self.assertEqual(counts['zero_count'], 1)
        self.assertEqual(counts['nonzero_count'], 1)
        self.assertEqual(counts['first_dword_zero'], 1)
        self.assertEqual(counts['extra_tail'], 1)
        self.assertEqual(counts['first_nonzero_count_zero'], 1)
        self.assertEqual(counts['first_zero_count_nonzero'], 1)
        self.assertEqual(counts['array_words'], 2)
        self.assertEqual(counts['array_zero_words'], 1)
        self.assertEqual(histogram, {0: 1, 2: 1})
        self.assertEqual(extra, {0: 1, 1: 1})

    def test_truncated_and_wrapping_counts(self):
        data = fixture([(0x102, 0, 0, b''), (0x102, 0, 0, b'\x00\x00'),
                        (0x102, 0, 0, b'\x00\x00' + b'\x00' * 17),
                        (0x102, 0, 0, body(1, 1, b'\x00' * 3)),
                        (0x102, 0, 0, body(1, 0x40000000))])
        counts, _, _ = measure(data)
        self.assertEqual(counts['short_prefix'], 1)
        self.assertEqual(counts['short_fields'], 1)
        self.assertEqual(counts['short_tail_header'], 1)
        self.assertEqual(counts['declared_data_exceeds_record'], 2)
        self.assertEqual(counts['count_multiply_wraps_32bit'], 1)
        self.assertEqual(counts['fits'], 0)

    def test_invalid_table_or_range(self):
        with self.assertRaises(ValueError):
            measure(b'SRSC')
        sample = fixture([(0x102, 0, 0, body(0, 0))])
        with self.assertRaises(ValueError):
            measure(sample[:-1])
        bad = bytearray(sample)
        table = struct.unpack_from('<I', bad, 6)[0]
        struct.pack_into('<I', bad, table + 6, 11)
        with self.assertRaises(ValueError):
            measure(bad)

    def test_cli_hash_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = fixture([(0x102, 0, 0, body(0, 0))])
            (root / 'sample').write_bytes(sample)
            item = {'path': 'sample', 'status': 'examined', 'file_size': len(sample),
                    'sha256': hashlib.sha256(sample).hexdigest()}
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'files': [item]}), encoding='utf-8')
            command = [sys.executable, str(Path(__file__).with_name('measure_0102_tail.py')),
                       str(root), str(inventory)]
            run = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(run.stdout)['counts']['fits'], 1)
            item['sha256'] = '0' * 64
            inventory.write_text(json.dumps({'files': [item]}), encoding='utf-8')
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('inventory size or hash mismatch', run.stderr)


if __name__ == '__main__':
    unittest.main()
