from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_0102_resource_table import measure, resource_entries
from test_measure_srsc_prefix_selector import fixture


def resource(items):
    data = bytearray(struct.pack('<I', len(items)))
    for key, value in items:
        entry = bytearray(32)
        struct.pack_into('<I', entry, 0, key)
        struct.pack_into('<I', entry, 20, value)
        data.extend(entry)
    return bytes(data)


def body(key, value):
    return b'\x01\x00X' + b'\x00' * 6 + struct.pack('<H', key) + b'\x00\x00' + struct.pack('<I', value)


class ResourceTableTests(unittest.TestCase):
    def test_comparison_preserves_first_match_and_distinguishes_missing(self):
        entries, count = resource_entries(resource([(3, 8), (3, 9), (4, 10)]))
        self.assertEqual(count, 3)
        self.assertEqual(entries[3], [8, 9])
        data = fixture([(0x102, 0, 0, body(3, 8)), (0x102, 0, 0, body(4, 11)),
                        (0x102, 0, 0, body(5, 0)), (0x101, 0, 0, b'')])
        result = measure(data, entries)
        self.assertEqual(result['records'], 3)
        self.assertEqual(result['multiple_key'], 1)
        self.assertEqual(result['unique_key'], 1)
        self.assertEqual(result['missing_key'], 1)
        self.assertEqual(result['first_match_equal'], 1)
        self.assertEqual(result['first_match_different'], 1)

    def test_truncation_and_outside_ranges(self):
        for data in (b'', b'\x01\x00\x00\x00', resource([(3, 8)])[:-1]):
            with self.assertRaises(ValueError):
                resource_entries(data)
        result = measure(fixture([(0x102, 0, 0, b'\x00'),
                                  (0x102, 0, 0, b'\x02\x00X'),
                                  (0x102, 0, 0, body(3, 8)[:-1])]), {})
        self.assertEqual(result['short_prefix'], 1)
        self.assertEqual(result['short_fields'], 2)
        sample = bytearray(fixture([(0x102, 0, 0, body(3, 8))]))
        table = struct.unpack_from('<I', sample, 6)[0]
        struct.pack_into('<I', sample, table + 6, 11)
        with self.assertRaises(ValueError):
            measure(sample, {})
        with self.assertRaises(ValueError):
            measure(sample[:-1], {})

    def test_cli_rejects_unpinned_module_before_reading_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / 'different.rfl'
            module.write_bytes(b'synthetic')
            result = subprocess.run([sys.executable,
                str(Path(__file__).with_name('measure_0102_resource_table.py')),
                str(root), str(root / 'missing.json'), str(module)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('RFL SHA-256 does not match', result.stderr)
            self.assertNotIn('missing.json', result.stderr)


if __name__ == '__main__':
    unittest.main()
