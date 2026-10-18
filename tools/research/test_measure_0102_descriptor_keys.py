import struct
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from measure_0102_descriptor_keys import measure


def fixture(keys, gates=()):
    payloads = [b'\x01\x00X' + b'\x00\x00' + struct.pack('<I', key << 16) + bytes(4)
                for key in keys]
    table = 12 + sum(map(len, payloads))
    records = []
    offset = 12
    for payload in payloads:
        records.append(struct.pack('<HHHII', 0x0102, 1, 2, offset, len(payload)))
        offset += len(payload)
    for gate in gates:
        payloads.append(gate)
        records.append(struct.pack('<HHHII', 0x0402, 0, 0, offset, len(gate)))
        offset += len(gate)
    table = offset
    return b'SRSC' + struct.pack('<HIH', 0x100, table, len(records)) + b''.join(payloads + records)


class DescriptorKeyTests(unittest.TestCase):
    def test_zero_unique_multiple_and_missing(self):
        result = measure(fixture([0, 1, 2, 3]), [1, 2, 2])
        self.assertEqual(result['records'], 4)
        self.assertEqual(result['zero_keys'], 1)
        self.assertEqual(result['nonzero_unique_matches'], 1)
        self.assertEqual(result['nonzero_multiple_matches'], 1)
        self.assertEqual(result['nonzero_missing'], 1)
        self.assertEqual(result['distinct_missing_keys_per_file'], 1)
        self.assertTrue(result['files_with_missing_keys'])
        self.assertTrue(result['gate_missing'])

    def test_version_gate_and_duplicates(self):
        good = struct.pack('<I', 0x102)
        for payload, counter in [(good, 'gate_equals_0102'),
                                 (bytes(4), 'gate_other'), (bytes(3), 'gate_short')]:
            with self.subTest(counter=counter):
                result = measure(fixture([1], [payload]), [1])
                self.assertEqual(result[counter], 1)
                self.assertEqual(result['gate_tuple_count'], 1)
        self.assertEqual(measure(fixture([1], [good, good]), [1])['gate_duplicate'], 1)

    def test_missing_key_level_membership_is_optional(self):
        data = fixture([3, 3, 4, 1])
        without_level = measure(data, [1])
        self.assertEqual(without_level['distinct_missing_keys_per_file'], 2)
        self.assertEqual(without_level['missing_with_level'], 0)
        with_level = measure(data, [1], [3])
        self.assertEqual(with_level['missing_with_level'], 3)
        self.assertEqual(with_level['missing_in_level'], 2)

    def test_low_half_is_measured_for_zero_and_missing_keys(self):
        data = bytearray(fixture([0, 3, 1]))
        for index in range(3):
            struct.pack_into('<H', data, 12 + 13 * index + 5, 7)
        counts = measure(data, [1])
        self.assertEqual(counts['zero_key_nonzero_low'], 1)
        self.assertEqual(counts['missing_key_nonzero_low'], 1)

    def test_inventory_hash_and_same_path_pairing(self):
        script = Path(__file__).with_name('measure_0102_descriptor_keys.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            odb = fixture([1], [struct.pack('<I', 0x102)])
            db = b'version 1\r\ndependencies 1\r\n1 source\r\n'
            entries = []
            for name, data in [('sample.odb', odb), ('sample.db', db)]:
                (root / name).write_bytes(data)
                entries.append({'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'files': entries}), encoding='utf-8')
            command = [sys.executable, str(script), str(root), str(inventory)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout)['nonzero_unique_matches'], 1)
            entries[1]['sha256'] = '0' * 64
            inventory.write_text(json.dumps({'files': entries}), encoding='utf-8')
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('inventory length or hash mismatch', result.stderr)

    def test_rejects_truncated_table_and_payload(self):
        data = fixture([1])
        with self.assertRaises(ValueError):
            measure(data[:-1], [1])
        bad = bytearray(data)
        struct.pack_into('<H', bad, 12, 100)
        with self.assertRaises(ValueError):
            measure(bad, [1])
        with self.assertRaises(ValueError):
            measure(b'not SRSC', [])


if __name__ == '__main__':
    unittest.main()
