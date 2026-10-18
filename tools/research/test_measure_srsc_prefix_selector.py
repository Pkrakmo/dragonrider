import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_srsc_prefix_selector import measure


def fixture(items):
    payload = bytearray()
    entries = []
    for kind, second, third, body in items:
        entries.append(struct.pack('<HHHII', kind, second, third, 12 + len(payload), len(body)))
        payload.extend(body)
    return (b'SRSC' + struct.pack('<HIH', 0x100, 12 + len(payload), len(entries))
            + payload + b''.join(entries))


class PrefixSelectorTests(unittest.TestCase):
    def test_measures_equal_and_unequal_independently_by_kind(self):
        body = b'\x01\x00X\x34\x12'
        data = fixture([(0x102, 0x1234, 0x1234, body),
                        (0x102, 0, 0x1235, body),
                        (0x302, 0, 0, b'\x00\x00\x00\x00')])
        result = measure(data)
        self.assertEqual(result[0x102]['compared'], 2)
        self.assertEqual(result[0x102]['equals_second'], 1)
        self.assertEqual(result[0x102]['equals_third'], 1)
        self.assertEqual(result[0x102]['differs_third'], 1)
        self.assertEqual(result[0x302]['word_zero'], 1)
        self.assertEqual(result[0x302]['third_zero'], 1)

    def test_incomplete_prefix_and_post_prefix_are_counted(self):
        data = fixture([(0x102, 0, 0, b'\x00'), (0x102, 0, 0, b'\x02\x00X'),
                        (0x102, 0, 0, b'\x01\x00X\x00'),
                        (0x102, 0, 0, b'\x00\x00\x00\x00')])
        result = measure(data)[0x102]
        self.assertEqual(result['records'], 4)
        self.assertEqual(result['short_prefix'], 1)
        self.assertEqual(result['prefix_outside_record'], 1)
        self.assertEqual(result['short_post_prefix'], 1)
        self.assertEqual(result['compared'], 1)

    def test_post_prefix_word_matching_does_not_assume_unique_target(self):
        body = b'\x00\x00\x2a\x00'
        result = measure(fixture([(0x102, 1, 7, body), (0x101, 42, 0, b''),
                                  (0x101, 42, 2, b'')]))[0x102]
        self.assertEqual(result['matches_0101_multiple'], 1)
        result = measure(fixture([(0x102, 1, 7, body), (0x101, 42, 0, b'')]))[0x102]
        self.assertEqual(result['matches_0101_unique'], 1)
        result = measure(fixture([(0x102, 1, 42, body)]))[0x102]
        self.assertEqual(result['matches_0101_none'], 1)

    def test_rejects_bad_header_table_and_selected_range(self):
        data = fixture([(0x102, 0, 0, b'\x00\x00\x00\x00')])
        for bad in (b'invalid', data[:-1]):
            with self.assertRaises(ValueError):
                measure(bad)
        bad = bytearray(data)
        struct.pack_into('<I', bad, 16 + 6, 11)
        with self.assertRaises(ValueError):
            measure(bad)

    def test_cli_validates_manifest_and_hash(self):
        script = Path(__file__).with_name('measure_srsc_prefix_selector.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = fixture([(0x102, 0, 42, b'\x00\x00\x2a\x00')])
            (root / 'sample').write_bytes(data)
            entry = {'path': 'sample', 'status': 'examined', 'file_size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'files': [entry]}), encoding='utf-8')
            command = [sys.executable, str(script), str(root), str(inventory)]
            run = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(run.stdout)['kinds']['0102']['equals_third'], 1)
            entry['sha256'] = '0' * 64
            inventory.write_text(json.dumps({'files': [entry]}), encoding='utf-8')
            run = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('inventory size or hash mismatch', run.stderr)


if __name__ == '__main__':
    unittest.main()
