import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_level_frame_variants import body_category, length_bucket, measure
from test_measure_level_entry_caller import fixture


def object_bytes(frames=(), n=1, m=None, flags=0, tail=b''):
    if m is None:
        m = len(frames)
    result = bytearray(struct.pack('<7IHH', 1, 2, 3, 4, 5, 6, flags, 7, 0))
    result.extend(struct.pack('<3Hii', 8, 9, 10, n, m))
    if n > 0 and m > 0:
        result.extend(bytes(4 * n + 2 * m))
        for tag, body in frames:
            result.extend(struct.pack('<IH', tag, len(body)))
            result.extend(body)
    result.extend(tail)
    return bytes(result)


def payload(*objects):
    return struct.pack('<H', len(objects)) + b''.join(objects)


class LevelFrameVariantTests(unittest.TestCase):
    def test_categories_reuse_and_tag_pairing(self):
        data = payload(
            object_bytes([(0x1000, b'Hi\0'), (0x1000, b'Hi\0'), (2, b'\0A')]),
            object_bytes([(0, b'')]),
        )
        counts = measure(data)
        self.assertEqual(counts['objects'], 2)
        self.assertEqual(counts['objects_with_frames'], 2)
        self.assertEqual(counts['frames'], 4)
        self.assertEqual(counts['body_printable_terminal_nul'], 2)
        self.assertEqual(counts['body_printable_other_nul'], 1)
        self.assertEqual(counts['body_empty'], 1)
        self.assertEqual(counts['tag_bit_1000_set'], 2)
        self.assertEqual(counts['tag_bits_outside_low_12_set'], 2)
        self.assertEqual(counts['objects_with_duplicate_exact_frames'], 1)
        self.assertEqual(counts['repeated_body_occurrences'], 1)
        self.assertEqual(counts['repeated_tag_body_pair_occurrences'], 1)

    def test_byte_and_length_categories_are_not_text_decoders(self):
        self.assertEqual(body_category(b''), 'empty')
        self.assertEqual(body_category(b'abc'), 'printable_no_nul')
        self.assertEqual(body_category(b'abc\0'), 'printable_terminal_nul')
        self.assertEqual(body_category(b'a\0b'), 'printable_other_nul')
        self.assertEqual(body_category(b'\x1f'), 'other_bytes')
        self.assertEqual(length_bucket(0), 'length_0')
        self.assertEqual(length_bucket(1), 'length_1')
        self.assertEqual(length_bucket(7), 'length_2_7')
        self.assertEqual(length_bucket(31), 'length_8_31')
        self.assertEqual(length_bucket(127), 'length_32_127')
        self.assertEqual(length_bucket(128), 'length_128_plus')

    def test_nonpositive_counts_do_not_claim_frames_and_trailing_is_counted(self):
        counts = measure(payload(object_bytes(n=-1, m=2, tail=b'opaque')))
        self.assertEqual(counts['objects_without_frames'], 1)
        self.assertEqual(counts['frames'], 0)
        self.assertEqual(counts['trailing_bytes'], len(b'opaque'))

    def test_every_truncation_of_a_frame_is_rejected(self):
        data = payload(object_bytes([(9, b'abc')]))
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                measure(data[:length])

    def test_cli_checks_level_hash_before_aggregate_output(self):
        script = Path(__file__).with_name('measure_level_frame_variants.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = fixture(payload(object_bytes([(1, b'x')])))
            sample = root / 'sample.lvl'
            sample.write_bytes(data)
            entry = {'path': sample.name, 'status': 'examined', 'file_size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'files': [entry]}), encoding='utf-8')
            command = [sys.executable, str(script), str(root), str(inventory)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout)['counts']['frames'], 1)
            entry['sha256'] = '0' * 64
            inventory.write_text(json.dumps({'files': [entry]}), encoding='utf-8')
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('inventory size or hash mismatch', result.stderr)


if __name__ == '__main__':
    unittest.main()
