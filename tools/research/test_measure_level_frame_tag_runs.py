import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_level_frame_tag_runs import measure
from test_measure_level_entry_caller import fixture


def object_bytes(frames=(), n=None, m=None, tail=b''):
    if n is None:
        n = len(frames)
    if m is None:
        m = len(frames)
    result = bytearray(struct.pack('<7IHH', 1, 2, 3, 4, 5, 6, 0, 7, 0))
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


class LevelFrameTagRunTests(unittest.TestCase):
    def test_empty_single_multiple_duplicates_and_adjacent_categories(self):
        data = payload(
            object_bytes(),
            object_bytes([(7, b'a')]),
            object_bytes([(2, b'a'), (2, b'a'), (5, b'b'), (3, b'c')]),
        )
        counts = measure(data)
        self.assertEqual(counts['objects'], 3)
        self.assertEqual(counts['objects_with_empty_frame_sequence'], 1)
        self.assertEqual(counts['objects_with_single_frame_sequence'], 1)
        self.assertEqual(counts['objects_with_multiple_frame_sequence'], 1)
        self.assertEqual(counts['frames'], 5)
        self.assertEqual(counts['objects_with_duplicate_tags'], 1)
        self.assertEqual(counts['duplicate_tag_occurrences_within_object'], 1)
        self.assertEqual(counts['adjacent_tag_equal'], 1)
        self.assertEqual(counts['adjacent_tag_increase'], 1)
        self.assertEqual(counts['adjacent_tag_decrease'], 1)
        self.assertEqual(counts['objects_with_exact_adjacent_tag_body_repeat'], 1)
        self.assertEqual(counts['exact_adjacent_tag_body_repeats'], 1)

    def test_equal_tags_with_different_bodies_are_not_exact_body_repeats(self):
        counts = measure(payload(object_bytes([(4, b'first'), (4, b'second')])))
        self.assertEqual(counts['adjacent_tag_equal'], 1)
        self.assertEqual(counts['objects_with_duplicate_tags'], 1)
        self.assertEqual(counts['exact_adjacent_tag_body_repeats'], 0)

    def test_nonpositive_counts_leave_tail_uninterpreted(self):
        counts = measure(payload(object_bytes(n=0, m=2, tail=b'opaque')))
        self.assertEqual(counts['objects_with_empty_frame_sequence'], 1)
        self.assertEqual(counts['frames'], 0)
        self.assertEqual(counts['trailing_bytes'], len(b'opaque'))

    def test_every_truncation_of_framed_data_is_rejected(self):
        data = payload(object_bytes([(9, b'abc')]))
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                measure(data[:length])

    def test_cli_checks_inventory_hash_before_aggregate_output(self):
        script = Path(__file__).with_name('measure_level_frame_tag_runs.py')
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
