import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_level_frame_tag_recurrence import distance_bucket, measure
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


class LevelFrameTagRecurrenceTests(unittest.TestCase):
    def test_first_repeated_distance_and_body_comparisons(self):
        counts = measure(payload(object_bytes([
            (7, b'aa'),       # first
            (7, b'aa'),       # adjacent, equal body
            (9, b'x'),        # first
            (7, b'bb'),       # distance 2 from previous 7, same length
            (4, b'long'),     # first
            (5, b'q'),        # first
            (6, b'z'),        # first
            (7, b'c'),        # distance 4, different length
        ])))
        self.assertEqual(counts['objects'], 1)
        self.assertEqual(counts['frames'], 8)
        self.assertEqual(counts['first_tag_occurrences'], 5)
        self.assertEqual(counts['repeated_tag_occurrences'], 3)
        self.assertEqual(counts['objects_with_repeated_tags'], 1)
        self.assertEqual(counts['repeat_distance_adjacent'], 1)
        self.assertEqual(counts['repeat_distance_2_3'], 1)
        self.assertEqual(counts['repeat_distance_4_plus'], 1)
        self.assertEqual(counts['repeated_tag_same_body_length'], 2)
        self.assertEqual(counts['repeated_tag_different_body_length'], 1)
        self.assertEqual(counts['repeated_tag_exact_body_equal'], 1)
        self.assertEqual(counts['repeated_tag_exact_body_different'], 2)

    def test_same_length_different_content_is_not_exact_equality(self):
        counts = measure(payload(object_bytes([(2, b'ab'), (2, b'cd')])))
        self.assertEqual(counts['repeated_tag_same_body_length'], 1)
        self.assertEqual(counts['repeated_tag_different_body_length'], 0)
        self.assertEqual(counts['repeated_tag_exact_body_equal'], 0)
        self.assertEqual(counts['repeated_tag_exact_body_different'], 1)

    def test_nonpositive_counts_leave_tail_uninterpreted(self):
        counts = measure(payload(object_bytes(n=0, m=2, tail=b'opaque')))
        self.assertEqual(counts['frames'], 0)
        self.assertEqual(counts['first_tag_occurrences'], 0)
        self.assertEqual(counts['trailing_bytes'], len(b'opaque'))

    def test_every_truncation_of_framed_data_is_rejected(self):
        data = payload(object_bytes([(9, b'abc'), (9, b'd')]))
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                measure(data[:length])

    def test_distance_buckets_cover_positive_distances(self):
        self.assertEqual(distance_bucket(1), 'repeat_distance_adjacent')
        self.assertEqual(distance_bucket(2), 'repeat_distance_2_3')
        self.assertEqual(distance_bucket(3), 'repeat_distance_2_3')
        self.assertEqual(distance_bucket(4), 'repeat_distance_4_plus')

    def test_cli_refuses_stale_inventory_hash_before_output(self):
        script = Path(__file__).with_name('measure_level_frame_tag_recurrence.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = fixture(payload(object_bytes([(1, b'x'), (1, b'x')])))
            sample = root / 'sample.lvl'
            sample.write_bytes(data)
            entry = {'path': sample.name, 'status': 'examined', 'file_size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'files': [entry]}), encoding='utf-8')
            command = [sys.executable, str(script), str(root), str(inventory)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout)['counts']['repeated_tag_occurrences'], 1)
            entry['sha256'] = '0' * 64
            inventory.write_text(json.dumps({'files': [entry]}), encoding='utf-8')
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('inventory size or hash mismatch', result.stderr)


if __name__ == '__main__':
    unittest.main()
