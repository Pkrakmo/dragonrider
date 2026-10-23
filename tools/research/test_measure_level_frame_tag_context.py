import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_level_frame_tag_context import measure
from test_measure_level_entry_caller import fixture


def object_bytes(frames=(), fields=(10, 11, 12, 13, 14, 15, 16), first_word=17,
                 references=(), following=(18, 19, 20), n=None, m=None, tail=b''):
    if n is None:
        n = len(frames)
    if m is None:
        m = len(frames)
    result = bytearray(struct.pack('<7IHH', *fields, first_word, len(references)))
    result.extend(struct.pack(f'<{len(references)}H', *references))
    result.extend(struct.pack('<3Hii', *following, n, m))
    if n > 0 and m > 0:
        result.extend(bytes(4 * n + 2 * m))
        for tag, body in frames:
            result.extend(struct.pack('<IH', tag, len(body)))
            result.extend(body)
    result.extend(tail)
    return bytes(result)


def payload(*objects):
    return struct.pack('<H', len(objects)) + b''.join(objects)


class LevelFrameTagContextTests(unittest.TestCase):
    def test_raw_field_and_count_equalities_are_aggregate_only(self):
        data = payload(object_bytes(
            [(10, b'a'), (17, b'b'), (4, b'c'), (3, b'd')],
            references=(9, 8, 7), n=4, m=4))
        counts = measure(data)
        self.assertEqual(counts['objects'], 1)
        self.assertEqual(counts['frames'], 4)
        self.assertEqual(counts['tag_equals_field_0'], 1)
        self.assertEqual(counts['tag_equals_first_word'], 1)
        self.assertEqual(counts['tag_equals_reference_count'], 1)
        self.assertEqual(counts['tag_equals_first_count'], 1)
        self.assertEqual(counts['tag_equals_second_count'], 1)
        self.assertEqual(counts['tag_equals_frame_count'], 1)
        self.assertEqual(counts['tag_equals_frame_position'], 1)
        self.assertEqual(counts['tags_matching_any_context_value'], 4)
        self.assertEqual(counts['tags_matching_multiple_context_values'], 2)
        self.assertEqual(counts['objects_with_any_tag_context_match'], 1)

    def test_u16_context_is_numeric_without_low_word_coercion(self):
        counts = measure(payload(object_bytes([(0x10000, b'x'), (18, b'y')],
                                               following=(18, 0, 0), n=2, m=2)))
        self.assertEqual(counts['tag_equals_first_word'], 0)
        self.assertEqual(counts['tag_equals_following_0'], 1)
        self.assertEqual(counts['tag_equals_following_1'], 0)
        self.assertEqual(counts['tags_matching_any_context_value'], 1)

    def test_nonpositive_conditional_counts_leave_tail_uninterpreted(self):
        counts = measure(payload(object_bytes(n=-1, m=2, tail=b'opaque')))
        self.assertEqual(counts['objects_without_frames'], 1)
        self.assertEqual(counts['frames'], 0)
        self.assertEqual(counts['trailing_bytes'], len(b'opaque'))

    def test_every_truncation_is_rejected(self):
        data = payload(object_bytes([(10, b'abc')]))
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                measure(data[:length])

    def test_cli_verifies_hash_before_aggregate_output(self):
        script = Path(__file__).with_name('measure_level_frame_tag_context.py')
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
