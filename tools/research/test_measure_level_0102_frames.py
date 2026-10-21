import struct
import unittest

from measure_level_0102_frames import compare, record_frames
from test_measure_0102_array_types import body
from test_measure_srsc_prefix_selector import fixture


class Level0102FramesTests(unittest.TestCase):
    def test_parse_and_compare_exact_and_terminal_nul(self):
        frames = struct.pack('<IH', 5, 3) + b'ab\0' + struct.pack('<IH', 7, 1) + b'x'
        data = fixture([(0x102, 3, 0, body(7, 2, [1, 2]) + frames)])
        source = record_frames(data)[3][0]
        result = compare([1, 0, 5], [(7, b'x'), (5, b'ab'), (0, b'')], source)
        self.assertEqual(result['frames'], 3)
        self.assertEqual(result['body_exact'], 1)
        self.assertEqual(result['body_equal_allow_terminal_nul'], 2)
        self.assertEqual(result['tags_equal'], 2)
        self.assertEqual(result['index_outside_source'], 1)
        with self.assertRaises(ValueError):
            compare([0], [], source)

    def test_invalid_and_duplicate_records(self):
        frame = struct.pack('<IH', 5, 1) + b'a'
        valid = body(7, 1, [0]) + frame
        duplicate = fixture([(0x102, 3, 0, valid), (0x102, 3, 1, valid)])
        self.assertEqual(len(record_frames(duplicate)[3]), 2)
        for bad in (valid[:-1], valid + b'x', body(7, 2, [0]) + frame):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                record_frames(fixture([(0x102, 3, 0, bad)]))


if __name__ == '__main__':
    unittest.main()
