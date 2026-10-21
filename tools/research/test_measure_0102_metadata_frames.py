import struct
import unittest

from measure_0102_metadata_frames import compare_tail, measure
from test_measure_0102_array_types import body
from test_measure_srsc_prefix_selector import fixture


class MetadataFrameTests(unittest.TestCase):
    def test_exact_and_trailing_frames(self):
        frame = struct.pack('<IH', 7, 4) + b'abc\0'
        flags = [7]
        names = [{'0_descriptor': b'abc'}]
        result = compare_tail(frame, flags, names)
        self.assertEqual(result['exact_tails'], 1)
        self.assertEqual(result['flags_equal'], 1)
        self.assertEqual(result['names_equal'], 1)
        self.assertEqual(compare_tail(frame + b'x', flags, names)['trailing_bytes'], 1)
        self.assertEqual(compare_tail(frame, [8], names)['flags_equal'], 0)
        self.assertEqual(compare_tail(frame, flags, [{}])['names_equal'], 0)

    def test_truncated_and_zero_count(self):
        names = [{'0_descriptor': b'x'}]
        self.assertEqual(compare_tail(b'', [1], names)['too_short_for_frame_headers'], 1)
        self.assertEqual(compare_tail(struct.pack('<IH', 1, 2) + b'x', [1], names)['truncated_frame_body'], 1)
        self.assertEqual(compare_tail(b'', [], [])['exact_tails'], 1)
        with self.assertRaises(ValueError):
            compare_tail(b'', [1], [])

    def test_variant_tracking_discards_partial_frames(self):
        values = {}
        names = [{'0_descriptor': b'x'}]
        compare_tail(struct.pack('<IH', 1, 2) + b'x', [1], names, values, 7)
        self.assertEqual(values, {})
        compare_tail(struct.pack('<IH', 1, 1) + b'x', [1], names, values, 7)
        compare_tail(struct.pack('<IH', 1, 2) + b'x\0', [1], names, values, 7)
        self.assertEqual(values[(7, 0)], {b'x', b'x\0'})

    def test_even_writer_rule(self):
        names = [{'0_descriptor': b'x'}, {'0_descriptor': b'xy'}]
        frames = struct.pack('<IH', 1, 2) + b'x\0' + struct.pack('<IH', 2, 2) + b'xy'
        result = compare_tail(frames, [1, 2], names)
        self.assertEqual(result['body_matches_even_writer_rule'], 2)
        self.assertEqual(result['body_even_length'], 2)
        odd = compare_tail(struct.pack('<IH', 1, 1) + b'x', [1], names[:1])
        self.assertEqual(odd['body_matches_even_writer_rule'], 0)

    def test_record_selection_and_bounds(self):
        frame = struct.pack('<IH', 5, 1) + b'a'
        payload = body(7, 1, [10]) + frame
        data = fixture([(0x102, 0, 0, payload)])
        result = measure(data, {7: [[5]]}, {7: [[{'0_descriptor': b'a'}]]})
        self.assertEqual(result['names_equal'], 1)
        with self.assertRaises(ValueError):
            measure(data, {}, {})
        with self.assertRaises(ValueError):
            measure(fixture([(0x102, 0, 0, payload[:12])]), {}, {})


if __name__ == '__main__':
    unittest.main()
