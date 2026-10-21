from collections import Counter
import struct
import unittest

from measure_level_inner_graph import measure, signed


def payload(rows):
    out = bytearray(struct.pack('<I', len(rows)))
    for fields, values in rows:
        out.extend(struct.pack('<7I', *fields))
        out.extend(b'\0\0' + bytes(24))
        out.extend(struct.pack('<I', len(values)))
        for value in values:
            out.extend(struct.pack('<I', value))
    return bytes(out)


class LevelInnerGraphTests(unittest.TestCase):
    def test_self_duplicate_reciprocity_and_rectangles(self):
        a = [0, 2, 2, 0, 0, 0, 0]
        b = [0, 2, 2, 0, 1, 0, 0]
        result = measure(payload([(a, [0, 1, 1, 3]), (b, [1, 0])]))
        self.assertEqual(result['entries_self_once'], 2)
        self.assertEqual(result['first_dword_duplicate_occurrences'], 1)
        self.assertEqual(result['first_dword_matches_entry_index'], 1)
        self.assertEqual(result['entries_self_first'], 2)
        self.assertEqual(result['repeated_low_occurrences'], 1)
        self.assertEqual(result['low_outside'], 1)
        self.assertEqual(result['reciprocal_occurrences'], 5)
        self.assertEqual(result['strict_rectangle_overlap'], 5)
        self.assertEqual(signed(0xffffffff), -1)
        self.assertEqual(signed(0x100000000), 0)

    def test_span_gaps_and_wrapped_signed_extents(self):
        a = [0, 2, 2, 0, 0, 0, 0]
        b = [0, 2, 2, 0, 1, 0, 0]
        c = [0, 1, 1, 0, 10, 0, 0]
        result = measure(payload([(a, [0, 2, 1]), (b, [1]), (c, [2])]))
        self.assertEqual(result['entries_with_overlap'], 3)
        self.assertEqual(result['entries_overlap_contiguous'], 2)
        self.assertEqual(result['nonoverlap_inside_overlap_span'], 1)
        self.assertEqual(result['overlap_nonreciprocal'], 1)
        wrapped = [0, 2, 2, 0, 0x7fffffff, 0, 0]
        result = measure(payload([(wrapped, [0])]))
        self.assertEqual(result['entries_without_overlap'], 1)
        self.assertEqual(result['strict_rectangle_nonoverlap'], 1)

    def test_cross_file_counts_each_value_once_per_file(self):
        fields = [0, 1, 1, 0, 0, 0, 0]
        shared = Counter()
        measure(payload([(fields, [0]), (fields, [1])]), shared)
        self.assertEqual(shared[0], 1)
        measure(payload([(fields, [0])]), shared)
        self.assertEqual(shared[0], 2)

    def test_truncated_prefix(self):
        data = payload([([0, 1, 1, 0, 0, 0, 0], [0])])
        for i in range(len(data)):
            with self.assertRaises(ValueError):
                measure(data[:i])


if __name__ == '__main__':
    unittest.main()
