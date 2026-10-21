import struct
import unittest

from measure_level_0102_arrays import compare, positive_range, record_arrays
from test_measure_0102_array_types import body
from test_measure_srsc_prefix_selector import fixture


class Level0102ArrayTests(unittest.TestCase):
    def test_candidate_lookup_and_halves(self):
        counts = compare([1, 0, 3], [0x12340001, 0x77770002, 0],
                         (3, [0x88880002, 0x12340001, 9]),
                         [(0x1000, b''), (0, b''), (0, b'')])
        self.assertEqual(counts['units_compared'], 2)
        self.assertEqual(counts['exact_units'], 1)
        self.assertEqual(counts['equal_low_halves'], 2)
        self.assertEqual(counts['equal_high_halves'], 1)
        self.assertEqual(counts['word_outside_candidate_base'], 1)
        self.assertEqual(counts['objects_all_base_units_equal'], 0)
        self.assertEqual(counts['flagged_exact_units'], 1)
        self.assertEqual(counts['unflagged_exact_units'], 0)
        self.assertEqual(counts['exact_nonzero'], 1)

    def test_short_level_array_and_candidate(self):
        counts = compare([0, 1], [4], (3, [4]), [(0, b''), (0, b'')])
        self.assertEqual(counts['word_without_level_unit'], 1)
        self.assertEqual(counts['source_declared_exceeds_array'], 1)
        self.assertEqual(counts['objects_all_base_units_equal'], 0)
        with self.assertRaises(ValueError):
            compare([0], [4], (1, [4]), [])

    def test_ranges_are_independently_bounded(self):
        units = [0, 5, 6]
        self.assertEqual(positive_range(0x00020001, units), [5, 6])
        for value in (0, 1, 0x10000, 0x80000001, 0x00030001, 0x00010003):
            self.assertIsNone(positive_range(value, units))
        counts = compare([0], [0x00010001, 7],
                         (1, [0x00010002, 8, 7]), [(0x1000, b'')])
        self.assertEqual(counts['flagged_both_ranges_bounded'], 1)
        self.assertEqual(counts['flagged_ranges_same_length'], 1)
        self.assertEqual(counts['flagged_ranges_exact'], 1)
        self.assertEqual(counts['flagged_exact_units'], 0)

    def test_records_duplicates_and_bounds(self):
        payload = body(7, 2, [0x1234, 0x5678])
        data = fixture([(0x102, 3, 0, payload), (0x102, 3, 1, payload)])
        self.assertEqual(record_arrays(data)[3], [(2, (0x1234, 0x5678))] * 2)
        for bad in (b'', b'\x05\x00', payload[:-1]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                record_arrays(fixture([(0x102, 3, 0, bad)]))
        broken = bytearray(payload)
        struct.pack_into('<I', broken, len(broken) - 12, 99)
        with self.assertRaises(ValueError):
            record_arrays(fixture([(0x102, 3, 0, broken)]))


if __name__ == '__main__':
    unittest.main()
