from collections import Counter
import unittest

from measure_0102_level_keys import classify, measure
from test_measure_0102_array_types import body
from test_measure_srsc_prefix_selector import fixture


class LevelKeyMeasurementTests(unittest.TestCase):
    def test_scalar_and_flagged_ranges(self):
        levels = Counter({3: 1, 4: 2})
        # Two scalar units, one valid range and three inactive/invalid ranges.
        flags = [12, 12, 0x100c, 0x100c, 0x100c, 0x100c]
        units = [3, 4, (2 << 16) | 6, 0, (0xffff << 16) | 1,
                 (2 << 16) | 9, 3, 99]
        distinct = set()
        result = classify(units, flags, levels, {3: {0}, 4: {0, 1}}, distinct)
        self.assertEqual(result['scalar_values'], 2)
        self.assertEqual(result['scalar_one_level_match'], 1)
        self.assertEqual(result['scalar_multiple_level_matches'], 1)
        self.assertEqual(result['range_descriptors'], 4)
        self.assertEqual(result['range_in_bounds'], 1)
        self.assertEqual(result['range_values'], 2)
        self.assertEqual(result['range_one_level_match'], 1)
        self.assertEqual(result['range_no_level_match'], 1)
        self.assertEqual(result['range_no_common_level'], 1)
        self.assertEqual(distinct, {3, 99})
        self.assertEqual(result['range_empty'], 1)
        self.assertEqual(result['range_negative'], 1)
        self.assertEqual(result['range_outside'], 1)

    def test_reject_short(self):
        with self.assertRaises(ValueError):
            classify([], [12], Counter())

    def test_record_selection_and_bounds(self):
        data = fixture([(0x102, 0, 0, body(7, 1, [3]))])
        self.assertEqual(measure(data, {7: [[12]]}, Counter({3: 1}))['scalar_one_level_match'], 1)
        for invalid_metadata in ({}, {7: [[12], [12]]}, {7: [[12, 12]]}):
            with self.assertRaises(ValueError):
                measure(data, invalid_metadata, Counter())
        with self.assertRaises(ValueError):
            measure(fixture([(0x102, 0, 0, body(7, 1, [3])[:-1])]), {7: [[12]]}, Counter())


if __name__ == '__main__':
    unittest.main()
