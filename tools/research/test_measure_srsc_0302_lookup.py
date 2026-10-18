import unittest

from measure_srsc_0302_lookup import measure


class LookupComparisonTests(unittest.TestCase):
    def test_zero_search_can_miss_or_choose_a_later_duplicate(self):
        result = measure([(0x302, 3, 8), (0x302, 3, 0),
                          (0x302, 4, 9), (0x302, 5, 0), (0x40, 4, 0)])
        self.assertEqual(result['records'], 4)
        self.assertEqual(result['nonzero_third'], 2)
        self.assertEqual(result['pairs'], 3)
        self.assertEqual(result['duplicate_pair_occurrences'], 1)
        self.assertEqual(result['first_match_differs'], 1)
        self.assertEqual(result['zero_third_not_found'], 1)

    def test_empty_and_stable_order(self):
        self.assertEqual(measure([])['pairs'], 0)
        result = measure([(0x302, 9, 0), (0x302, 1, 0), (0x302, 9, 2)])
        self.assertEqual(result['first_match_differs'], 0)
        self.assertEqual(result['zero_third_not_found'], 0)


if __name__ == '__main__':
    unittest.main()
