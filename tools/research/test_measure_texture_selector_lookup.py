import unittest
from measure_texture_selector_lookup import measure


class TextureSelectorLookupTests(unittest.TestCase):
    def test_pair_and_zero_third_can_diverge(self):
        records = [(0x40, 7, 3), (0x40, 7, 0), (0x40, 8, 3), (0x20, 7, 0)]
        result = measure(records)
        self.assertEqual(result['texture_records'], 3)
        self.assertEqual(result['texture_nonzero_third'], 2)
        self.assertEqual(result['lookup_pairs'], 2)
        self.assertEqual(result['duplicate_pair_occurrences'], 1)
        self.assertEqual(result['first_lookup_disagreements'], 1)
        self.assertEqual(result['zero_third_not_found'], 1)

    def test_empty_and_first_match(self):
        self.assertEqual(measure([])['lookup_pairs'], 0)
        result = measure([(0x40, 9, 0), (0x40, 9, 1)])
        self.assertEqual(result['first_lookup_disagreements'], 0)
        self.assertEqual(result['zero_third_not_found'], 0)


if __name__ == '__main__':
    unittest.main()
