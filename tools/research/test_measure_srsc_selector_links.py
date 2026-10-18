import unittest

from measure_srsc_selector_links import (measure, measure_same_kind,
                                         measure_same_kind_chains, measure_cross_kind_chains)


class SelectorLinkTests(unittest.TestCase):
    def test_missing_unique_and_duplicate_matches(self):
        records = [(0x101, 4, 123), (0x101, 5, 0), (0x101, 5, 999),
                   (0x102, 1, 4), (0x102, 2, 5), (0x102, 3, 6),
                   (0x999, 6, 0)]
        counts = measure(records)['0102_to_0101']
        self.assertEqual(dict(counts), {'records': 3, 'no_matches': 1,
                                        'one_match': 1, 'multiple_matches': 1})

    def test_selected_pairs_and_no_cross_file_matching(self):
        first = measure([(0x200, 8, 3), (0x301, 9, 0), (0x302, 8, 9)])
        second = measure([(0x201, 3, 0)])
        self.assertEqual(first['0200_to_0201']['no_matches'], 1)
        self.assertEqual(second['0200_to_0201']['records'], 0)
        self.assertEqual(first['0302_to_0301']['one_match'], 1)

    def test_same_kind_zero_missing_duplicates_and_self(self):
        records = [(0x101, 1, 0), (0x101, 2, 1), (0x101, 3, 2),
                   (0x101, 3, 9), (0x101, 4, 3), (0x101, 5, 5)]
        self.assertEqual(dict(measure_same_kind(records, 0x101)), {
            'records': 6, 'third_zero': 1, 'nonzero_no_matches': 1,
            'nonzero_one_match': 3, 'nonzero_multiple_matches': 1,
            'nonzero_self_match': 1})

    def test_chain_end_conditions(self):
        records = [(0x101, 1, 0), (0x101, 2, 1), (0x101, 3, 9),
                   (0x101, 4, 5), (0x101, 5, 4), (0x101, 6, 7),
                   (0x101, 7, 0), (0x101, 7, 0)]
        self.assertEqual(dict(measure_same_kind_chains(records, 0x101)), {
            'chains': 8, 'end_zero': 4, 'end_missing': 1,
            'end_ambiguous': 1, 'end_cycle': 2})

    def test_cross_kind_chain_end_conditions(self):
        records = [(0x101, 1, 0), (0x101, 2, 3), (0x101, 3, 2),
                   (0x101, 4, 0), (0x101, 4, 0), (0x102, 1, 1),
                   (0x102, 2, 2), (0x102, 3, 4), (0x102, 4, 5)]
        self.assertEqual(dict(measure_cross_kind_chains(records, 0x102, 0x101)), {
            'chains': 4, 'end_zero': 1, 'end_missing': 1,
            'end_ambiguous': 1, 'end_cycle': 1})


if __name__ == '__main__':
    unittest.main()
