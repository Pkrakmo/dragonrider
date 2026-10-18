import unittest

from measure_srsc_link_exceptions import measure_files


class LinkExceptionTests(unittest.TestCase):
    def test_missing_hops_and_cross_file_or_kind_matches(self):
        files = [
            [(0x201, 1, 0), (0x201, 2, 99), (0x201, 3, 2),
             (0x200, 8, 3), (0x200, 9, 2), (0x555, 99, 0)],
            [(0x201, 99, 0), (0x200, 1, 2)],
        ]
        result = measure_files(files)
        self.assertEqual(dict(result['totals']), {
            'files': 2, 'files_with_direct_missing': 1,
            'direct_missing_records': 1, 'distinct_file_missing_keys': 1,
            'missing_keys_matching_other_kind_in_same_file': 1,
            'missing_keys_matching_0201_in_another_file': 1,
            'affected_0201_chains': 2, 'affected_0200_chains': 3,
            'ambiguous_chains': 0, 'cyclic_chains': 0})
        self.assertEqual(dict(result['missing_chain_matched_hops']['0201']), {'0': 1, '1': 1})
        self.assertEqual(dict(result['missing_chain_matched_hops']['0200']), {'0': 1, '1': 1, '2': 1})

    def test_duplicate_missing_key_and_unresolved_branches(self):
        records = [(0x201, 1, 50), (0x201, 2, 50),
                   (0x201, 3, 4), (0x201, 4, 3),
                   (0x201, 5, 0), (0x201, 5, 0), (0x200, 1, 5),
                   (0x200, 2, 0)]
        result = measure_files([records])
        totals = result['totals']
        self.assertEqual(totals['direct_missing_records'], 2)
        self.assertEqual(totals['distinct_file_missing_keys'], 1)
        self.assertEqual(totals['cyclic_chains'], 2)
        self.assertEqual(totals['ambiguous_chains'], 1)
        self.assertEqual(totals['affected_0200_chains'], 0)
        self.assertEqual(totals['missing_keys_matching_0201_in_another_file'], 0)

    def test_empty_and_files_do_not_share_local_targets(self):
        result = measure_files([[(0x201, 1, 2)], [(0x201, 2, 0)], []])
        self.assertEqual(result['totals']['files'], 3)
        self.assertEqual(result['totals']['direct_missing_records'], 1)
        self.assertEqual(result['totals']['affected_0201_chains'], 1)
        self.assertEqual(result['totals']['missing_keys_matching_0201_in_another_file'], 1)


if __name__ == '__main__':
    unittest.main()
