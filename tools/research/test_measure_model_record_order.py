import unittest
from measure_model_record_order import measure


class ModelOrderTests(unittest.TestCase):
    def test_sort_can_change_relative_records(self):
        records = [(0x200, 2, 7), (0x206, 1, 7), (0x203, 2, 7),
                   (0x204, 2, 7), (0x208, 2, 7), (0x209, 2, 7)]
        result = measure(records)
        self.assertEqual(result['lookup_pairs'], 1)
        self.assertEqual(result['reordered_lookup_positions'], 1)
        self.assertEqual(result['relative_1_to_4_same_original_indices'], 0)
        self.assertEqual(result['relative_2_and_3_same_original_indices'], 0)
        self.assertEqual(result['fourth_relative_kind_0209'], 1)
        self.assertEqual(result['fourth_relative_kind_other'], 0)

    def test_stable_group_and_truncated_tail(self):
        records = [(9, 3, 0), (0x200, 2, 7), (0x206, 2, 7),
                   (0x203, 2, 7), (0x204, 2, 7), (0x208, 2, 7)]
        result = measure(records)
        self.assertEqual(result['lookup_pairs'], 1)
        self.assertEqual(result['relative_1_to_4_same_original_indices'], 1)
        self.assertEqual(result['fourth_relative_kind_0208'], 1)
        self.assertEqual(measure([(0x200, 1, 0)])['missing_relative_records'], 1)

    def test_other_fourth_kind_is_counted_separately(self):
        records = [(0x200, 2, 7), (0x206, 2, 7), (0x203, 2, 7),
                   (0x204, 2, 7), (0x999, 2, 7)]
        result = measure(records)
        self.assertEqual(result['fourth_relative_kind_other'], 1)
        self.assertEqual(result['fourth_relative_kind_0208'], 0)
        self.assertEqual(result['fourth_relative_kind_0209'], 0)


if __name__ == '__main__':
    unittest.main()
