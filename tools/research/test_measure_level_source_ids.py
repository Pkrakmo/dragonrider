import struct
import unittest

from measure_level_source_ids import counter_for, records


class SourceIdsTest(unittest.TestCase):
    def test_counts_occurrences_and_ambiguity(self):
        counts, add = counter_for([(42, 0, 0), (8, 0, 0), (8, 0, 0), (0, 0, 0),
                                   (0x10000, 0, 0)])
        add(0x002a0001, 0x00080002)
        add(0x00090003, 4)
        add(-1, 0x002a0001)
        self.assertEqual(dict(counts), {'unique_explicit': 2, 'duplicate_explicit': 1,
                                        'unmatched': 1, 'zero_high': 1, 'negative': 1})

    def test_selected_record_bounds_and_duplicates(self):
        table = struct.pack('<HHHII', 0, 0, 0, 12, 0) + struct.pack('<HHHII', 1, 0, 0, 12, 0)
        data = b'SRSC' + struct.pack('<HIH', 0x100, 12, 2) + table
        self.assertEqual(records(data)[(1, 0, 0)], (1, b''))
        for bad in (data[:-1], data[:12] + table[:14] * 2,
                    data[:12] + struct.pack('<HHHII', 0, 0, 0, 0xffffffff, 1) + table[14:]):
            with self.assertRaises(ValueError):
                records(bad)


if __name__ == '__main__':
    unittest.main()
