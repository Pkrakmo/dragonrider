import unittest
import hashlib
from pathlib import Path
import struct
import tempfile
from measure_srsc_lookup import measure, read_records


class LookupMeasurements(unittest.TestCase):
    def test_stable_sort_preserves_first_duplicate_and_pair_ambiguity(self):
        records = [(1, 4, 9), (2, 1, 0), (1, 4, 7), (1, 4, 9)]
        result = measure(records)
        self.assertEqual(result['duplicate_pair_occurrences'], 2)
        self.assertEqual(result['duplicate_triple_occurrences'], 1)
        self.assertEqual(result['pairs_with_multiple_third_words'], 1)
        self.assertEqual(result['pair_first_changes_after_stable_sort'], 0)
        self.assertEqual(result['triple_first_changes_after_stable_sort'], 0)
        self.assertEqual(result['records_reordered'], 2)
        self.assertEqual(result['adjacent_second_word_decreases'], 1)

    def test_empty_and_unique(self):
        self.assertEqual(measure([])['records'], 0)
        result = measure([(1, 0, 2), (1, 1, 2)])
        self.assertEqual(result['duplicate_pair_occurrences'], 0)
        self.assertEqual(result['records_reordered'], 0)

    def test_inventory_hash_and_table_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b'SRSC' + struct.pack('<HIH', 0x100, 12, 1) + struct.pack('<HHHII', 1, 2, 3, 12, 0)
            (root / 'sample').write_bytes(data)
            entry = {'path': 'sample', 'sha256': hashlib.sha256(data).hexdigest()}
            self.assertEqual(read_records(root, entry), [(1, 2, 3)])
            entry['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                read_records(root, entry)
            (root / 'sample').write_bytes(data[:-1])
            with self.assertRaisesRegex(ValueError, 'invalid bounded table'):
                read_records(root, entry)


if __name__ == '__main__':
    unittest.main()
