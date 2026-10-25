import unittest
import hashlib
from pathlib import Path
import struct
import tempfile
from unittest.mock import patch
from measure_srsc_lookup import measure, read_records, read_snapshot


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
            entry = {'path': 'sample', 'sha256': hashlib.sha256(data).hexdigest(),
                     'file_size': len(data)}
            self.assertEqual(read_records(root, entry), [(1, 2, 3)])
            self.assertEqual(read_snapshot(root, entry), (data, [(1, 2, 3)]))
            entry['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                read_records(root, entry)
            truncated = data[:-1]
            (root / 'sample').write_bytes(truncated)
            bad_table = {
                'path': 'sample', 'sha256': hashlib.sha256(truncated).hexdigest(),
                'file_size': len(truncated),
            }
            with self.assertRaisesRegex(ValueError, 'invalid bounded table'):
                read_records(root, bad_table)

    def test_verified_snapshot_rejects_bad_metadata_and_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            data = b'SRSC' + struct.pack('<HIH', 0x100, 12, 1) + struct.pack('<HHHII', 1, 2, 3, 12, 0)
            sample = root / 'sample'
            sample.write_bytes(data)
            entry = {'path': sample.name, 'sha256': hashlib.sha256(data).hexdigest(),
                     'file_size': len(data)}
            self.assertEqual(read_records(root, entry), [(1, 2, 3)])
            with self.assertRaisesRegex(ValueError, 'size mismatch'):
                read_records(root, dict(entry, file_size=len(data) + 1))
            with self.assertRaisesRegex(ValueError, 'invalid inventory hash'):
                read_records(root, dict(entry, sha256='bad'))
            self.assertEqual(read_records(
                root, {key: value for key, value in entry.items() if key != 'file_size'}),
                [(1, 2, 3)])
            with self.assertRaisesRegex(ValueError, 'invalid inventory path'):
                read_records(root, dict(entry, path='../sample'))
            linked = root / 'linked'
            linked.symlink_to(Path(outside) / 'outside')
            with self.assertRaisesRegex(ValueError, 'symlink in inventory path'):
                read_records(root, dict(entry, path=linked.name))

    def test_rejects_large_file_size_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / 'large'
            with sample.open('wb') as output:
                output.truncate(257 * 1024 * 1024)
            entry = {'path': sample.name, 'sha256': '0' * 64,
                     'file_size': sample.stat().st_size}
            for selected in (entry, {key: value for key, value in entry.items()
                                     if key != 'file_size'}):
                with self.subTest(has_size='file_size' in selected), \
                        patch.object(Path, 'open') as open_file:
                    with self.assertRaisesRegex(ValueError, 'exceeds snapshot limit'):
                        read_snapshot(root, selected)
                    open_file.assert_not_called()


if __name__ == '__main__':
    unittest.main()
