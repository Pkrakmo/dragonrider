#!/usr/bin/env python3
"""Synthetic tests for SRSC research measurements."""
import struct
import tempfile
import unittest
from pathlib import Path

from analyze_srsc_records import inspect


class RecordMeasurementsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.path = self.root / 'fixture.bin'

    def write(self, header, payload=b'', table=b'', trailing=b''):
        self.path.write_bytes(header + payload + table + trailing)
        return inspect(self.path, self.root)

    def test_contiguous_ranges_and_duplicate_pair(self):
        table = struct.pack('<HIII', 9, 42, 12, 2) + struct.pack('<HIII', 9, 42, 14, 3)
        result = self.write(struct.pack('<4sHIH', b'SRSC', 0x100, 17, 2), b'abcde', table)
        self.assertEqual(result['ranges_within_payload'], 2)
        self.assertEqual(result['adjacent_pairs'], 1)
        self.assertTrue(result['first_range_starts_at_12'])
        self.assertTrue(result['last_range_ends_at_table'])
        self.assertEqual(result['duplicate_keys'], 1)
        self.assertTrue(result['table_ends_at_eof'])

    def test_bad_range_gap_and_trailing_bytes_are_measured(self):
        table = struct.pack('<HIII', 1, 2, 11, 1) + struct.pack('<HIII', 1, 3, 14, 1)
        result = self.write(struct.pack('<4sHIH', b'SRSC', 0x100, 15, 2), b'abc', table, b'x')
        self.assertEqual(result['ranges_within_payload'], 1)
        self.assertEqual(result['adjacent_pairs'], 0)
        self.assertFalse(result['first_range_starts_at_12'])
        self.assertTrue(result['last_range_ends_at_table'])
        self.assertFalse(result['table_ends_at_eof'])

    def test_invalid_candidate_table_is_skipped(self):
        result = self.write(struct.pack('<4sHIH', b'SRSC', 0x100, 12, 1))
        self.assertEqual(result['status'], 'skipped_invalid_header')
        self.assertIsNone(self.write(b'not SRSC'))


if __name__ == '__main__':
    unittest.main()
