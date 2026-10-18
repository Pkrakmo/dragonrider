import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from measure_srsc_label_relationships import measure, payload_labels
from measure_srsc_lookup import read_records


class LabelRelationshipsTests(unittest.TestCase):
    def test_fanout_ambiguity_missing_and_duplicate_siblings(self):
        records = [(0x101, 1, 0), (0x101, 2, 0), (0x101, 2, 1),
                   (0x102, 8, 1), (0x102, 9, 1), (0x102, 10, 2),
                   (0x102, 11, 7)]
        labels = {0: b'a', 1: b'a', 2: b'a'}
        got = measure(records, labels, 0x102, 0x101)
        self.assertEqual(got['source_matched_unique'], 2)
        self.assertEqual(got['source_ambiguous'], 1)
        self.assertEqual(got['source_unmatched'], 1)
        self.assertEqual(got['duplicate_text_occurrences'], 2)
        self.assertEqual(got['duplicate_sibling_text_occurrences'], 1)
        self.assertEqual(got['max_label_fanout'], 2)

    def test_hash_and_bounded_payload(self):
        payload = b'\x02\x00A\x00'
        record = struct.pack('<HHHII', 0x101, 1, 0, 12, len(payload))
        contents = b'SRSC' + struct.pack('<HIH', 0x100, 12 + len(payload), 1) + payload + record
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'fixture'
            path.write_bytes(contents)
            entry = {'path': 'fixture', 'sha256': hashlib.sha256(contents).hexdigest()}
            records = read_records(root, entry)
            self.assertEqual(payload_labels(path, records), {0: b'A'})
            entry['sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                read_records(root, entry)
            bad = bytearray(contents)
            bad[12] = 3
            path.write_bytes(bad)
            with self.assertRaises(ValueError):
                payload_labels(path, records)
            bad = bytearray(contents)
            bad[-4:] = struct.pack('<I', 100000)
            path.write_bytes(bad)
            with self.assertRaises(ValueError):
                payload_labels(path, records)

    def test_payload_table_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture'
            payload = b'\x02\x00A\x00'
            record = struct.pack('<HHHII', 0x101, 2, 0, 12, len(payload))
            path.write_bytes(b'SRSC' + struct.pack('<HIH', 0x100, 16, 1) + payload + record)
            with self.assertRaises(ValueError):
                payload_labels(path, [(0x101, 1, 0)])


if __name__ == '__main__':
    unittest.main()
