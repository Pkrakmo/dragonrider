import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from measure_srsc_cross_kind_distance import (
    add_file_categories, load_entries, measure, read_verified_records,
)


RECORD = struct.Struct("<HHHII")


def srsc(records, *, table_offset=None):
    """Build a complete synthetic SRSC table with a bounded pre-table region."""
    if table_offset is None:
        table_offset = 16
    table = b"".join(RECORD.pack(*record) for record in records)
    return b"SRSC" + struct.pack("<HIH", 0x0100, table_offset, len(records)) + (
        b"P" * (table_offset - 12)) + table


class CrossKindDistanceTests(unittest.TestCase):
    def test_direction_and_distance_buckets(self):
        records = [
            (0x0101, 10, 0, 12, 0),  # distance 1, target before
            (0x0102, 1, 10, 12, 0),
            (0x0102, 2, 20, 12, 0),  # distance 2, source before
            (0x9999, 0, 0, 12, 0),
            (0x0101, 20, 0, 12, 0),
            (0x0101, 30, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x9999, 0, 0, 12, 0),
            (0x0102, 3, 30, 12, 0),  # distance 14, target before
            (0x0102, 4, 40, 12, 0),  # distance 18, source before
        ] + [(0x9999, 0, 0, 12, 0)] * 17 + [
            (0x0101, 40, 0, 12, 0),
        ]
        counts = measure(records)["0102_to_0101"]
        self.assertEqual(dict(counts), {
            "source_records": 4, "unique_relations": 4,
            "missing_targets": 0, "ambiguous_targets": 0,
            "target_before_source": 2, "source_before_target": 2,
            "distance_zero": 0, "distance_1": 1, "distance_2_to_4": 1,
            "distance_5_to_16": 1, "distance_17_plus": 1,
        })

    def test_missing_duplicate_and_per_file_categories(self):
        records = [
            (0x0101, 7, 0, 12, 0), (0x0101, 7, 0, 12, 0),
            (0x0102, 1, 7, 12, 0), (0x0102, 2, 9, 12, 0),
        ]
        counts = measure(records)["0102_to_0101"]
        self.assertEqual(counts["ambiguous_targets"], 1)
        self.assertEqual(counts["missing_targets"], 1)
        self.assertEqual(counts["distance_zero"], 0)
        from collections import Counter
        totals = {"0102_to_0101": Counter(), "0200_to_0201": Counter(),
                  "0302_to_0301": Counter()}
        add_file_categories(records, totals)
        add_file_categories([(0x0101, 1, 0, 12, 0),
                             (0x0102, 2, 1, 12, 0)], totals)
        self.assertEqual(dict(totals["0102_to_0101"]), {
            "files_with_sources": 2, "files_complete": 1,
            "files_with_missing_targets": 1,
            "files_with_ambiguous_targets": 1,
        })

    def test_hash_header_table_and_every_payload_range_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = srsc([(0x0101, 1, 0, 12, 4)])
            path = root / "sample"
            path.write_bytes(contents)
            entry = {"path": "sample", "status": "examined",
                     "sha256": hashlib.sha256(contents).hexdigest()}
            self.assertEqual(read_verified_records(root, entry),
                             [(0x0101, 1, 0, 12, 4)])
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                read_verified_records(root, dict(entry, sha256="0" * 64))
            malformed = srsc([(0x0101, 1, 0, 12, 5)])
            path.write_bytes(malformed)
            bad = dict(entry, sha256=hashlib.sha256(malformed).hexdigest())
            with self.assertRaisesRegex(ValueError, "pre-table"):
                read_verified_records(root, bad)
            truncated = b"SRSC" + struct.pack("<HIH", 0x0100, 16, 1)
            path.write_bytes(truncated)
            bad = dict(entry, sha256=hashlib.sha256(truncated).hexdigest())
            with self.assertRaisesRegex(ValueError, "table"):
                read_verified_records(root, bad)

    def test_rejects_escaping_symlink_and_malformed_inventory(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            data = srsc([(0x0101, 1, 0, 12, 0)])
            (root / "sample").write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            with self.assertRaisesRegex(ValueError, "path"):
                read_verified_records(root, {"path": "../sample", "status": "examined",
                                             "sha256": digest})
            target = Path(outside) / "outside"
            target.write_bytes(data)
            (root / "linked").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlink"):
                read_verified_records(root, {"path": "linked", "status": "examined",
                                             "sha256": digest})
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps({"files": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty"):
                load_entries(inventory)
            inventory.write_text("nope", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid inventory"):
                load_entries(inventory)
            inventory.write_text(json.dumps({"not_files": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid inventory"):
                load_entries(inventory)

    def test_rejects_non_hex_inventory_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = srsc([(0x0101, 1, 0, 12, 0)])
            (root / "sample").write_bytes(data)
            with self.assertRaisesRegex(ValueError, "hash"):
                read_verified_records(root, {
                    "path": "sample", "status": "examined", "sha256": "g" * 64,
                })


if __name__ == "__main__":
    unittest.main()
