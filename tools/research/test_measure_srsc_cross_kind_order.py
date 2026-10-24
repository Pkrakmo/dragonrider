import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from measure_srsc_cross_kind_order import (
    aggregate_file_completeness,
    load_inventory,
    measure,
    read_records,
)


def srsc(records, *, table_offset=12, payloads=None):
    """Build a small bounded SRSC file with a table at the requested offset."""
    payloads = payloads or [(12, 0)] * len(records)
    table = b"".join(
        struct.pack("<HHHII", first, second, third, offset, length)
        for (first, second, third), (offset, length) in zip(records, payloads)
    )
    return b"SRSC" + struct.pack("<HIH", 0x0100, table_offset, len(records)) + (
        b"\0" * (table_offset - 12)) + table


class CrossKindOrderTests(unittest.TestCase):
    def test_unique_order_missing_and_duplicate_categories(self):
        records = [
            (0x0101, 10, 0),  # unique target before source
            (0x0102, 20, 10),
            (0x0102, 21, 30),  # target after source
            (0x0101, 30, 0),
            (0x0102, 22, 99),  # missing
            (0x0101, 40, 0),
            (0x0101, 40, 0),
            (0x0102, 23, 40),  # duplicate
        ]
        counts = measure(records)["0102_to_0101"]
        self.assertEqual(dict(counts), {
            "source_records": 4,
            "unique_relations": 2,
            "missing_targets": 1,
            "duplicate_targets": 1,
            "target_before_source": 1,
            "source_before_target": 1,
            "same_position": 0,
        })

    def test_per_file_completeness_counts_only_files_with_sources(self):
        totals = {label: {} for label in ("0102_to_0101", "0200_to_0201", "0302_to_0301")}
        # Counter.update is required by the production helper; start exact type.
        from collections import Counter
        totals = {label: Counter() for label in totals}
        aggregate_file_completeness([(0x0101, 4, 0), (0x0102, 1, 4)], totals)
        aggregate_file_completeness([(0x0102, 1, 9)], totals)
        aggregate_file_completeness([(0x0101, 4, 0)], totals)
        self.assertEqual(dict(totals["0102_to_0101"]), {
            "files_with_sources": 2,
            "files_all_sources_unique": 1,
            "files_with_missing_targets": 1,
            "files_with_duplicate_targets": 0,
        })

    def test_read_records_validates_hash_table_and_payload_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = srsc([(0x0101, 1, 0)], payloads=[(12, 0)])
            (root / "sample.srsc").write_bytes(data)
            entry = {
                "path": "sample.srsc", "status": "examined",
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            self.assertEqual(read_records(root, entry), [(0x0101, 1, 0)])

            bad_hash = dict(entry, sha256="0" * 64)
            with self.assertRaisesRegex(ValueError, "hash"):
                read_records(root, bad_hash)

            truncated = b"SRSC" + struct.pack("<HIH", 0x0100, 12, 1)
            (root / "truncated.srsc").write_bytes(truncated)
            bad_table = dict(entry, path="truncated.srsc",
                             sha256=hashlib.sha256(truncated).hexdigest())
            with self.assertRaisesRegex(ValueError, "table"):
                read_records(root, bad_table)

            range_data = srsc([(0x0101, 1, 0)], payloads=[(12, 1)])
            (root / "range.srsc").write_bytes(range_data)
            bad_range = dict(entry, path="range.srsc",
                             sha256=hashlib.sha256(range_data).hexdigest())
            with self.assertRaisesRegex(ValueError, "pre-table"):
                read_records(root, bad_range)

    def test_rejects_parent_path_and_malformed_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = srsc([(0x0101, 1, 0)])
            (root / "sample.srsc").write_bytes(data)
            entry = {
                "path": "../sample.srsc", "status": "examined",
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            with self.assertRaisesRegex(ValueError, "path"):
                read_records(root, entry)
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps({"not_files": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inventory"):
                load_inventory(inventory)
            inventory.write_text(json.dumps({"files": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty"):
                load_inventory(inventory)
            inventory.write_text("not json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inventory"):
                load_inventory(inventory)

    def test_rejects_non_hex_inventory_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = srsc([(0x0101, 1, 0)])
            (root / "sample.srsc").write_bytes(data)
            entry = {
                "path": "sample.srsc", "status": "examined",
                "sha256": "g" * 64,
            }
            with self.assertRaisesRegex(ValueError, "hash"):
                read_records(root, entry)

    def test_rejects_symlinked_inventory_file(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            outside = Path(outside_directory) / "outside.srsc"
            data = srsc([(0x0101, 1, 0)])
            outside.write_bytes(data)
            linked = root / "linked.srsc"
            linked.symlink_to(outside)
            entry = {
                "path": linked.name, "status": "examined",
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            with self.assertRaisesRegex(ValueError, "symlink"):
                read_records(root, entry)


if __name__ == "__main__":
    unittest.main()
