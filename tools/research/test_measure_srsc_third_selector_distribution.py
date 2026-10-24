import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from measure_srsc_third_selector_distribution import (load_entries, measure,
                                                       read_verified_records)


RECORD = struct.Struct("<HHHII")


def srsc(records, *, table_offset=None):
    payload = b"P" * 4
    if table_offset is None:
        table_offset = 12 + len(payload)
    table = b"".join(RECORD.pack(*record) for record in records)
    return b"SRSC" + struct.pack("<HIH", 0x0100, table_offset, len(records)) + payload + table


class ThirdSelectorDistributionTests(unittest.TestCase):
    def test_own_and_cross_distribution_including_ambiguity(self):
        records = [
            (0x0101, 1, 0, 12, 0), (0x0101, 2, 1, 12, 0),
            (0x0101, 2, 9, 12, 0), (0x0102, 7, 2, 12, 0),
            (0x0102, 8, 1, 12, 0), (0x0102, 9, 0, 12, 0),
            (0x0201, 3, 0, 12, 0), (0x0200, 4, 3, 12, 0),
        ]
        result = measure(records)
        self.assertEqual(dict(result["own_kind"]["0101"]), {
            "records": 3, "third_zero": 1, "third_nonzero": 2,
            "nonzero_no_second_match": 1, "nonzero_one_second_match": 1,
            "nonzero_multiple_second_matches": 0,
        })
        self.assertEqual(dict(result["selected_cross_kind"]["0102_to_0101"]), {
            "records": 3, "third_zero": 1, "third_nonzero": 2,
            "nonzero_no_second_match": 0, "nonzero_one_second_match": 1,
            "nonzero_multiple_second_matches": 1,
        })
        self.assertEqual(result["selected_cross_kind"]["0200_to_0201"]
                         ["nonzero_one_second_match"], 1)

    def test_unselected_kinds_do_not_contribute(self):
        result = measure([(0x9999, 1, 2, 12, 0)])
        self.assertTrue(all(counts["records"] == 0
                            for scope in result.values() for counts in scope.values()))

    def test_palette_kind_third_selector_counts(self):
        result = measure([
            (0x0030, 4, 0, 12, 2),
            (0x0030, 8, 7, 14, 2),
        ])
        self.assertEqual(dict(result["own_kind"]["0030"]), {
            "records": 2,
            "third_zero": 1,
            "third_nonzero": 1,
            "nonzero_no_second_match": 1,
            "nonzero_one_second_match": 0,
            "nonzero_multiple_second_matches": 0,
        })

    def test_writer_gate_kind_third_selector_counts(self):
        result = measure([
            (0x0051, 0, 0, 12, 2),
            (0x0051, 1, 2, 14, 2),
        ])
        self.assertEqual(result["own_kind"]["0051"]["records"], 2)
        self.assertEqual(result["own_kind"]["0051"]["third_zero"], 1)
        self.assertEqual(result["own_kind"]["0051"]["third_nonzero"], 1)

    def test_hash_table_and_all_payload_ranges_are_validated(self):
        records = [(0x0101, 1, 0, 12, 4)]
        contents = srsc(records)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "sample"
            path.write_bytes(contents)
            entry = {"path": "sample", "status": "examined", "file_size": len(contents),
                     "sha256": hashlib.sha256(contents).hexdigest()}
            self.assertEqual(read_verified_records(root, entry), records)
            entry["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "hash"):
                read_verified_records(root, entry)
            entry["sha256"] = hashlib.sha256(contents).hexdigest()
            with self.assertRaisesRegex(ValueError, "size or hash"):
                read_verified_records(root, dict(entry, file_size=len(contents) + 1))
            entry["sha256"] = hashlib.sha256(contents).hexdigest()
            path.write_bytes(srsc([(0x0101, 1, 0, 12, 5)]))
            entry["file_size"] = path.stat().st_size
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "pre-table"):
                read_verified_records(root, entry)

    def test_rejects_malformed_headers_tables_and_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "sample"
            cases = [
                b"short",
                b"NOPE" + struct.pack("<HIH", 0x0100, 12, 1),
                b"SRSC" + struct.pack("<HIH", 0x0100, 12, 0),
                b"SRSC" + struct.pack("<HIH", 0x0100, 100, 1),
            ]
            for contents in cases:
                path.write_bytes(contents)
                entry = {"path": "sample", "status": "examined", "file_size": len(contents),
                         "sha256": hashlib.sha256(contents).hexdigest()}
                with self.assertRaises(ValueError):
                    read_verified_records(root, entry)
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps({"files": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty"):
                load_entries(inventory)
            inventory.write_text("not json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid inventory"):
                load_entries(inventory)

    def test_rejects_unexamined_or_escaping_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = srsc([(0x0101, 1, 0, 12, 0)])
            (root / "sample").write_bytes(contents)
            digest = hashlib.sha256(contents).hexdigest()
            with self.assertRaisesRegex(ValueError, "unexamined"):
                read_verified_records(root, {"path": "sample", "status": "pending",
                                             "file_size": len(contents), "sha256": digest})
            with self.assertRaisesRegex(ValueError, "path"):
                read_verified_records(root, {"path": "../sample", "status": "examined",
                                             "file_size": len(contents), "sha256": digest})

    def test_rejects_symlinked_inventory_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = srsc([(0x0101, 1, 0, 12, 0)])
            target = root / "target"
            target.write_bytes(contents)
            link = root / "link"
            link.symlink_to(target)
            entry = {"path": "link", "status": "examined", "file_size": len(contents),
                     "sha256": hashlib.sha256(contents).hexdigest()}
            with self.assertRaisesRegex(ValueError, "symlink"):
                read_verified_records(root, entry)


if __name__ == "__main__":
    unittest.main()
