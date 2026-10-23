import hashlib
import tempfile
import unittest
from pathlib import Path

from measure_srsc_extended_selector_links import (measure_file,
                                                  measure_inventory)


class ExtendedSelectorLinkTests(unittest.TestCase):
    def test_unique_missing_duplicate_zero_and_table_order(self):
        records = [
            (0x0201, 0x11, 0, 0, 0),
            (0x0201, 0x22, 0, 0, 0),
            (0x0207, 1, 0x22, 0, 0),
            (0x0208, 2, 0x33, 0, 0),
            (0x0209, 3, 0x11, 0, 0),
            (0x0201, 0x22, 0, 0, 0),
            (0x0207, 4, 0x22, 0, 0),
            (0x0208, 5, 0, 0, 0),
            (0x0207, 6, 0x44, 0, 0),
            (0x0201, 0x44, 0, 0, 0),
        ]
        result = measure_file(records)
        self.assertEqual(result["0207_to_0201"]["source_records"], 3)
        self.assertEqual(result["0207_to_0201"]["nonzero_multiple_matches"], 2)
        self.assertEqual(result["0207_to_0201"]["unique_target_after_source"], 1)
        self.assertEqual(result["0208_to_0201"]["nonzero_no_match"], 1)
        self.assertEqual(result["0208_to_0201"]["third_zero"], 1)
        self.assertEqual(result["0209_to_0201"]["unique_target_before_source"], 1)

    def test_verified_inventory_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"\x00" * 12
            file = root / "sample.bin"
            file.write_bytes(payload)
            # Minimal SRSC 1.0 header and one record; empty payload is valid here.
            table_offset = 12
            data = b"SRSC" + (0x0100).to_bytes(2, "little")
            data += table_offset.to_bytes(4, "little") + (1).to_bytes(2, "little")
            data += (0x0201).to_bytes(2, "little") + (7).to_bytes(2, "little")
            data += (0).to_bytes(2, "little") + (12).to_bytes(4, "little") + (0).to_bytes(4, "little")
            file.write_bytes(data)
            entry = {"status": "examined", "path": "sample.bin", "file_size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            result = measure_inventory(root, [entry])
            self.assertEqual(result["files_examined"], 1)
            self.assertEqual(result["relationships"]["0207_to_0201"]["source_records"], 0)
            stale = dict(entry, sha256="0" * 64)
            with self.assertRaisesRegex(ValueError, "size or hash mismatch"):
                measure_inventory(root, [stale])

    def test_rejects_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # A structurally valid SRSC file ensures duplicate detection is
            # reached before any malformed-entry condition can mask it.
            data = b"SRSC" + (0x0100).to_bytes(2, "little")
            data += (12).to_bytes(4, "little") + (1).to_bytes(2, "little")
            data += (0x0201).to_bytes(2, "little") + (7).to_bytes(2, "little")
            data += (0).to_bytes(2, "little") + (12).to_bytes(4, "little") + (0).to_bytes(4, "little")
            (root / "sample.bin").write_bytes(data)
            entry = {"path": "sample.bin", "status": "examined",
                     "file_size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            with self.assertRaisesRegex(ValueError, "duplicate"):
                measure_inventory(root, [entry, entry])


if __name__ == "__main__":
    unittest.main()
