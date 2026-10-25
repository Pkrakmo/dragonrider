"""Synthetic validation for aggregate cell-reference measurement."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from measure_level_cell_references import measure_inventory


def fixture(first, second):
    prefix = struct.pack("<I7I", 1, 7, 1, 1, 0, 0, 0, 0)
    prefix += struct.pack("<H", 0) + struct.pack("<6I", *([0] * 6))
    prefix += struct.pack("<I", 0) + struct.pack("<I", 1)
    decoded = struct.pack("<8H", *([0] * 8)) + struct.pack("<Hii8H", 1, first, second, *([0] * 8))
    compressed = zlib.compress(decoded)
    payload = prefix + struct.pack("<I", len(compressed)) + compressed
    table_offset = 12 + len(payload)
    record = struct.pack("<HHHII", 1, 0, 0, 12, len(payload))
    return b"SRSC" + struct.pack("<HIH", 0x100, table_offset, 1) + payload + record


class CellReferenceTests(unittest.TestCase):
    def test_aggregates_without_emitting_identifiers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = fixture(42, 42)
            (root / "sample.lvl").write_bytes(data)
            entry = {"path": "sample.lvl", "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            result = measure_inventory(root, [entry])
            self.assertEqual(result["cells"], 1)
            self.assertEqual(result["equal_reference_pairs"], 1)
            self.assertEqual(result["distinct_reference_values"], 1)
            self.assertNotIn("identifiers", result)

    def test_rejects_stale_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = fixture(42, 42)
            (root / "sample.lvl").write_bytes(data)
            entry = {"path": "sample.lvl", "size": len(data), "sha256": "0" * 64}
            with self.assertRaisesRegex(ValueError, "hash"):
                measure_inventory(root, [entry])

    def test_counts_high_bit_in_signed_reference_word(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = fixture(-1, 42)
            (root / "sample.lvl").write_bytes(data)
            entry = {"path": "sample.lvl", "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            result = measure_inventory(root, [entry])
            self.assertEqual(result["high_bit_reference_values"], 1)

    def test_rejects_duplicate_inventory_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = fixture(42, 42)
            (root / "sample.lvl").write_bytes(data)
            entry = {"path": "sample.lvl", "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            with self.assertRaisesRegex(ValueError, "duplicate level inventory path"):
                measure_inventory(root, [entry, entry])

    def test_rejects_symlink_component(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root.parent / (root.name + "-outside.lvl")
            data = fixture(42, 42)
            outside.write_bytes(data)
            (root / "link.lvl").symlink_to(outside)
            entry = {"path": "link.lvl", "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            try:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    measure_inventory(root, [entry])
            finally:
                outside.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
