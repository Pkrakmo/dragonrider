"""Synthetic checks for the hash-checked SRSC payload-layout scan."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from measure_srsc_payload_layout_inventory import measure_file, measure_inventory


def make_srsc(records, *, trailing=b""):
    payload = b"".join(value for _, value in records)
    offset = 12 + len(payload)
    table = b"".join(
        struct.pack("<HHHII", *selectors, start, len(value))
        for (selectors, value), start in zip(records, _starts(records))
    )
    return b"SRSC" + struct.pack("<HIH", 0x100, offset, len(records)) + payload + table + trailing


def _starts(records):
    start = 12
    for _, payload in records:
        yield start
        start += len(payload)


class PayloadLayoutInventoryTests(unittest.TestCase):
    def test_measures_complete_partition_without_claiming_a_rule(self):
        data = make_srsc([((0x40, 0, 0), b"abc"), ((0x41, 0, 0), b"de")])
        metrics = measure_file(data)
        self.assertEqual(metrics["ranges_within_payload"], 2)
        self.assertEqual(metrics["transitions"], {"contiguous": 1})
        self.assertTrue(metrics["first_starts_at_header_end"])
        self.assertTrue(metrics["last_ends_at_table_start"])
        self.assertTrue(metrics["table_ends_at_eof"])
        self.assertEqual(metrics["maximum_start_offset"], 15)
        self.assertEqual(metrics["maximum_range_end"], 17)
        self.assertEqual(metrics["maximum_range_length"], 3)

    def test_measurement_reports_table_overlap_and_trailing_bytes(self):
        header = b"SRSC" + struct.pack("<HIH", 0x100, 12, 1)
        record = struct.pack("<HHHII", 1, 2, 3, 12, 14)
        metrics = measure_file(header + record + b"x")
        self.assertEqual(metrics["invalid_ranges"], 1)
        self.assertFalse(metrics["table_ends_at_eof"])

    def test_distinguishes_gaps_and_overlapping_ranges(self):
        payload = b"abcdefgh"
        offset = 12 + len(payload)
        header = b"SRSC" + struct.pack("<HIH", 0x100, offset, 2)
        gap_table = (struct.pack("<HHHII", 1, 1, 1, 12, 2)
                     + struct.pack("<HHHII", 2, 2, 2, 16, 4))
        overlap_table = (struct.pack("<HHHII", 1, 1, 1, 12, 4)
                         + struct.pack("<HHHII", 2, 2, 2, 14, 6))
        self.assertEqual(measure_file(header + payload + gap_table)["transitions"], {"gap": 1})
        self.assertEqual(measure_file(header + payload + overlap_table)["transitions"], {"overlap": 1})

    def test_hash_gates_every_inventory_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = make_srsc([((1, 2, 3), b"x")])
            path = root / "sample.txd"
            path.write_bytes(data)
            entry = {"status": "examined", "path": path.name, "file_size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            self.assertEqual(measure_inventory(root, [entry])[0], 1)
            with self.assertRaisesRegex(ValueError, "hash"):
                measure_inventory(root, [dict(entry, sha256="f" * 64)])
            with self.assertRaisesRegex(ValueError, "size or hash"):
                measure_inventory(root, [dict(entry, file_size=len(data) + 1)])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                measure_inventory(root, [entry, entry])

    def test_rejects_unsafe_path_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = make_srsc([((1, 2, 3), b"x")])
            sample = root / "sample.txd"
            sample.write_bytes(data)
            entry = {"status": "examined", "path": "../sample.txd", "file_size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            with self.assertRaisesRegex(ValueError, "path"):
                measure_inventory(root, [entry])
            link = root / "link.txd"
            link.symlink_to(sample)
            with self.assertRaisesRegex(ValueError, "symlink"):
                measure_inventory(root, [dict(entry, path=link.name)])

    def test_rejects_empty_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "empty"):
                measure_inventory(Path(directory), [])


if __name__ == "__main__":
    unittest.main()
