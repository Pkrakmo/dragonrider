"""Synthetic checks for hash-gated C++ SRSC inspector comparisons."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from verify_srsc_inspector import parse_inspector_records, verified_records


class VerifySrscInspectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "sample.txd"
        record = struct.pack("<HHHII", 4, 5, 6, 12, 3)
        self.data = b"SRSC" + struct.pack("<HIH", 0x100, 12, 1) + record
        self.path.write_bytes(self.data)
        self.item = {
            "path": self.path.name,
            "size": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "candidate_table": {"offset": 12, "count": 1},
        }

    def test_reads_only_after_hash_and_table_bounds_match(self):
        path, records, data = verified_records(self.root, self.item)
        self.assertEqual(path, self.path)
        self.assertEqual(records, [(4, 5, 6, 12, 3)])
        self.assertEqual(data, self.data)

    def test_rejects_hash_mismatch_and_unsafe_paths(self):
        with self.assertRaisesRegex(ValueError, "hash"):
            verified_records(self.root, dict(self.item, sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "size or hash"):
            verified_records(self.root, dict(self.item, size=len(self.data) + 1))
        with self.assertRaisesRegex(ValueError, "path"):
            verified_records(self.root, dict(self.item, path="../sample.txd"))

    def test_rejects_symlink_and_out_of_file_table(self):
        link = self.root / "linked.txd"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, "symlink"):
            verified_records(self.root, dict(self.item, path=link.name))
        target_dir = self.root / "target"
        target_dir.mkdir()
        (target_dir / "sample.txd").write_bytes(self.data)
        linked_dir = self.root / "linked-dir"
        linked_dir.symlink_to(target_dir, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            verified_records(self.root, dict(self.item, path="linked-dir/sample.txd"))
        truncated = b"SRSC" + struct.pack("<HIH", 0x100, 12, 2) + self.data[12:]
        self.path.write_bytes(truncated)
        with self.assertRaisesRegex(ValueError, "outside"):
            verified_records(self.root, dict(
                self.item, size=len(truncated), sha256=hashlib.sha256(truncated).hexdigest(),
                candidate_table={"version": 0x100, "offset": 12, "count": 2, "end": 40}))
        self.path.write_bytes(self.data)
        with self.assertRaisesRegex(ValueError, "disagrees"):
            verified_records(self.root, dict(self.item,
                candidate_table={"version": 0x100, "offset": 13, "count": 1, "end": 27}))

    def test_parses_bounded_inspector_rows(self):
        output = (
            "Record 0: selectors=4,5,6 offset=12 length=3\n"
            "other diagnostic line\n"
            "Record 1: selectors=7,8,9 offset=15 length=1\n"
        )
        self.assertEqual(parse_inspector_records(output), [(4, 5, 6, 12, 3), (7, 8, 9, 15, 1)])


if __name__ == "__main__":
    unittest.main()
