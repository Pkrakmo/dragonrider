"""Synthetic checks for the cross-extension level-record measurement."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from measure_level_0001_inventory import measure_inventory


def srsc(records):
    body = b"".join(payload for _, payload in records)
    offset = 12
    table = []
    for selectors, payload in records:
        table.append(struct.pack("<HHHII", *selectors, offset, len(payload)))
        offset += len(payload)
    return b"SRSC" + struct.pack("<HIH", 0x100, offset, len(table)) + body + b"".join(table)


class LevelInventoryMeasurementTests(unittest.TestCase):
    def test_measures_only_present_selector_across_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compressed_branch = root / "level.lvl"
            compressed_data = srsc([((1, 0, 0), struct.pack("<II", 0, 1))])
            compressed_branch.write_bytes(compressed_data)
            unrelated = root / "other.mod"
            unrelated_data = srsc([((2, 0, 0), b"unused")])
            unrelated.write_bytes(unrelated_data)
            entries = [
                {"path": path.name, "status": "examined", "file_size": len(data),
                 "sha256": hashlib.sha256(data).hexdigest()}
                for path, data in ((compressed_branch, compressed_data), (unrelated, unrelated_data))
            ]
            files, result = measure_inventory(root, entries)
            self.assertEqual(files, 2)
            self.assertEqual(dict(result[".lvl"]), {
                "files": 1, "storage_word_1": 1, "blocks": 0, "zlib_streams": 0,
            })
            self.assertNotIn(".mod", result)

    def test_rejects_bad_hash_and_selector_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = srsc([((1, 0, 0), struct.pack("<II", 0, 1))])
            sample = root / "sample.lvl"
            sample.write_bytes(data)
            entry = {"path": sample.name, "status": "examined", "file_size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            with self.assertRaisesRegex(ValueError, "hash"):
                measure_inventory(root, [dict(entry, sha256="z" * 64)])
            duplicate = srsc([
                ((1, 0, 0), struct.pack("<II", 0, 1)),
                ((1, 0, 0), struct.pack("<II", 0, 1)),
            ])
            sample.write_bytes(duplicate)
            entry = dict(entry, file_size=len(duplicate), sha256=hashlib.sha256(duplicate).hexdigest())
            with self.assertRaisesRegex(ValueError, "at most one"):
                measure_inventory(root, [entry])
            overlapping = b"SRSC" + struct.pack("<HIH", 0x100, 12, 1) + \
                struct.pack("<HHHII", 1, 0, 0, 12, 8)
            sample.write_bytes(overlapping)
            entry = dict(entry, file_size=len(overlapping),
                         sha256=hashlib.sha256(overlapping).hexdigest())
            with self.assertRaisesRegex(ValueError, "overlaps"):
                measure_inventory(root, [entry])


if __name__ == "__main__":
    unittest.main()
