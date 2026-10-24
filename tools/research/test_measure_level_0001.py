#!/usr/bin/env python3
"""Synthetic bounds checks for the level prefix measurement."""

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from measure_level_0001 import decode_prefix, level_candidates, load_inventory, safe_inventory_path


class LevelPrefixTest(unittest.TestCase):
    def test_variable_entry_and_opaque_tail(self):
        payload = (struct.pack("<I", 1) + bytes(28) + struct.pack("<H", 3) + b"abc"
                   + bytes(24) + struct.pack("<III", 2, 0, 7) + b"tail")
        self.assertEqual(decode_prefix(payload), (1, [2], [3], [0, 7], 4))
        for size in range(len(payload) - 4):
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode_prefix(payload[:size])

    def test_empty_and_excessive_counts(self):
        self.assertEqual(decode_prefix(struct.pack("<I", 0)), (0, [], [], [], 0))
        with self.assertRaises(ValueError):
            decode_prefix(struct.pack("<I", 4097))
        with self.assertRaises(ValueError):
            decode_prefix(struct.pack("<I", 1) + bytes(28) + bytes(2) + bytes(24)
                          + struct.pack("<I", 4097))

    def test_inventory_validation_and_safe_paths(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            outside = Path(outside_directory) / "outside.lvl"
            outside.write_bytes(b"data")
            sample = root / "sample.lvl"
            sample.write_bytes(b"data")
            entry = {"path": "sample.lvl", "candidate_table": {},
                     "sha256": hashlib.sha256(b"data").hexdigest()}
            self.assertEqual(level_candidates([entry]), [entry])
            self.assertEqual(safe_inventory_path(root, entry["path"]), sample)
            with self.assertRaisesRegex(ValueError, "path"):
                safe_inventory_path(root, "../outside.lvl")
            with self.assertRaisesRegex(ValueError, "path"):
                safe_inventory_path(root, str(outside))
            (root / "linked.lvl").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symlink"):
                safe_inventory_path(root, "linked.lvl")
            nested = root / "nested"
            nested.mkdir()
            (nested / "inside.lvl").write_bytes(b"data")
            (root / "linked-dir").symlink_to(nested, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                safe_inventory_path(root, "linked-dir/inside.lvl")
            with self.assertRaisesRegex(ValueError, "regular"):
                safe_inventory_path(root, "nested")
            with self.assertRaisesRegex(ValueError, "regular"):
                safe_inventory_path(root, "missing.lvl")
            with self.assertRaisesRegex(ValueError, "hash"):
                level_candidates([dict(entry, sha256="g" * 64)])
            with self.assertRaisesRegex(ValueError, "entry"):
                level_candidates(["not an inventory entry"])
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps({"files": [entry]}), encoding="utf-8")
            self.assertEqual(load_inventory(inventory), [entry])
            inventory.write_text("not json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inventory"):
                load_inventory(inventory)
            inventory.write_text(json.dumps({"files": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty"):
                load_inventory(inventory)


if __name__ == "__main__":
    unittest.main()
