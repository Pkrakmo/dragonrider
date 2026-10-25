"""Synthetic tests for bounded LFL/MPL inventory-link measurement."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from measure_text_list_inventory_links import TARGETS, measure


class TextListInventoryLinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entries = []
        for index, relative in enumerate(sorted(TARGETS)):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            data = (b"metadata\r\nworld/level.lvl\r\n" if index < 3
                    else b"area/scene.reo\r\n")
            path.write_bytes(data)
            self.entries.append({"path": relative, "size": len(data),
                                 "sha256": hashlib.sha256(data).hexdigest()})
        for relative in ("world/level.lvl", "other/scene.reo"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture")
            self.entries.append({"path": relative, "size": 7,
                                 "sha256": hashlib.sha256(b"fixture").hexdigest()})

    def test_reports_only_candidate_aggregate_matches(self):
        result = measure(self.root, self.entries)
        self.assertFalse(result["row_values_emitted"])
        self.assertFalse(result["path_meaning_established"])
        self.assertEqual(len(result["files"]), 4)
        for item in result["files"]:
            if item["path"].endswith(".lfl"):
                self.assertEqual(item["path_rows"], 1)
                self.assertEqual(item["unique_exact_basename_inventory_matches"], 1)
                self.assertEqual(item["unique_casefold_basename_inventory_matches"], 1)
                self.assertEqual(item["unique_basename_stem_inventory_matches"], 1)
                self.assertEqual(item["normalized_root_relative_exact_inventory_matches"], 1)
            else:
                self.assertEqual(item["suffix_counts"], {"reo": 1})
                self.assertEqual(item["unique_exact_basename_inventory_matches"], 1)
                self.assertEqual(item["unique_casefold_basename_inventory_matches"], 1)
                self.assertEqual(item["unique_basename_stem_inventory_matches"], 1)

    def test_rejects_missing_or_duplicate_target(self):
        with self.assertRaises(ValueError):
            measure(self.root, [item for item in self.entries
                                if item["path"] != sorted(TARGETS)[0]])
        with self.assertRaises(ValueError):
            measure(self.root, self.entries + [self.entries[0]])

    def test_rejects_stale_hash(self):
        bad = [dict(item) for item in self.entries]
        bad[0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            measure(self.root, bad)

    def test_rejects_unsafe_manifest_or_row_paths(self):
        bad = [dict(item) for item in self.entries]
        bad[-1]["path"] = "../escape"
        with self.assertRaises(ValueError):
            measure(self.root, bad)
        relative = sorted(TARGETS)[0]
        path = self.root / relative
        data = b"metadata\r\n../outside.lvl\r\n"
        path.write_bytes(data)
        bad = [dict(item) for item in self.entries]
        target = next(item for item in bad if item["path"] == relative)
        target.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        result = measure(self.root, bad)
        item = next(item for item in result["files"] if item["path"] == relative)
        self.assertEqual(item["unsafe_or_nonrelative_rows"], 1)

    def test_rejects_symlinked_source_file(self):
        relative = sorted(TARGETS)[0]
        path = self.root / relative
        outside = self.root.parent / (self.root.name + "-outside.txt")
        data = path.read_bytes()
        outside.write_bytes(data)
        path.unlink()
        path.symlink_to(outside)
        try:
            with self.assertRaisesRegex(ValueError, "symlink"):
                measure(self.root, self.entries)
        finally:
            outside.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
