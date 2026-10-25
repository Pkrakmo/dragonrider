"""Synthetic tests for bounded LFL/MPL text-list classification."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from classify_retail_text_lists import TARGETS, classify


class ClassifyRetailTextListsTests(unittest.TestCase):
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

    def test_reports_only_aggregate_shapes(self):
        result = classify(self.root, self.entries)
        self.assertFalse(result["content_values_emitted"])
        self.assertEqual(len(result["files"]), 4)
        for item in result["files"]:
            expected_lines = 1 if item["path"].endswith(".mpl") else 2
            self.assertEqual(item["line_count"], expected_lines)
            self.assertEqual(item["slash_or_backslash_lines"], 1)

    def test_rejects_missing_or_duplicate_paths(self):
        with self.assertRaises(ValueError):
            classify(self.root, self.entries[:-1])
        with self.assertRaises(ValueError):
            classify(self.root, self.entries + [self.entries[0]])

    def test_rejects_stale_hash(self):
        bad = [dict(entry) for entry in self.entries]
        bad[0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            classify(self.root, bad)

    def test_rejects_non_ascii(self):
        relative = self.entries[0]["path"]
        data = b"bad\xff"
        (self.root / relative).write_bytes(data)
        bad = [dict(entry) for entry in self.entries]
        bad[0].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        with self.assertRaises(ValueError):
            classify(self.root, bad)


if __name__ == "__main__":
    unittest.main()
