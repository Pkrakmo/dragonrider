"""Synthetic tests for bounded retail support-text shape classification."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from classify_retail_support_text import MAX_BYTES, TARGETS, classify


class ClassifyRetailSupportTextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        samples = {
            ".htm": b'<!DOCTYPE html><a href="https://secret.invalid/a">x</a><img src="i.gif">',
            ".ini": b"[Local]\r\nKey=value\r\nkey=secret\r\n;note\r\n[Web]\nURL=https://secret.invalid\n",
            ".url": b"[InternetShortcut]\r\nURL=https://secret.invalid\r\n",
            ".txt": b"Heading\r\n====\r\n\r\n  body\r\n- bullet\r\n",
        }
        self.entries = []
        for index, relative in enumerate(sorted(TARGETS)):
            suffix = Path(relative).suffix
            data = samples[suffix]
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.entries.append({"path": relative, "size": len(data),
                                 "sha256": hashlib.sha256(data).hexdigest()})

    def test_reports_only_aggregate_shapes(self):
        result = classify(self.root, self.entries)
        self.assertFalse(result["content_values_emitted"])
        self.assertEqual(len(result["files"]), 8)
        serialized = str(result)
        self.assertNotIn("secret", serialized)
        html = next(item for item in result["files"] if item["path"].endswith(".htm"))
        self.assertEqual(html["html_shape"]["doctype_count"], 1)
        self.assertEqual(html["html_shape"]["reference_kind_counts"],
                         {"http": 1, "relative_or_empty_scheme": 1})
        ini = next(item for item in result["files"] if item["path"].endswith(".ini"))
        self.assertEqual(ini["ini_shape"]["duplicate_key_count"], 1)
        self.assertEqual(ini["ini_shape"]["section_count"], 2)
        readme = next(item for item in result["files"] if item["path"].endswith(".txt"))
        self.assertEqual(readme["prose_shape"]["bullet_line_count"], 1)

    def test_rejects_missing_or_duplicate_paths(self):
        with self.assertRaises(ValueError):
            classify(self.root, self.entries[:-1])
        with self.assertRaises(ValueError):
            classify(self.root, self.entries + [self.entries[0]])

    def test_rejects_stale_hash(self):
        bad = [dict(entry) for entry in self.entries]
        bad[0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            classify(self.root, bad)

    def test_rejects_symlinked_path(self):
        relative = self.entries[0]["path"]
        path = self.root / relative
        target = self.root / "outside" / Path(relative).name
        target.parent.mkdir()
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            classify(self.root, self.entries)

    def test_rejects_nul_and_invalid_utf8(self):
        for data, message in ((b"a\0b", "NUL"), (b"\xff", "UTF-8")):
            path = self.root / self.entries[0]["path"]
            path.write_bytes(data)
            bad = [dict(entry) for entry in self.entries]
            bad[0].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
            with self.assertRaisesRegex(ValueError, message):
                classify(self.root, bad)

    def test_rejects_oversized_metadata_before_read(self):
        bad = [dict(entry) for entry in self.entries]
        bad[0]["size"] = MAX_BYTES + 1
        with self.assertRaisesRegex(ValueError, "oversized"):
            classify(self.root, bad)


if __name__ == "__main__":
    unittest.main()
