"""Synthetic tests for bounded Mplayer CSV candidate classification."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from classify_mplayer_csvs import MAX_BYTES, TARGETS, classify


class ClassifyMplayerCsvsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entries = []
        for relative, data in zip(sorted(TARGETS),
                                  (b'a,"b,c"\r\n\r\n', b"1,2\n")):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.entries.append({"path": relative, "size": len(data),
                                 "sha256": hashlib.sha256(data).hexdigest()})

    def test_reports_aggregate_fields_and_line_endings_only(self):
        result = classify(self.root, self.entries)
        self.assertEqual(len(result["files"]), 2)
        first = result["files"][0]
        self.assertEqual(first["field_count_distribution"], {"0": 1, "2": 1})
        self.assertEqual(first["crlf_count"], 2)
        self.assertFalse(first["content_values_emitted"])
        self.assertNotIn('"b,c"', str(result))

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
        path = self.root / self.entries[0]["path"]
        data = b"bad\xff"
        path.write_bytes(data)
        bad = [dict(entry) for entry in self.entries]
        bad[0].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(ValueError, "ASCII CSV"):
            classify(self.root, bad)

    def test_rejects_symlinked_inventory_path(self):
        relative = self.entries[0]["path"]
        path = self.root / relative
        target = self.root / "outside.csv"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            classify(self.root, self.entries)

    def test_rejects_oversized_inventory_entry_before_read(self):
        bad = [dict(entry) for entry in self.entries]
        bad[0]["size"] = MAX_BYTES + 1
        with self.assertRaisesRegex(ValueError, "oversized"):
            classify(self.root, bad)

    def test_rejects_malformed_csv(self):
        path = self.root / self.entries[0]["path"]
        data = b'"unterminated\r\n'
        path.write_bytes(data)
        bad = [dict(entry) for entry in self.entries]
        bad[0].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(ValueError, "parseable ASCII CSV"):
            classify(self.root, bad)


if __name__ == "__main__":
    unittest.main()
