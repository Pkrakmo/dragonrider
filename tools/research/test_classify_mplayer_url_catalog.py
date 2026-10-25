"""Synthetic tests for the aggregate-only mpurl.dat classifier."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from classify_mplayer_url_catalog import TARGET, classify


class ClassifyMplayerUrlCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        target = self.root / TARGET
        target.parent.mkdir(parents=True)
        self.data = b"https://one.invalid/a\n\nftp://two.invalid/b\r\n"
        target.write_bytes(self.data)
        self.entry = {"path": TARGET, "size": len(self.data),
                      "sha256": hashlib.sha256(self.data).hexdigest()}

    def test_reports_aggregate_without_content(self):
        result = classify(self.root, [self.entry])
        self.assertEqual(result["uri_scheme_token_counts"],
                         {"http": 0, "https": 1, "ftp": 1})
        self.assertEqual(result["uri_bearing_nonempty_lines"], 2)
        self.assertEqual(result["blank_line_count"], 1)
        self.assertFalse(result["content_values_emitted"])
        self.assertNotIn("one.invalid", str(result))

    def test_requires_one_matching_inventory_path(self):
        with self.assertRaises(ValueError):
            classify(self.root, [])
        with self.assertRaises(ValueError):
            classify(self.root, [self.entry, self.entry])

    def test_rejects_stale_hash(self):
        bad = dict(self.entry, sha256="0" * 64)
        with self.assertRaises(ValueError):
            classify(self.root, [bad])

    def test_rejects_non_ascii(self):
        target = self.root / TARGET
        data = b"bad\xff\n"
        target.write_bytes(data)
        entry = {"path": TARGET, "size": len(data),
                 "sha256": hashlib.sha256(data).hexdigest()}
        with self.assertRaises(ValueError):
            classify(self.root, [entry])


if __name__ == "__main__":
    unittest.main()
