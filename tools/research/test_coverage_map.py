from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("verify_coverage_map", Path(__file__).with_name("verify_coverage_map.py"))
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class CoverageMapTests(unittest.TestCase):
    def test_repository_map_is_valid_and_has_stable_totals(self) -> None:
        root = Path(__file__).resolve().parents[2]
        summary = VERIFY.summarize(VERIFY.load_map(root / "docs/research/coverage-map.json", root))
        self.assertIn("Coverage topics: 17", summary)
        self.assertIn("active: 13", summary)
        self.assertIn("not_started: 3", summary)
        self.assertIn("blocked: 1", summary)

    def test_rejects_missing_evidence_and_duplicate_id(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source = json.loads((root / "docs/research/coverage-map.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "map.json"
            source["topics"][1]["id"] = source["topics"][0]["id"]
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate topic id"):
                VERIFY.load_map(path, root)
            source["topics"][1]["id"] = "different-id"
            source["topics"][0]["evidence"] = ["docs/research/missing.md"]
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing or unsafe evidence"):
                VERIFY.load_map(path, root)


if __name__ == "__main__":
    unittest.main()
