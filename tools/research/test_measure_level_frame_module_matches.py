import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import measure_level_frame_module_matches as module_scan


class LevelFrameModuleMatchesTests(unittest.TestCase):
    def test_exact_tokens_report_counts_without_bytes(self):
        level = {(7, b"frame"): 2, (9, b"other"): 1}
        data = b"prefix" + b"\x07\x00\x00\x00\x05\x00frame" + b"suffix"
        report = module_scan.measure([level], data)
        self.assertEqual(report, {
            "level_files": 1,
            "distinct_level_frame_tokens": 2,
            "distinct_exact_tokens_found": 1,
        })
        self.assertEqual(set(report), {
            "level_files", "distinct_level_frame_tokens", "distinct_exact_tokens_found",
        })

    def test_empty_levels(self):
        self.assertEqual(module_scan.measure([{}], b"nothing"), {
            "level_files": 1,
            "distinct_level_frame_tokens": 0,
            "distinct_exact_tokens_found": 0,
        })

    def test_candidate_checks_size_and_hash(self):
        payload = b"synthetic module"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "module"
            path.write_bytes(payload)
            candidate = (len(payload), hashlib.sha256(payload).hexdigest())
            with patch.object(module_scan, "EXPECTED_CANDIDATES", {path.name: candidate}):
                self.assertEqual(module_scan.read_candidate(path)[0], payload)
                with patch.object(module_scan, "EXPECTED_CANDIDATES",
                                  {path.name: (len(payload), "0" * 64)}):
                    with self.assertRaisesRegex(ValueError, "SHA-256"):
                        module_scan.read_candidate(path)
                with patch.object(module_scan, "EXPECTED_CANDIDATES",
                                  {path.name: (len(payload) + 1, candidate[1])}):
                    with self.assertRaisesRegex(ValueError, "size"):
                        module_scan.read_candidate(path)

    def test_candidate_rejects_symlinked_and_hardlinked_inputs(self):
        payload = b"synthetic module"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "module"
            source.write_bytes(payload)
            linked = root / "symlink"
            try:
                linked.symlink_to(source.name)
                hardlinked = root / "hardlink"
                os.link(source, hardlinked)
            except OSError as error:
                self.skipTest(f"link creation unavailable: {error}")
            candidate = (len(payload), hashlib.sha256(payload).hexdigest())
            with patch.object(module_scan, "EXPECTED_CANDIDATES", {
                    source.name: candidate, linked.name: candidate,
                    hardlinked.name: candidate}):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    module_scan.read_candidate(linked)
                with self.assertRaisesRegex(ValueError, "regular file"):
                    module_scan.read_candidate(hardlinked)

    def test_inventory_duplicate_level_path_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = root / "inventory.json"
            inventory.write_text('{"files":[{"path":"same.lvl","status":"examined"},'
                                  '{"path":"same.lvl","status":"examined"}]}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                module_scan.measure_inventory(root, inventory, b"")


if __name__ == "__main__":
    unittest.main()
