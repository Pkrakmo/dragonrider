"""Synthetic tests for the pinned retail support-text literal scan."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from verify_mplayer_support_text_refs import PROGRAM, TARGETS, verify


class VerifyMplayerSupportTextRefsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entries = []
        for i in range(21):
            suffix = (".exe", ".dll", ".ocx")[i % 3]
            relative = f"English_-_Mplayer_Files/Program{i}{suffix}"
            data = b"no literal"
            if i == 0:
                data = b"Blank.htm " + "MplayerLocal.ini".encode("utf-16le")
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.entries.append({"path": relative, "size": len(data),
                                 "sha256": hashlib.sha256(data).hexdigest()})
        program = self.root / PROGRAM
        program.parent.mkdir(parents=True, exist_ok=True)
        program.write_bytes(b"mic-help.htm")
        self.entries.append({"path": PROGRAM, "size": 12,
                             "sha256": hashlib.sha256(b"mic-help.htm").hexdigest()})

    def test_reports_exact_ascii_and_utf16le_matches(self):
        result = verify(self.root, self.entries)
        self.assertEqual(result["program_snapshots_verified"], 22)
        self.assertEqual(result["ascii_basename_literal_programs"]["Blank.htm"], ["Program0.exe"])
        self.assertEqual(result["utf16le_basename_literal_programs"]["MplayerLocal.ini"],
                         ["Program0.exe"])
        self.assertEqual(result["ascii_basename_literal_programs"]["mic-help.htm"],
                         ["Drakan.exe"])
        self.assertFalse(result["executed_programs"])

    def test_rejects_incomplete_and_duplicate_inventory(self):
        with self.assertRaisesRegex(ValueError, "expected"):
            verify(self.root, self.entries[:-1])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify(self.root, self.entries + [dict(self.entries[0])])

    def test_rejects_stale_hash_before_literal_scan(self):
        bad = [dict(entry) for entry in self.entries]
        bad[0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verify(self.root, bad)

    def test_rejects_symlinked_program(self):
        bad = [dict(entry) for entry in self.entries]
        entry = bad[0]
        path = self.root / entry["path"]
        target = self.root / "target.exe"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            verify(self.root, bad)


if __name__ == "__main__":
    unittest.main()
