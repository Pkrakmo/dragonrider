import hashlib
from pathlib import Path
import tempfile
import unittest

from scan_mplayer_pe_references import MAX_PE_FILE_BYTES, scan


class MplayerReferenceScanTests(unittest.TestCase):
    def make_inputs(self, root):
        entries = []
        base = root / "English_-_Mplayer_Files"
        base.mkdir()
        for index in range(21):
            suffix = (".exe", ".dll", ".ocx")[index % 3]
            relative = f"English_-_Mplayer_Files/pe{index}{suffix}"
            if index == 0:
                data = b"fetch MPI file mICTemp.mpi mpdrakan.mpi mpurl.dat mphisto.csv mpusage.csv"
            elif index == 1:
                data = ".tln drakan.tln mpurl.dat".encode("utf-16le")
            else:
                data = b"no target"
            path = root / relative
            path.write_bytes(data)
            entries.append({"path": relative, "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
        return entries

    def test_reports_ascii_and_utf16le_substrings_without_payloads(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            entries = self.make_inputs(root)
            result = scan(root, entries)
            self.assertEqual(result["files_scanned"], 21)
            self.assertEqual(result["ascii"][".mpi"], ["pe0.exe"])
            self.assertEqual(result["ascii"]["mpdrakan.mpi"], ["pe0.exe"])
            self.assertEqual(result["ascii"]["mpurl.dat"], ["pe0.exe"])
            self.assertEqual(result["ascii"]["mphisto.csv"], ["pe0.exe"])
            self.assertEqual(result["ascii"]["mpusage.csv"], ["pe0.exe"])
            self.assertEqual(result["utf16le"][".tln"], ["pe1.dll"])
            self.assertEqual(result["utf16le"]["drakan.tln"], ["pe1.dll"])
            self.assertEqual(result["utf16le"]["mpurl.dat"], ["pe1.dll"])
            self.assertFalse(result["executed_binaries"])

    def test_rejects_incomplete_duplicate_and_stale_inventories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            entries = self.make_inputs(root)
            with self.assertRaisesRegex(ValueError, "expected 21"):
                scan(root, entries[:-1])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                scan(root, entries[:-1] + [dict(entries[0])])
            entries[0] = dict(entries[0], sha256="0" * 64)
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                scan(root, entries)
            entries[0] = dict(entries[0], size=MAX_PE_FILE_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "oversized"):
                scan(root, entries)

    def test_rejects_symlinked_manifest_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            entries = self.make_inputs(root)
            source = root / entries[0]["path"]
            link = source.with_name("linked.exe")
            link.symlink_to(source)
            entries[0] = dict(entries[0], path="English_-_Mplayer_Files/linked.exe")
            with self.assertRaisesRegex(ValueError, "symlink"):
                scan(root, entries)


if __name__ == "__main__":
    unittest.main()
