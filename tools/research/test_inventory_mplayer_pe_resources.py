import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from inventory_mplayer_pe_resources import MAX_PE_FILE_BYTES, inventory


class MplayerPEResourceInventoryTests(unittest.TestCase):
    def make_inputs(self, root):
        base = root / "English_-_Mplayer_Files"
        base.mkdir()
        entries = []
        for index in range(21):
            suffix = (".exe", ".dll", ".ocx")[index % 3]
            relative = f"English_-_Mplayer_Files/pe{index}{suffix}"
            data = f"synthetic-{index}".encode()
            (root / relative).write_bytes(data)
            entries.append({"path": relative, "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
        return entries

    def listing(self, command, **kwargs):
        data = Path(command[-1]).read_bytes()
        index = int(data.decode().split("-")[-1])
        types = {0: ("--type=3", "--type=3", "--type=5"),
                 1: ("--type=16", "--type='TYPELIB'"), 2: ()}[index % 3]
        output = "".join(f"{type_id} --name=1 --language=0 [redacted]\n"
                         for type_id in types)
        error = (f"wrestool: {command[-1]}: file contains no resources\n"
                 if index % 3 == 2 else "")
        return subprocess.CompletedProcess(command, 0, output, error)

    def test_counts_numeric_types_and_number_of_files_without_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = self.make_inputs(root)
            with patch("inventory_mplayer_pe_resources.subprocess.run", self.listing):
                result = inventory(root, entries)
            self.assertEqual(result["files_scanned"], 21)
            self.assertEqual(result["resource_entries"], 35)
            self.assertEqual(result["types"], {
                "3": {"entries": 14, "files": 7},
                "5": {"entries": 7, "files": 7},
                "16": {"entries": 7, "files": 7},
                "TYPELIB": {"entries": 7, "files": 7},
            })
            self.assertNotIn("--name", repr(result))
            self.assertFalse(result["executed_binaries"])

    def test_wrestool_receives_checked_snapshot_even_if_source_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = self.make_inputs(root)

            def change_source(command, **kwargs):
                source = root / entries[0]["path"]
                source.write_bytes(b"changed after hash verification")
                return self.listing(command, **kwargs)

            with patch("inventory_mplayer_pe_resources.subprocess.run", change_source):
                result = inventory(root, entries)
            self.assertEqual(result["files_scanned"], 21)

    def test_rejects_incomplete_duplicate_stale_and_oversized_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = self.make_inputs(root)
            with patch("inventory_mplayer_pe_resources.subprocess.run", self.listing):
                with self.assertRaisesRegex(ValueError, "expected 21"):
                    inventory(root, entries[:-1])
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    inventory(root, entries[:-1] + [dict(entries[0])])
                bad = [dict(item) for item in entries]
                bad[0]["sha256"] = "0" * 64
                with self.assertRaisesRegex(ValueError, "mismatch"):
                    inventory(root, bad)
                too_large = [dict(item) for item in entries]
                too_large[0]["size"] = MAX_PE_FILE_BYTES + 1
                with self.assertRaisesRegex(ValueError, "oversized"):
                    inventory(root, too_large)

    def test_rejects_symlink_paths_and_unrecognized_tool_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = self.make_inputs(root)
            source = root / entries[0]["path"]
            (source.parent / "linked.exe").symlink_to(source)
            linked = [dict(item) for item in entries]
            linked[0]["path"] = "English_-_Mplayer_Files/linked.exe"
            with patch("inventory_mplayer_pe_resources.subprocess.run", self.listing):
                with self.assertRaisesRegex(ValueError, "symlink"):
                    inventory(root, linked)
                with patch("inventory_mplayer_pe_resources.subprocess.run",
                           return_value=subprocess.CompletedProcess([], 0, "unexpected\n", "")):
                    with self.assertRaisesRegex(ValueError, "unrecognized"):
                        inventory(root, entries)


if __name__ == "__main__":
    unittest.main()
