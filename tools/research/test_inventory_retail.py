#!/usr/bin/env python3
"""Exercise the inventory tool with synthetic complete and truncated tables."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


class InventoryTest(unittest.TestCase):
    def test_table_bounds_and_empty_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "input"
            root.mkdir()
            output = Path(temp) / "inventory.json"
            header = b"SRSC" + struct.pack("<HIH", 256, 12, 1)
            (root / "complete.bin").write_bytes(header + bytes(14))
            (root / "truncated.bin").write_bytes(header)
            (root / "empty.bin").write_bytes(b"")
            script = Path(__file__).with_name("inventory_retail.py")
            subprocess.run([sys.executable, str(script), str(root), str(output)],
                           check=True, capture_output=True, text=True)
            inventory = json.loads(output.read_text(encoding="utf-8"))
            files = {item["path"]: item for item in inventory["files"]}
            self.assertEqual(inventory["file_count"], 3)
            self.assertTrue(files["complete.bin"]["candidate_table"]["ends_at_eof"])
            self.assertFalse(files["truncated.bin"]["candidate_table"]["within_file"])
            self.assertEqual(files["empty.bin"]["header_hex"], "")


if __name__ == "__main__":
    unittest.main()
