"""Synthetic parser tests for hash-pinned Mplayer INI call anchors."""
import unittest

from verify_mplayer_ini_path_anchors import (
    direct_callers,
    verify_anchors,
    verify_data_section,
    verify_named_import,
)


class VerifyMplayerIniPathAnchorsTests(unittest.TestCase):
    def test_accepts_and_rejects_instruction_anchors(self):
        text = """
10002a68: 68 00 95 03 10 push 0x10039500
10002a6d: 57 push edi
10002a6e: e8 3d bb 00 00 call 0x1000e5b0
"""
        expected = {
            0x10002A68: "push 0x10039500",
            0x10002A6D: "push edi",
            0x10002A6E: "call 0x1000e5b0",
        }
        self.assertEqual(verify_anchors(text, expected), 3)
        with self.assertRaisesRegex(ValueError, "anchor"):
            verify_anchors(text.replace("0x10039500", "0x10039504"), expected)

    def test_checks_data_section_mapping(self):
        text = "  2 .data 00008400 10039000 10039000 00037800 2**2\n"
        self.assertEqual(verify_data_section(text, 0x37800, 0x10039000), 0x8400)
        with self.assertRaisesRegex(ValueError, "mapping"):
            verify_data_section(text, 0x37804, 0x10039000)

    def test_checks_named_import_by_iat_rva(self):
        text = "  000695a0  <none>  02b1  strcat\n  000695a4 <none> 02b5 strcpy\n"
        self.assertEqual(verify_named_import(text, 0x695A0, "strcat"), "strcat")
        with self.assertRaisesRegex(ValueError, "strcat"):
            verify_named_import(text.replace("strcat", "strcpy", 1), 0x695A0, "strcat")

    def test_separates_direct_helper_callers_from_indirect_calls(self):
        text = """
100026d7: e8 db 03 00 00 call 0x10002ab7
100026bb: e8 49 04 00 00 call 0x10002b09
100026c0: ff 15 48 94 06 10 call dword ptr ds:0x10069448
"""
        self.assertEqual(direct_callers(text, 0x10002AB7), {0x100026D7})
        self.assertEqual(direct_callers(text, 0x10002B09), {0x100026BB})


if __name__ == "__main__":
    unittest.main()
