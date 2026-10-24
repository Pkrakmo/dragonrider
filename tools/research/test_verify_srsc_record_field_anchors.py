#!/usr/bin/env python3
"""Synthetic parser tests for SRSC record field-anchor verification."""

import unittest

from verify_srsc_record_field_anchors import (direct_references, instructions,
                                               literal_address_offsets)


class InstructionTests(unittest.TestCase):
    def test_parses_normalized_record_offsets(self):
        text = """
  45f6b2:\t66 8b 46 08          \tmov    ax,WORD PTR [esi+0x8]
  45f6b6:\t66 89 44 4a 04       \tmov    WORD PTR [edx+ecx*2+0x4],ax
  45f7ee:\t89 47 0a             \tmov    DWORD PTR [edi+0xa],eax
"""
        self.assertEqual(instructions(text), {
            0x45F6B2: "mov ax,WORD PTR [esi+0x8]",
            0x45F6B6: "mov WORD PTR [edx+ecx*2+0x4],ax",
            0x45F7EE: "mov DWORD PTR [edi+0xa],eax",
        })

    def test_ignores_headers_and_non_instruction_lines(self):
        text = """
Disassembly of section .text:
  commentary only
  45f1d5: 8b 4e 06 mov    ecx,DWORD PTR [esi+0x6]
"""
        self.assertEqual(instructions(text), {
            0x45F1D5: "mov ecx,DWORD PTR [esi+0x6]",
        })

    def test_separates_direct_accessor_calls_from_jumps(self):
        text = """
  42b0d9:\te8 f2 49 03 00       \tcall   0x45fad0
  435601:\te8 ca a4 02 00       \tcall   0x45fad0
  435606:\t85 c0                \ttest   eax,eax
  435607:\te9 00 00 00 00       \tjmp    0x45fad0
  435608:\tff d0                \tcall   eax
"""
        self.assertEqual(direct_references(text, "call"), {0x42B0D9, 0x435601})
        self.assertEqual(direct_references(text, "jmp"), {0x435607})
        self.assertEqual(direct_references(text, "call", 0x45F5D0), set())
        with self.assertRaisesRegex(ValueError, "mnemonic"):
            direct_references(text, "ret")

    def test_finds_only_raw_absolute_address_literals(self):
        address = 0x0045FAD0
        data = b"prefix" + address.to_bytes(4, "little") + b"middle" + \
            address.to_bytes(4, "little")
        self.assertEqual(literal_address_offsets(data, address), [6, 16])
        self.assertEqual(literal_address_offsets(b"no pointer", address), [])


if __name__ == "__main__":
    unittest.main()
