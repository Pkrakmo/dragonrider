#!/usr/bin/env python3
"""Synthetic parser tests for SRSC record field-anchor verification."""

import unittest

from verify_srsc_record_field_anchors import instructions


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


if __name__ == "__main__":
    unittest.main()
