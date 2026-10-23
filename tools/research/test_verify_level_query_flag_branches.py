#!/usr/bin/env python3
"""Synthetic parser tests for level query flag-branch verification."""

import unittest

from verify_level_query_flag_branches import instructions


class InstructionTests(unittest.TestCase):
    def test_parses_and_normalizes_instruction_lines(self):
        text = """
  42106a:\tf6 c3 10             \ttest   bl,0x10
  42106f:\t83 7a 28 02          \tcmp    DWORD PTR [edx+0x28],0x2
  421349:\t75 47                \tjne    0x421392
"""
        self.assertEqual(instructions(text), {
            0x42106A: "test bl,0x10",
            0x42106F: "cmp DWORD PTR [edx+0x28],0x2",
            0x421349: "jne 0x421392",
        })

    def test_ignores_headers_and_malformed_lines(self):
        text = """
Disassembly of section .text:
not an instruction
  42106a: f6 c3 10 test   bl,0x10
"""
        self.assertEqual(instructions(text), {0x42106A: "test bl,0x10"})


if __name__ == "__main__":
    unittest.main()
