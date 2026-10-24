#!/usr/bin/env python3
"""Synthetic tests for the bounded level query-caller verifier."""

import unittest

from verify_level_query_callers import direct_callers, direct_jumps


class DirectCallerTests(unittest.TestCase):
    def test_extracts_only_direct_calls_to_requested_target(self):
        disassembly = """
  403623:\te8 e8 d7 01 00       \tcall   0x420e10
  403624:\te8 e8 d7 01 00       \tcall   0x420e11
  403625:\tff 50 10             \tcall   DWORD PTR [eax+0x10]
  403626:\te8 e8 d7 01 00       \tcall   0x00420e10
"""
        self.assertEqual(direct_callers(disassembly), {0x403623, 0x403626})

    def test_allows_another_target_and_ignores_non_instruction_text(self):
        disassembly = """
Disassembly of section .text:
  401000:\te8 fb 0f 00 00       \tcall   0x402000
  comment: call 0x402000
"""
        self.assertEqual(direct_callers(disassembly, 0x402000), {0x401000})
        self.assertEqual(direct_callers(disassembly, 0x420e10), set())

    def test_identifies_direct_unconditional_jumps_separately(self):
        disassembly = """
  403623:\te9 e8 d7 01 00       \tjmp   0x420e10
  403624:\tff e0                \tjmp   eax
  403625:\te8 e8 d7 01 00       \tcall  0x420e10
"""
        self.assertEqual(direct_jumps(disassembly), {0x403623})


if __name__ == "__main__":
    unittest.main()
