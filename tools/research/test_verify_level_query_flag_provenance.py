"""Synthetic checks for level-query direct argument provenance anchors."""

import unittest
from unittest.mock import patch

import verify_level_query_flag_provenance as verifier


def disassembly_for(instructions=None, query_callers=None, wrapper_callers=None):
    rows = []
    anchors = dict(instructions or verifier.EXPECTED_INSTRUCTIONS)
    for address, text in anchors.items():
        if (query_callers is not None and text == "call 0x420960"
                and address not in query_callers):
            continue
        if (wrapper_callers is not None and text == "call 0x44c9f0"
                and address not in wrapper_callers):
            continue
        rows.append(f" {address:x}: 90 {text}")
    for address in sorted(query_callers if query_callers is not None
                          else verifier.EXPECTED_QUERY_CALLERS):
        if address not in anchors:
            rows.append(f" {address:x}: e8 00 00 00 00 call 0x420960")
    for address in sorted(wrapper_callers if wrapper_callers is not None
                           else verifier.EXPECTED_WRAPPER_CALLERS):
        if address not in anchors:
            rows.append(f" {address:x}: e8 00 00 00 00 call 0x44c9f0")
    return "\n".join(rows)


class LevelQueryFlagProvenanceTests(unittest.TestCase):
    def test_finds_only_direct_calls_to_selected_targets(self):
        text = """
  420df3: e8 00 00 00 00 call 0x420960
  420df4: ff d0 call eax
  420df5: e8 00 00 00 00 call 0x420961
  44c940: e8 00 00 00 00 call 0x44c9f0
"""
        self.assertEqual(verifier.direct_calls(text, verifier.QUERY), {0x420df3})
        self.assertEqual(verifier.direct_calls(text, verifier.WRAPPER), {0x44c940})

    def test_finds_direct_unconditional_jumps_separately(self):
        text = """
  420df3: e9 00 00 00 00 jmp 0x420960
  420df8: 74 02 je 0x420960
  420dfa: ff e0 jmp eax
"""
        self.assertEqual(verifier.direct_jumps(text, verifier.QUERY), {0x420df3})

    def test_finds_exact_raw_address_literals(self):
        needle = verifier.WRAPPER.to_bytes(4, "little")
        self.assertEqual(verifier.raw_pointer_offsets(b"a" + needle + b"b" + needle,
                                                       verifier.WRAPPER), [1, 6])

    def test_accepts_complete_pinned_call_and_anchor_inventory(self):
        self.assertEqual(
            verifier.verify(disassembly_for()),
            (verifier.EXPECTED_QUERY_CALLERS, verifier.EXPECTED_WRAPPER_CALLERS))

    def test_rejects_unexpected_direct_caller(self):
        text = disassembly_for() + "\n  401000: e8 00 00 00 00 call 0x420960"
        with self.assertRaisesRegex(ValueError, "caller inventory differs"):
            verifier.verify(text)

    def test_rejects_changed_stack_provenance_anchor(self):
        anchors = dict(verifier.EXPECTED_INSTRUCTIONS)
        anchors[0x0042199E] = "push 0x1"
        with self.assertRaisesRegex(ValueError, "anchors differ"):
            verifier.verify(disassembly_for(anchors))

    def test_rejects_changed_dynamic_branch_gate(self):
        anchors = dict(verifier.EXPECTED_INSTRUCTIONS)
        anchors[0x00420D7F] = "test ecx,ecx"
        with self.assertRaisesRegex(ValueError, "anchors differ"):
            verifier.verify(disassembly_for(anchors))

    def test_rejects_unexpected_push_in_argument_setup(self):
        anchors = dict(verifier.EXPECTED_INSTRUCTIONS)
        anchors[0x004219A3] = "push eax"
        with self.assertRaisesRegex(ValueError, "argument push sequence differs"):
            verifier.verify(disassembly_for(anchors))

    def test_rejects_raw_pointer_literal(self):
        data = verifier.QUERY.to_bytes(4, "little")
        with self.assertRaisesRegex(ValueError, "raw address literal"):
            verifier.verify(disassembly_for(), data)

    def test_rejects_stack_cleanup_during_argument_setup(self):
        anchors = dict(verifier.EXPECTED_INSTRUCTIONS)
        anchors[0x004219A3] = "add esp,0x4"
        with self.assertRaisesRegex(ValueError, "stack-pointer adjustment"):
            verifier.verify(disassembly_for(anchors))

    def test_rejects_bulk_and_implicit_stack_changes(self):
        for instruction in ("pushad", "pushaw", "pusha", "pushfd", "pushfw",
                            "pushf", "popad", "popaw", "popa", "popfd", "popfw",
                            "popf", "enter 0x10,0x0", "leave"):
            with self.subTest(instruction=instruction):
                anchors = dict(verifier.EXPECTED_INSTRUCTIONS)
                anchors[0x004219A3] = instruction
                with self.assertRaisesRegex(ValueError, "stack-pointer adjustment"):
                    verifier.verify(disassembly_for(anchors))

    def test_objdump_receives_the_hash_verified_snapshot(self):
        source = b"pinned level-query executable"

        def inspect_snapshot(command, **kwargs):
            self.assertEqual(command[1:3], ["-d", "-Mintel"])
            self.assertTrue(command[-1].endswith("Drakan.exe"))
            with open(command[-1], "rb") as snapshot:
                self.assertEqual(snapshot.read(), source)
            return type("Result", (), {"stdout": "snapshot disassembly"})()

        with patch.object(verifier.subprocess, "run", side_effect=inspect_snapshot):
            self.assertEqual(verifier.disassemble_snapshot(source), "snapshot disassembly")


if __name__ == "__main__":
    unittest.main()
