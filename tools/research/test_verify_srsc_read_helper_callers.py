"""Synthetic tests for direct calls to the SRSC bounded-read helper."""

import unittest
from unittest.mock import patch

import verify_srsc_read_helper_callers as verifier
from verify_srsc_read_helper_callers import (callers, classify_request_sizes,
                                             instructions, jumps, raw_pointer_offsets)


class SrscReadHelperCallerTests(unittest.TestCase):
    def test_extracts_direct_calls_only(self):
        text = """
  40be48:\te8 83 34 05 00       \tcall   0x45f2d0
  40be49:\te8 82 34 05 00       \tcall   0x45f2d1
  40be4a:\tff 50 08             \tcall   DWORD PTR [eax+0x8]
  comment: call 0x45f2d0
"""
        self.assertEqual(callers(text), {0x40be48})

    def test_identifies_direct_unconditional_jumps_separately(self):
        text = """
  40be48:\te9 83 34 05 00       \tjmp    0x45f2d0
  40be49:\te8 82 34 05 00       \tcall   0x45f2d0
  40be4a:\tff e0                \tjmp    eax
"""
        self.assertEqual(jumps(text), {0x40be48})
        self.assertEqual(callers(text), {0x40be49})

    def test_other_target_has_no_references(self):
        self.assertEqual(callers("  401000:\te8 00 00 00 00       \tcall 0x402000\n"), set())

    def test_finds_exact_raw_absolute_pointer_literals(self):
        pointer = (0x0045F2D0).to_bytes(4, "little")
        self.assertEqual(raw_pointer_offsets(b"xx" + pointer + b"yy" + pointer), [2, 8])

    def test_normalizes_bounded_instruction_anchors(self):
        text = """
  45f2fc:\t8b 07                \tmov eax,DWORD PTR [edi]
  45f2fe:\t3b c1                \tcmp eax,ecx
"""
        self.assertEqual(instructions(text), {
            0x45f2fc: "mov eax,DWORD PTR [edi]",
            0x45f2fe: "cmp eax,ecx",
        })

    def test_classifies_only_size_pointer_local_constant_stores(self):
        text = """
  401000: 8d 4c 24 10          lea ecx,[esp+0x10]
  401004: 51                   push ecx
  401005: 52                   push edx
  401006: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  40100e: e8 bd e2 05 00       call 0x45f2d0
  402000: 83 ec 20             sub esp,0x20
  402003: 8d 44 24 04          lea eax,[esp+0x4]
  402007: 50                   push eax
  402008: 53                   push ebx
  402009: c7 44 24 0c 10 00 00 00 mov DWORD PTR [esp+0xc],0x10
  402011: e8 b7 d2 05 00       call 0x45f2d0
  403000: 8d 4c 24 10          lea ecx,[esp+0x10]
  403004: 51                   push ecx
  403005: 52                   push edx
  403006: 89 44 24 18          mov DWORD PTR [esp+0x18],eax
  40300a: e8 c1 c2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {0x40100e: 6, 0x402011: 16})
        self.assertEqual(unknown, {0x40300a})

    def test_classifies_register_size_from_same_block_immediate_assignment(self):
        text = """
  4156b8: 8d 4c 24 10          lea ecx,[esp+0x10]
  4156bc: 8d 57 14             lea edx,[edi+0x14]
  4156bf: bb 04 00 00 00       mov ebx,0x4
  4156c4: 51                   push ecx
  4156c5: 52                   push edx
  4156c6: 8b ce                mov ecx,esi
  4156c8: 89 5c 24 18          mov DWORD PTR [esp+0x18],ebx
  4156cc: e8 ff 9b 04 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {0x4156cc: 4})
        self.assertEqual(unknown, set())

    def test_register_size_trace_rejects_clobbers_after_immediate(self):
        for instruction, encoding in (
                ("mov ebx,eax", "89 c3"),
                ("mov bl,0x2", "b3 02"),
                ("imul ebx,esi", "0f af de")):
            with self.subTest(instruction=instruction):
                text = f"""
  4156b8: 8d 4c 24 10          lea ecx,[esp+0x10]
  4156bc: 8d 57 14             lea edx,[edi+0x14]
  4156bf: bb 04 00 00 00       mov ebx,0x4
  4156c4: 51                   push ecx
  4156c5: 52                   push edx
  4156c6: 8b ce                mov ecx,esi
  4156c8: {encoding}          {instruction}
  4156ca: 89 5c 24 18          mov DWORD PTR [esp+0x18],ebx
  4156ce: e8 fd 9b 04 00       call 0x45f2d0
"""
                sizes, unknown = classify_request_sizes(text)
                self.assertEqual(sizes, {})
                self.assertEqual(unknown, {0x4156ce})

    def test_register_size_trace_rejects_popped_argument(self):
        text = """
  416000: 8d 4c 24 10          lea ecx,[esp+0x10]
  416004: 51                   push ecx
  416005: 52                   push edx
  416006: 58                   pop eax
  416007: c7 44 24 14 06 00 00 00 mov DWORD PTR [esp+0x14],0x6
  41600f: e8 bc 92 04 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x41600f})

    def test_register_size_trace_rejects_argument_slot_overwrite(self):
        text = """
  418000: 8d 4c 24 10          lea ecx,[esp+0x10]
  418004: 51                   push ecx
  418005: 52                   push edx
  418006: c7 44 24 04 00 20 40 00 mov DWORD PTR [esp+0x4],0x402000
  41800e: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  418016: e8 b5 72 04 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x418016})

    def test_register_size_trace_rejects_esp_alias_argument_slot_overwrite(self):
        text = """
  418100: 8d 4c 24 10          lea ecx,[esp+0x10]
  418104: 51                   push ecx
  418105: 52                   push edx
  418106: 8d 44 24 04          lea eax,[esp+0x4]
  41810a: c7 00 00 20 40 00    mov DWORD PTR [eax],0x402000
  418110: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  418118: e8 b3 71 04 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x418118})

    def test_register_size_trace_rejects_bypassed_esp_alias_definition(self):
        text = """
  400000: e9 ff 0f 00 00       jmp 0x401004
  400005: c3                   ret
  401000: 8d 44 24 20          lea eax,[esp+0x20]
  401004: 8d 4c 24 10          lea ecx,[esp+0x10]
  401008: 51                   push ecx
  401009: 52                   push edx
  40100a: c7 00 00 20 40 00    mov DWORD PTR [eax],0x402000
  401010: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  401018: e8 b3 e2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x401018})

    def test_register_size_trace_rejects_16_bit_argument_push(self):
        text = """
  418200: 8d 4c 24 10          lea ecx,[esp+0x10]
  418204: 51                   push ecx
  418205: 66 50                push ax
  418207: c7 44 24 16 06 00 00 00 mov DWORD PTR [esp+0x16],0x6
  41820f: e8 bc 70 04 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x41820f})

    def test_register_size_trace_rejects_size_store_over_argument(self):
        text = """
  418300: 8d 0c 24             lea ecx,[esp]
  418303: 83 c4 04             add esp,0x4
  418306: 51                   push ecx
  418307: 52                   push edx
  418308: c7 44 24 04 06 00 00 00 mov DWORD PTR [esp+0x4],0x6
  418310: e8 bb 6f 04 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x418310})

    def test_register_size_trace_rejects_branch_around_definition(self):
        text = """
  417000: 75 05                jne 0x417007
  417002: bb 04 00 00 00       mov ebx,0x4
  417007: 8d 4c 24 10          lea ecx,[esp+0x10]
  41700b: 51                   push ecx
  41700c: 52                   push edx
  41700d: 89 5c 24 18          mov DWORD PTR [esp+0x18],ebx
  417011: e8 ba 82 04 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x417011})

    def test_size_trace_stops_at_clobber_and_control_flow(self):
        clobbered = """
  404000: 8d 4c 24 10          lea ecx,[esp+0x10]
  404004: 89 d9                mov ecx,ebx
  404006: 51                   push ecx
  404007: 52                   push edx
  404008: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  404010: e8 bb d2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(clobbered)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x404010})

        implicit_clobber = """
  404100: 8d 74 24 10          lea esi,[esp+0x10]
  404104: a7                   cmpsd
  404105: 56                   push esi
  404106: 52                   push edx
  404107: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  40410f: e8 bc d1 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(implicit_clobber)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x40410f})

        cmpxchg_clobber = """
  404200: 8d 44 24 10          lea eax,[esp+0x10]
  404204: 0f b1 d1             cmpxchg ecx,edx
  404207: 50                   push eax
  404208: 52                   push edx
  404209: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  404211: e8 ba d0 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(cmpxchg_clobber)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x404211})

    def test_size_trace_rejects_partial_register_and_xchg_clobbers(self):
        for mutation, encoding in (
                ("mov cl,0x0", "b1 00"),
                ("xchg eax,ecx", "87 c1"),
                ("xchg ecx,eax", "87 c8")):
            with self.subTest(mutation=mutation):
                text = f"""
  406000: 8d 4c 24 10          lea ecx,[esp+0x10]
  406004: {encoding}                {mutation}
  406006: 51                   push ecx
  406007: 52                   push edx
  406008: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  406010: e8 bb d2 05 00       call 0x45f2d0
"""
                sizes, unknown = classify_request_sizes(text)
                self.assertEqual(sizes, {})
                self.assertEqual(unknown, {0x406010})

    def test_loop_is_a_control_flow_boundary(self):
        text = """
  407000: 8d 4c 24 10          lea ecx,[esp+0x10]
  407004: e2 01                loop 0x407007
  407006: 51                   push ecx
  407007: 52                   push edx
  407008: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  407010: e8 bb d2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x407010})

    def test_branch_into_argument_setup_makes_trace_unknown(self):
        text = """
  400000: e9 ff 5f 00 00       jmp 0x406004
  400005: c3                   ret
  406000: 8d 4c 24 10          lea ecx,[esp+0x10]
  406004: 51                   push ecx
  406005: 52                   push edx
  406006: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  40600e: e8 bd e2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x40600e})

    def test_missing_instruction_bytes_make_trace_unknown(self):
        text = """
  40a000: 8d 4c 24 10          lea ecx,[esp+0x10]
  40a008: 51                   push ecx
  40a009: 52                   push edx
  40a00a: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  40a012: e8 b9 d2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x40a012})

        missing_call_bytes = """
  40a100: 8d 4c 24 10          lea ecx,[esp+0x10]
  40a104: 51                   push ecx
  40a105: 52                   push edx
  40a106: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  40a110: e8 b9 d2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(missing_call_bytes)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x40a110})

    def test_memory_write_after_size_constant_makes_trace_unknown(self):
        for instruction, encoding, next_address in (
                ("mov WORD PTR [esp+0x18],ax", "66 89 44 24 18", 0x40b013),
                ("mov DWORD PTR [eax],ecx", "89 08", 0x40b010)):
            with self.subTest(instruction=instruction):
                text = f"""
  40b000: 8d 4c 24 10          lea ecx,[esp+0x10]
  40b004: 51                   push ecx
  40b005: 52                   push edx
  40b006: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  40b00e: {encoding} {instruction}
  {next_address:x}: e8 b9 d2 05 00 call 0x45f2d0
"""
                sizes, unknown = classify_request_sizes(text)
                self.assertEqual(sizes, {})
                self.assertEqual(unknown, {next_address})

    def test_rep_prefixed_string_instructions_make_trace_unknown(self):
        pointer_update = """
  40c000: 8d 74 24 10          lea esi,[esp+0x10]
  40c004: f3 a5                rep movsd DWORD PTR es:[edi],DWORD PTR ds:[esi]
  40c006: 56                   push esi
  40c007: 52                   push edx
  40c008: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  40c010: e8 bb d2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(pointer_update)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x40c010})

        memory_write = """
  40d000: 8d 4c 24 10          lea ecx,[esp+0x10]
  40d004: 51                   push ecx
  40d005: 52                   push edx
  40d006: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  40d00e: f3 a5                rep movsd DWORD PTR es:[edi],DWORD PTR ds:[esi]
  40d010: e8 bb d2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(memory_write)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x40d010})

    def test_stack_trace_models_operand_size_and_rejects_esp_xchg(self):
        adjusted = """
  408000: 8d 4c 24 10          lea ecx,[esp+0x10]
  408004: 66 50                push ax
  408006: 66 58                pop ax
  408008: 51                   push ecx
  408009: 52                   push edx
  40800a: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  408012: e8 b9 d2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(adjusted)
        self.assertEqual(sizes, {0x408012: 6})
        self.assertEqual(unknown, set())

        changed_esp = """
  409000: 8d 4c 24 10          lea ecx,[esp+0x10]
  409004: 87 e0                xchg eax,esp
  409006: 51                   push ecx
  409007: 52                   push edx
  409008: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  409010: e8 bb d2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(changed_esp)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x409010})

    def test_size_trace_refuses_unmodeled_stack_pointer_changes(self):
        text = """
  405000: 8d 4c 24 10          lea ecx,[esp+0x10]
  405004: 51                   push ecx
  405005: 52                   push edx
  405006: 89 ec                mov esp,ebp
  405008: c7 44 24 18 06 00 00 00 mov DWORD PTR [esp+0x18],0x6
  405010: e8 bb d2 05 00       call 0x45f2d0
"""
        sizes, unknown = classify_request_sizes(text)
        self.assertEqual(sizes, {})
        self.assertEqual(unknown, {0x405010})

    def test_verifies_selected_caller_request_sizes_and_loop_stride(self):
        rows = [
            f" {address:x}: 90 {instruction}"
            for address, instruction in (
                verifier.EXPECTED_INSTRUCTIONS | verifier.EXPECTED_CALLER_INSTRUCTIONS |
                verifier.EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS |
                verifier.EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS |
                verifier.EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS
            ).items()
        ]
        text = "\n".join(rows)
        verifier.verify_instruction_anchors(text)
        for original, replacement in (
            ("mov DWORD PTR [esp+0x18],0x6", "mov DWORD PTR [esp+0x18],0x8"),
            ("shl eax,1", "shl eax,2"),
            ("add eax,0x8", "add eax,0x4"),
            ("mov ecx,DWORD PTR [edi+0x18]", "test eax,eax"),
            ("test esi,esi", "test eax,eax"),
        ):
            with self.subTest(original=original):
                changed = text.replace(original, replacement)
                with self.assertRaisesRegex(ValueError, "anchors differ"):
                    verifier.verify_instruction_anchors(changed)

    def test_variable_request_formulas_are_covered_by_mutation_sensitive_anchors(self):
        anchor_addresses = set(verifier.EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS)
        for call_address, entry in verifier.EXPECTED_VARIABLE_REQUEST_FORMULAS.items():
            with self.subTest(callsite=hex(call_address)):
                self.assertIn(call_address, entry["anchors"])
                self.assertTrue(set(entry["anchors"]) <= anchor_addresses)

        rows = [
            f" {address:x}: 90 {instruction}"
            for address, instruction in (
                verifier.EXPECTED_INSTRUCTIONS | verifier.EXPECTED_CALLER_INSTRUCTIONS |
                verifier.EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS |
                verifier.EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS |
                verifier.EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS
            ).items()
        ]
        baseline = "\n".join(rows)
        verifier.verify_instruction_anchors(baseline)
        for address in verifier.EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS:
            with self.subTest(anchor=hex(address)):
                mutated_rows = [
                    f" {row_address:x}: 90 {'invalid mutation' if row_address == address else instruction}"
                    for row_address, instruction in (
                        verifier.EXPECTED_INSTRUCTIONS | verifier.EXPECTED_CALLER_INSTRUCTIONS |
                        verifier.EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS |
                        verifier.EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS |
                        verifier.EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS
                    ).items()
                ]
                mutated = "\n".join(mutated_rows)
                with self.assertRaisesRegex(ValueError, "anchors differ"):
                    verifier.verify_instruction_anchors(mutated)

    def test_october_24_followup_request_expressions_are_explicit(self):
        expected = {
            0x00424ADF: "48 (immediate size-slot store)",
            0x00424B86: "2 (immediate size-slot store)",
            0x004254E1: "2 (EDI=2 retained across read/skip helpers)",
            0x00425618: "4 (ESI=4 retained across helper)",
            0x0042562C: "4 (ESI=4 retained across helper)",
            0x00425C35: "48 (EDI=0x30 retained across helper)",
            0x00433279: "DWORD [esi+0x22]",
            0x004332C2: "DWORD [esp+0x10]",
            0x00435737: "4 * (DWORD [esp+0x18] & 0xffff)",
            0x00435C13: "DWORD [esp+0x1c]",
            0x00435D1C: "DWORD [esp+0x30]",
            0x0042603C: "16 * (DWORD [esi+0x8] + EBP)",
            0x0042BBA1: "DWORD [esp+0x28]",
            0x0042BCB7: "DWORD [esp+0x28]",
            0x00437782: "4 * DWORD [esp+0x20]",
            0x0043779D: "2 * DWORD [esp+0x18]",
            0x0045F47E: "min(DWORD [esp+0x10] & 0xffff, DWORD [esp+0x1c])",
            0x004156F3: "4 (EBX=4 retained across bounded-read, skip, and word-reader helpers)",
            0x0043143F: "12 (EBX=0xc retained across preceding bounded read)",
            0x00437035: "4 (ESI=4 retained on successful preceding read)",
            0x004376A9: "4 (EBP=4 retained across bounded read and 0x409db0)",
            0x004376D4: "4 (EBP=4 retained across bounded read and 0x409db0 calls)",
            0x004223BA: ("conditional when [esp+0x38] <= 0: 26*A*C + "
                          "4*(A+1)*(C+1); EBX retained across GlobalAlloc/GlobalLock"),
            0x0042B293: ("min(capacity DWORD [esp+0x1c]@0x42b1e4, "
                          "record DWORD [base+26*index+0x6]); EDI preserved by 0x45f270"),
            0x0042EEEF: "DWORD [0x0047d050 + 4*(DWORD [esp+0x20] & 0xffff)]",
            0x0040BE48: ("DWORD [esp+0x14] (local targeted as the buffer by "
                          "0x45f370 at 0x40bdd9)"),
        }
        actual = {
            address: verifier.EXPECTED_VARIABLE_REQUEST_FORMULAS[address]["formula"]
            for address in expected
        }
        self.assertEqual(actual, expected)

    def test_two_word_selector_lookup_has_mutation_sensitive_anchors(self):
        combined = (verifier.EXPECTED_INSTRUCTIONS | verifier.EXPECTED_CALLER_INSTRUCTIONS |
                    verifier.EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS |
                    verifier.EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS |
                    verifier.EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS)
        baseline = "\n".join(
            f" {address:x}: 90 {instruction}" for address, instruction in combined.items())
        verifier.verify_instruction_anchors(baseline)
        selector_path_anchors = (verifier.EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS |
                                  verifier.EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS)
        for address in selector_path_anchors:
            with self.subTest(anchor=hex(address)):
                mutated = "\n".join(
                    f" {row_address:x}: 90 "
                    f"{'invalid mutation' if row_address == address else instruction}"
                    for row_address, instruction in combined.items())
                with self.assertRaisesRegex(ValueError, "anchors differ"):
                    verifier.verify_instruction_anchors(mutated)

    def test_selector_path_direct_caller_sets_are_exact(self):
        self.assertEqual(verifier.EXPECTED_SELECTOR_CALLERS, {
            0x00415360: {0x00415345, 0x0041682E, 0x00416BA8, 0x00417450,
                         0x0041801F, 0x00418B24},
            0x004155D0: {0x0041538D},
            0x0045FA10: {0x00415668, 0x0042476E, 0x00433030, 0x0045F24D},
        })
        lines = []
        for target, callers in verifier.EXPECTED_SELECTOR_CALLERS.items():
            for address in callers:
                lines.append(f" {address:x}: e8 00 00 00 00 call 0x{target:x}")
        self.assertEqual(
            verifier.verify_selector_callers("\n".join(lines)),
            verifier.EXPECTED_SELECTOR_CALLERS,
        )
        missing = lines[:-1]
        with self.assertRaisesRegex(ValueError, "direct callers"):
            verifier.verify_selector_callers("\n".join(missing))
        unexpected = lines + [" 401234: e8 00 00 00 00 call 0x45fa10"]
        with self.assertRaisesRegex(ValueError, "direct callers"):
            verifier.verify_selector_callers("\n".join(unexpected))

    def test_new_register_constant_callers_have_mutation_sensitive_anchors(self):
        callers_added = {
            0x004156CC, 0x004254B5, 0x00425604, 0x00425BFD,
            0x00425D66, 0x0042B7E1, 0x00431427, 0x00437012,
            0x0043767E,
        }
        expected = verifier.EXPECTED_CALLER_INSTRUCTIONS
        anchors = {
            address: instruction for address, instruction in expected.items()
            if any(call - 0x30 <= address <= call for call in callers_added)
        }
        baseline = "\n".join(
            f" {address:x}: 90 {instruction}"
            for address, instruction in (
                verifier.EXPECTED_INSTRUCTIONS | expected |
                verifier.EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS |
                    verifier.EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS |
                    verifier.EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS
            ).items())
        verifier.verify_instruction_anchors(baseline)
        for address in anchors:
            with self.subTest(anchor=hex(address)):
                rows = [
                    f" {row_address:x}: 90 {'invalid mutation' if row_address == address else instruction}"
                    for row_address, instruction in (
                        verifier.EXPECTED_INSTRUCTIONS | expected |
                        verifier.EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS |
                        verifier.EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS |
                        verifier.EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS
                    ).items()
                ]
                with self.assertRaisesRegex(ValueError, "anchors differ"):
                    verifier.verify_instruction_anchors("\n".join(rows))

    def test_objdump_receives_the_verified_snapshot(self):
        original = b"verified executable bytes"

        def inspect_snapshot(command, **kwargs):
            self.assertEqual(command[1:3], ["-d", "-Mintel"])
            self.assertTrue(command[-1].endswith("Drakan.exe"))
            with open(command[-1], "rb") as snapshot:
                self.assertEqual(snapshot.read(), original)
            return type("Result", (), {"stdout": "pinned disassembly"})()

        with patch.object(verifier.subprocess, "run", side_effect=inspect_snapshot):
            self.assertEqual(verifier.disassemble_snapshot(original), "pinned disassembly")


if __name__ == "__main__":
    unittest.main()
