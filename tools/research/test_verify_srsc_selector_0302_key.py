import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_srsc_selector_0302_key as key_trace


def disassembly(instructions):
    return "\n".join(
        f" {address:x}: 90 {instruction}"
        for address, instruction in instructions.items()
    )


class VerifySrscSelector0302KeyTests(unittest.TestCase):
    def test_accepts_all_anchored_instructions(self):
        self.assertEqual(
            key_trace.verify_anchors(disassembly(key_trace.EXPECTED_INSTRUCTIONS)),
            len(key_trace.EXPECTED_INSTRUCTIONS),
        )

    def test_rejects_mutated_instruction_anchors(self):
        for address, wanted in key_trace.EXPECTED_INSTRUCTIONS.items():
            with self.subTest(address=hex(address)):
                changed = dict(key_trace.EXPECTED_INSTRUCTIONS)
                changed[address] = wanted + " ; changed"
                with self.assertRaisesRegex(ValueError, f"0x{address:08x}"):
                    key_trace.verify_anchors(disassembly(changed))

    def test_checks_exact_direct_callers_and_no_direct_jump_thunks(self):
        text = disassembly(key_trace.EXPECTED_INSTRUCTIONS)
        self.assertEqual(key_trace.verify_direct_callers(text), key_trace.EXPECTED_CALLERS)
        missing = dict(key_trace.EXPECTED_INSTRUCTIONS)
        del missing[0x00432A6B]
        with self.assertRaisesRegex(ValueError, "missing=.*432a6b"):
            key_trace.verify_direct_callers(disassembly(missing))
        extra = dict(key_trace.EXPECTED_INSTRUCTIONS)
        extra[0x0043F000] = "call 0x432f70"
        with self.assertRaisesRegex(ValueError, "unexpected=.*43f000"):
            key_trace.verify_direct_callers(disassembly(extra))
        jump = dict(key_trace.EXPECTED_INSTRUCTIONS)
        jump[0x0043F004] = "jmp 0x432f70"
        with self.assertRaisesRegex(ValueError, "direct jumps"):
            key_trace.verify_direct_callers(disassembly(jump))

    def test_objdump_receives_one_hash_verified_snapshot(self):
        payload = b"synthetic retail executable snapshot"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Drakan.exe"
            source.write_bytes(payload)
            snapshots = []

            def fake_objdump(command, **kwargs):
                snapshot = Path(command[-1])
                self.assertNotEqual(snapshot, source)
                self.assertEqual(snapshot.read_bytes(), payload)
                snapshots.append(snapshot)
                return subprocess.CompletedProcess(
                    command, 0, disassembly(key_trace.EXPECTED_INSTRUCTIONS), ""
                )

            with patch.object(key_trace, "EXPECTED_SHA256", hashlib.sha256(payload).hexdigest()), \
                    patch.object(key_trace.subprocess, "run", fake_objdump):
                result = key_trace.verify_binary(source)
        self.assertEqual(len(snapshots), len(key_trace.DISASSEMBLY_RANGES) + 1)
        self.assertEqual(len(set(snapshots)), 1)
        self.assertEqual(result["instruction_anchors"], len(key_trace.EXPECTED_INSTRUCTIONS))
        self.assertEqual(len(result["direct_callers_to_0x00432f70"]), 8)

    def test_rejects_stale_hash_before_disassembly(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Drakan.exe"
            source.write_bytes(b"stale executable")
            with patch.object(key_trace, "EXPECTED_SHA256", "0" * 64), \
                    patch.object(key_trace.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unexpected executable SHA-256"):
                    key_trace.verify_binary(source)
            run.assert_not_called()

    def test_rejects_symlinked_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.exe"
            link = root / "Drakan.exe"
            target.write_bytes(b"executable")
            link.symlink_to(target)
            with patch.object(key_trace.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "non-symlink"):
                    key_trace.verify_binary(link)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
