import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_srsc_selector_0200_key as key_trace


def disassembly(instructions):
    return "\n".join(f" {address:x}: 90 {instruction}" for address, instruction in instructions.items())


class VerifySrscSelector0200KeyTests(unittest.TestCase):
    def test_accepts_and_mutations_reject_all_anchors(self):
        self.assertEqual(key_trace.verify_anchors(disassembly(key_trace.EXPECTED_INSTRUCTIONS)), len(key_trace.EXPECTED_INSTRUCTIONS))
        for address, wanted in key_trace.EXPECTED_INSTRUCTIONS.items():
            changed = dict(key_trace.EXPECTED_INSTRUCTIONS)
            changed[address] = wanted + " ; changed"
            with self.subTest(address=hex(address)), self.assertRaisesRegex(ValueError, f"0x{address:08x}"):
                key_trace.verify_anchors(disassembly(changed))

    def test_checks_exact_direct_caller_set_and_no_jumps(self):
        self.assertEqual(key_trace.verify_callers(" 4246ba: 90 call 0x4246d0"), key_trace.EXPECTED_CALLERS)
        with self.assertRaisesRegex(ValueError, "missing"):
            key_trace.verify_callers("")
        with self.assertRaisesRegex(ValueError, "unexpected"):
            key_trace.verify_callers(" 4246ba: 90 call 0x4246d0\n 424700: 90 call 0x4246d0")
        with self.assertRaisesRegex(ValueError, "direct jumps"):
            key_trace.verify_callers(" 4246ba: 90 call 0x4246d0\n 424700: 90 jmp 0x4246d0")

    def test_objdump_uses_one_hash_verified_snapshot(self):
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
                return subprocess.CompletedProcess(command, 0, disassembly(key_trace.EXPECTED_INSTRUCTIONS), "")

            with patch.object(key_trace, "EXPECTED_SHA256", hashlib.sha256(payload).hexdigest()), \
                    patch.object(key_trace.subprocess, "run", fake_objdump):
                result = key_trace.verify_binary(source)
        self.assertEqual(len(set(snapshots)), 1)
        self.assertEqual(len(snapshots), len(key_trace.RANGES) + 1)
        self.assertEqual(result["instruction_anchors"], len(key_trace.EXPECTED_INSTRUCTIONS))

    def test_rejects_stale_hash_before_disassembly(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Drakan.exe"
            source.write_bytes(b"stale executable")
            with patch.object(key_trace, "EXPECTED_SHA256", "0" * 64), patch.object(key_trace.subprocess, "run") as run:
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
