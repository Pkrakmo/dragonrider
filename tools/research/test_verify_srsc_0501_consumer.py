import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_srsc_0501_consumer as consumer
from verify_srsc_0501_consumer import EXPECTED_INSTRUCTIONS, verify_anchors


def disassembly(instructions):
    return "\n".join(
        f" {address:x}: 90 {instruction}"
        for address, instruction in instructions.items()
    )


class VerifySrsc0501Consumer(unittest.TestCase):
    def test_verifies_hash_pinned_scale_constant_bytes(self):
        data = bytearray(consumer.SCALE_CONSTANT_FILE_OFFSET + 4)
        data[consumer.SCALE_CONSTANT_FILE_OFFSET:
             consumer.SCALE_CONSTANT_FILE_OFFSET + 4] = consumer.SCALE_CONSTANT_BYTES
        self.assertEqual(consumer.verify_scale_constant(data), 2048.0)
        data[consumer.SCALE_CONSTANT_FILE_OFFSET] = 1
        with self.assertRaisesRegex(ValueError, "scale constant"):
            consumer.verify_scale_constant(data)

    def test_accepts_all_pinned_instruction_anchors(self):
        self.assertEqual(
            verify_anchors(disassembly(EXPECTED_INSTRUCTIONS)),
            len(EXPECTED_INSTRUCTIONS),
        )

    def test_rejects_missing_anchor(self):
        instructions = dict(EXPECTED_INSTRUCTIONS)
        del instructions[0x00415829]
        with self.assertRaisesRegex(ValueError, "0x00415829"):
            verify_anchors(disassembly(instructions))

    def test_rejects_mutated_anchor(self):
        for address, wanted in EXPECTED_INSTRUCTIONS.items():
            with self.subTest(address=hex(address)):
                instructions = dict(EXPECTED_INSTRUCTIONS)
                instructions[address] = wanted + " ; changed"
                with self.assertRaisesRegex(ValueError, f"0x{address:08x}"):
                    verify_anchors(disassembly(instructions))

    def test_rejects_wrong_branch_target(self):
        instructions = dict(EXPECTED_INSTRUCTIONS)
        instructions[0x0041584A] = "jl 0x415820"
        with self.assertRaisesRegex(ValueError, "0x0041584a"):
            verify_anchors(disassembly(instructions))

    def test_objdump_receives_the_hash_verified_snapshot_for_each_window(self):
        payload = bytearray(consumer.SCALE_CONSTANT_FILE_OFFSET + 4)
        payload[consumer.SCALE_CONSTANT_FILE_OFFSET:
                consumer.SCALE_CONSTANT_FILE_OFFSET + 4] = consumer.SCALE_CONSTANT_BYTES
        payload = bytes(payload)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Drakan.exe"
            source.write_bytes(payload)
            observed_snapshots = []

            def inspect_snapshot(command, **kwargs):
                snapshot = Path(command[-1])
                self.assertNotEqual(snapshot, source)
                self.assertEqual(snapshot.read_bytes(), payload)
                observed_snapshots.append(snapshot)
                return subprocess.CompletedProcess(
                    command, 0, disassembly(EXPECTED_INSTRUCTIONS), ""
                )

            with patch.object(consumer, "EXPECTED_SHA256",
                              hashlib.sha256(payload).hexdigest()), \
                    patch.object(consumer, "EXPECTED_SIZE", len(payload)), \
                    patch.object(consumer.subprocess, "run", inspect_snapshot):
                result = consumer.verify_binary(source)
        self.assertEqual(len(observed_snapshots), len(consumer.DISASSEMBLY_RANGES))
        self.assertEqual(len(set(observed_snapshots)), 1)
        self.assertEqual(result["instruction_anchors"], len(EXPECTED_INSTRUCTIONS))

    def test_rejects_stale_hash_before_running_objdump(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Drakan.exe"
            source.write_bytes(b"stale executable")
            with patch.object(consumer, "EXPECTED_SHA256", "0" * 64), \
                    patch.object(consumer, "EXPECTED_SIZE", len(b"stale executable")), \
                    patch.object(consumer.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unexpected executable SHA-256"):
                    consumer.verify_binary(source)
            run.assert_not_called()

    def test_rejects_unexpected_size_before_hash_or_objdump(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Drakan.exe"
            source.write_bytes(b"wrong size")
            with patch.object(consumer, "EXPECTED_SIZE", 100), \
                    patch.object(Path, "open") as open_file, \
                    patch.object(consumer.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unexpected executable size"):
                    consumer.verify_binary(source)
            open_file.assert_not_called()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
