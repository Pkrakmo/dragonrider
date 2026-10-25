"""Synthetic tests for hash-pinned gizmo CSV filename call anchors."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_gizmo_csv_references as verifier


def disassembly(instructions):
    return "\n".join(f" {address:x}: 90 {value}"
                     for address, value in instructions.items())


class VerifyGizmoCsvReferencesTests(unittest.TestCase):
    def make_binary(self, directory):
        data = bytearray(b"x" * verifier.EXPECTED_SIZE)
        for filename, (offset, _) in verifier.LITERALS.items():
            encoded = filename.encode("ascii") + b"\0"
            data[offset:offset + len(encoded)] = encoded
        for address, value in ((0x100273B0, b"wb\0"),
                               (0x100273B4, b"%s\\%s\0")):
            offset = 0x25800 + (address - 0x10027000)
            data[offset:offset + len(value)] = value
        path = Path(directory) / "gizmo.ocx"
        path.write_bytes(data)
        return path, bytes(data)

    def test_verifies_exact_instruction_anchors(self):
        self.assertEqual(verifier.verify_anchors(
            disassembly(verifier.EXPECTED_INSTRUCTIONS)),
            len(verifier.EXPECTED_INSTRUCTIONS))

    def test_rejects_mutated_anchor(self):
        instructions = dict(verifier.EXPECTED_INSTRUCTIONS)
        instructions[0x10016F87] = "call dword ptr ds:0x1004e160"
        with self.assertRaisesRegex(ValueError, "10016f87"):
            verifier.verify_anchors(disassembly(instructions))

    def test_resolves_import_at_anchored_iat(self):
        text = (" 0004e15c <none> 02ad sprintf\n 0004e134 <none> 0252 fopen\n"
                " 0004e13c <none> 0261 fwrite\n 0004e140 <none> 0247 fclose\n")
        self.assertEqual(verifier.verify_imports(text), {
            "sprintf": "sprintf", "fopen": "fopen",
            "fwrite": "fwrite", "fclose": "fclose"})
        with self.assertRaisesRegex(ValueError, "not sprintf"):
            verifier.verify_imports(text.replace("sprintf", "strcpy"))

    def test_verifies_data_section_mapping(self):
        output = "  2 .data 0000c000 10027000 10027000 00025800 2**2\n"
        self.assertEqual(verifier.verify_data_section(output), {
            "size": "0xc000", "virtual_address": "0x10027000",
            "file_offset": "0x25800"})
        with self.assertRaisesRegex(ValueError, "section mapping"):
            verifier.verify_data_section(output.replace("00025800", "00026000"))

    def test_objdump_receives_hash_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path, data = self.make_binary(directory)
            observed = []

            def fake_objdump(command, **kwargs):
                snapshot = Path(command[-1])
                self.assertNotEqual(snapshot, path)
                self.assertEqual(snapshot.read_bytes(), data)
                observed.append(snapshot)
                output = (" 0004e15c <none> 02ad sprintf\n"
                          " 0004e134 <none> 0252 fopen\n"
                          " 0004e13c <none> 0261 fwrite\n"
                          " 0004e140 <none> 0247 fclose\n" if "-p" in command
                          else disassembly(verifier.EXPECTED_INSTRUCTIONS))
                if "-h" in command:
                    output = "  2 .data 0000c000 10027000 10027000 00025800 2**2\n"
                return subprocess.CompletedProcess(command, 0, output, "")

            with patch.object(verifier, "EXPECTED_SHA256",
                              hashlib.sha256(data).hexdigest()), \
                 patch.object(verifier.subprocess, "run", fake_objdump):
                report = verifier.verify(path)
            self.assertEqual(report["instruction_anchors"],
                             len(verifier.EXPECTED_INSTRUCTIONS))
            self.assertEqual(report["import_names"], {
                "sprintf": "sprintf", "fopen": "fopen",
                "fwrite": "fwrite", "fclose": "fclose"})
            self.assertEqual(len(observed), 5)

    def test_rejects_bad_hash_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path, data = self.make_binary(directory)
            with patch.object(verifier, "EXPECTED_SHA256", "0" * 64), \
                 patch.object(verifier.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unexpected gizmo"):
                    verifier.verify(path)
            run.assert_not_called()
            link = Path(directory) / "linked.ocx"
            link.symlink_to(path)
            with patch.object(verifier, "EXPECTED_SHA256",
                              hashlib.sha256(data).hexdigest()), \
                 patch.object(verifier.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "singly linked"):
                    verifier.verify(link)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
