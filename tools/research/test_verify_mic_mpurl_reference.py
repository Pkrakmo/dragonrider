import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_mic_mpurl_reference as verifier


def disassembly(instructions):
    return "\n".join(f" {address:x}: 90 {value}"
                     for address, value in instructions.items())


class VerifyMicMpurlReferenceTests(unittest.TestCase):
    def make_sources(self, directory):
        mic = bytearray(b"x" * 0x35000)
        mic[verifier.MIC_NAME_OFFSET:verifier.MIC_NAME_OFFSET + len(verifier.MIC_NAME)] = verifier.MIC_NAME
        mic[verifier.MIC_LOG_OFFSET:verifier.MIC_LOG_OFFSET + len(verifier.MIC_LOG)] = verifier.MIC_LOG
        drakan = b"retail executable without filename"
        mic_path = Path(directory) / "mIC.exe"
        drakan_path = Path(directory) / "Drakan.exe"
        mic_path.write_bytes(mic)
        drakan_path.write_bytes(drakan)
        return mic_path, drakan_path, bytes(mic), drakan

    def test_verifies_instruction_anchors(self):
        self.assertEqual(
            verifier.verify_anchors(disassembly(verifier.EXPECTED_INSTRUCTIONS)),
            len(verifier.EXPECTED_INSTRUCTIONS),
        )

    def test_rejects_mutated_instruction(self):
        instructions = dict(verifier.EXPECTED_INSTRUCTIONS)
        instructions[0x00402B80] = "call 0x424249"
        with self.assertRaisesRegex(ValueError, "0x00402b80"):
            verifier.verify_anchors(disassembly(instructions))

    def test_resolves_anchored_import_to_ordinal(self):
        report = """\
DLL Name: MFC42.DLL
 00042b58    924  <none> <none>
"""
        self.assertEqual(verifier.parse_import_ordinal(report, 0x42B58, "MFC42.dll"), 924)

    def test_rejects_wrong_dll_for_anchored_import(self):
        report = "DLL Name: KERNEL32.dll\n 00042b58 924 <none> <none>\n"
        with self.assertRaisesRegex(ValueError, "unexpected DLL"):
            verifier.parse_import_ordinal(report, 0x42B58, "MFC42.dll")

    def test_objdump_receives_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            mic_path, drakan_path, mic, drakan = self.make_sources(directory)
            observed = []

            def fake_objdump(command, **kwargs):
                snapshot = Path(command[-1])
                self.assertNotEqual(snapshot, mic_path)
                self.assertEqual(snapshot.read_bytes(), mic)
                observed.append(snapshot)
                output = ("DLL Name: MFC42.DLL\n 00042b58 924 <none> <none>\n"
                          if "-p" in command else disassembly(verifier.EXPECTED_INSTRUCTIONS))
                return subprocess.CompletedProcess(
                    command, 0, output, ""
                )

            with patch.object(verifier, "MIC_SHA256", hashlib.sha256(mic).hexdigest()), \
                 patch.object(verifier, "DRAKAN_SHA256", hashlib.sha256(drakan).hexdigest()), \
                 patch.object(verifier.subprocess, "run", fake_objdump):
                result = verifier.verify(mic_path, drakan_path)
            self.assertEqual(result["instruction_anchors"], len(verifier.EXPECTED_INSTRUCTIONS))
            self.assertEqual(result["call_target_import"], "MFC42.DLL ordinal 924")
            self.assertEqual(len(observed), 3)

    def test_rejects_stale_hash_before_disassembly(self):
        with tempfile.TemporaryDirectory() as directory:
            mic_path, drakan_path, _, _ = self.make_sources(directory)
            with patch.object(verifier, "MIC_SHA256", "0" * 64), \
                 patch.object(verifier.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unexpected mIC.exe SHA-256"):
                    verifier.verify(mic_path, drakan_path)
            run.assert_not_called()

    def test_rejects_symlinked_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            mic_path, drakan_path, mic, drakan = self.make_sources(directory)
            link = Path(directory) / "mIC-link.exe"
            link.symlink_to(mic_path)
            with patch.object(verifier, "MIC_SHA256", hashlib.sha256(mic).hexdigest()), \
                 patch.object(verifier, "DRAKAN_SHA256", hashlib.sha256(drakan).hexdigest()), \
                 patch.object(verifier.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "singly linked regular file"):
                    verifier.verify(link, drakan_path)
            run.assert_not_called()

    def test_rejects_filename_reference_in_retail_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            mic_path, drakan_path, mic, _ = self.make_sources(directory)
            for drakan in (b"contains mpurl.dat", "contains mpurl.dat".encode("utf-16le")):
                with self.subTest(encoding="utf16le" if b"\0" in drakan else "ascii"):
                    drakan_path.write_bytes(drakan)
                    with patch.object(verifier, "MIC_SHA256", hashlib.sha256(mic).hexdigest()), \
                         patch.object(verifier, "DRAKAN_SHA256", hashlib.sha256(drakan).hexdigest()), \
                         patch.object(verifier.subprocess, "run") as run:
                        with self.assertRaisesRegex(ValueError, "unexpected mpurl.dat"):
                            verifier.verify(mic_path, drakan_path)
                    run.assert_not_called()

    def test_rejects_csv_reference_in_retail_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            mic_path, drakan_path, mic, _ = self.make_sources(directory)
            for name in verifier.DRAKAN_CSV_NAMES:
                for drakan in (b"contains " + name,
                               b"contains " + name.decode().encode("utf-16le")):
                    drakan_path.write_bytes(drakan)
                    with patch.object(verifier, "MIC_SHA256", hashlib.sha256(mic).hexdigest()), \
                         patch.object(verifier, "DRAKAN_SHA256", hashlib.sha256(drakan).hexdigest()), \
                         patch.object(verifier.subprocess, "run") as run:
                        with self.assertRaisesRegex(ValueError, "Mplayer CSV"):
                            verifier.verify(mic_path, drakan_path)
                    run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
