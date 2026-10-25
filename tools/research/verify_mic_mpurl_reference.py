#!/usr/bin/env python3
"""Verify hash-pinned static references to the Mplayer mpurl.dat filename."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile

MIC_SHA256 = "074398d985605edb5d88117ff47c1c4e17936f630ba998d15a7bfdc1f21f1e00"
DRAKAN_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"
DRAKAN_CSV_NAMES = (b"mphisto.csv", b"mpusage.csv")
MIC_NAME_OFFSET = 0x2D850
MIC_LOG_OFFSET = 0x34A68
MIC_NAME = b"mpurl.dat\0"
MIC_LOG = b"ICSEngine:: Done waiting for mpurl.dat (%s)\0"
DRAKAN_NAME = b"mpurl.dat"

EXPECTED_INSTRUCTIONS = {
    0x00402B6F: "push 0x42f650",
    0x00402B74: "lea ecx,[ebp-0x18]",
    0x00402B77: "push 0x42f64c",
    0x00402B7C: "push DWORD PTR [ebp+0x8]",
    0x00402B7F: "push ecx",
    0x00402B80: "call 0x424248",
    0x00424248: "jmp DWORD PTR ds:0x442b58",
    0x00402B85: "push eax",
    0x00402B86: "lea ecx,[ebp-0x10]",
    0x00402B8E: "call 0x424248",
}
DISASSEMBLY_RANGES = ((0x00402B6F, 0x00402B94), (0x00424248, 0x0042424E))
LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+(.+?)\s*$")
IMPORT_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+(\d+)\s+<none> <none>\s*$")


def parse_disassembly(text):
    result = {}
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if match:
            result[int(match.group(1), 16)] = " ".join(match.group(2).split()).lower()
    return result


def verify_anchors(text, expected=EXPECTED_INSTRUCTIONS):
    actual = parse_disassembly(text)
    for address, wanted in expected.items():
        if actual.get(address) != wanted.lower():
            raise ValueError(
                f"instruction anchor 0x{address:08x}: expected {wanted!r}, "
                f"got {actual.get(address)!r}"
            )
    return len(expected)


def parse_import_ordinal(text, iat_rva, expected_dll):
    """Return one ordinal import at a specific IAT RVA, or reject ambiguity."""
    current_dll = None
    matches = []
    for line in text.splitlines():
        dll_match = re.match(r"^\s*DLL Name:\s*(\S+)\s*$", line, re.IGNORECASE)
        if dll_match:
            current_dll = dll_match.group(1).lower()
            continue
        match = IMPORT_RE.match(line)
        if match and int(match.group(1), 16) == iat_rva:
            if current_dll == expected_dll.lower():
                matches.append(int(match.group(2), 10))
            else:
                raise ValueError("import address resolves under an unexpected DLL")
    if len(matches) != 1:
        raise ValueError("expected exactly one ordinal import at the anchored IAT RVA")
    return matches[0]


def read_verified(path, expected_hash, label):
    path = Path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"{label} input is not a singly linked regular file")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_hash:
        raise ValueError(f"unexpected {label} SHA-256: {digest}")
    return data, digest


def verify(mic_path, drakan_path, objdump="objdump"):
    mic, mic_hash = read_verified(mic_path, MIC_SHA256, "mIC.exe")
    drakan, drakan_hash = read_verified(drakan_path, DRAKAN_SHA256, "Drakan.exe")
    if mic[MIC_NAME_OFFSET:MIC_NAME_OFFSET + len(MIC_NAME)] != MIC_NAME:
        raise ValueError("mIC.exe mpurl.dat literal differs at pinned file offset")
    if mic[MIC_LOG_OFFSET:MIC_LOG_OFFSET + len(MIC_LOG)] != MIC_LOG:
        raise ValueError("mIC.exe mpurl.dat log string differs at pinned file offset")
    if DRAKAN_NAME in drakan.lower() or DRAKAN_NAME.decode().encode("utf-16le") in drakan.lower():
        raise ValueError("unexpected mpurl.dat filename reference in Drakan.exe")
    if any(name in drakan.lower() or name.decode().encode("utf-16le") in drakan.lower()
           for name in DRAKAN_CSV_NAMES):
        raise ValueError("unexpected Mplayer CSV filename reference in Drakan.exe")

    with tempfile.TemporaryDirectory(prefix="dragonrider-mpurl-") as temporary:
        snapshot = Path(temporary) / "mIC.exe"
        snapshot.write_bytes(mic)
        outputs = []
        for start, stop in DISASSEMBLY_RANGES:
            result = subprocess.run(
                [objdump, "-d", "-Mintel", "-w",
                 f"--start-address=0x{start:x}",
                 f"--stop-address=0x{stop:x}", str(snapshot)],
                check=True, capture_output=True, text=True,
            )
            outputs.append(result.stdout)
        imports = subprocess.run(
            [objdump, "-p", str(snapshot)],
            check=True, capture_output=True, text=True,
        )
    anchors = verify_anchors("\n".join(outputs))
    ordinal = parse_import_ordinal(imports.stdout, 0x42B58, "MFC42.DLL")
    if ordinal != 924:
        raise ValueError(f"unexpected MFC42 import ordinal at call target: {ordinal}")
    return {
        "mIC_sha256": mic_hash,
        "mIC_mpurl_filename_file_offset": f"0x{MIC_NAME_OFFSET:x}",
        "mIC_code_reference": "0x00402B6F",
        "mIC_call_receiving_filename_argument": "0x00402B80",
        "instruction_anchors": anchors,
        "call_target_import": "MFC42.DLL ordinal 924",
        "static_call_effect": "not identified",
        "Drakan_sha256": drakan_hash,
        "Drakan_ascii_or_utf16le_filename_reference": False,
        "Drakan_ascii_or_utf16le_csv_references": False,
        "executed_binaries": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mic_executable", type=Path)
    parser.add_argument("drakan_executable", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    print(json.dumps(verify(args.mic_executable, args.drakan_executable,
                            args.objdump), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
