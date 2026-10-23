#!/usr/bin/env python3
"""Verify bounded reader/writer anchors for SRSC's 14-byte records."""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess

EXPECTED_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"
EXPECTED_INSTRUCTIONS = {
    0x0045F5EB: "and eax,0xffff",
    0x0045F5F0: "mov DWORD PTR [ecx+0x8],eax",
    0x0045F6B2: "mov ax,WORD PTR [esi+0x8]",
    0x0045F6B6: "mov WORD PTR [edx+ecx*2+0x4],ax",
    0x0045F6D4: "mov DWORD PTR [ecx+edx*2+0x6],eax",
    0x0045F7EB: "sub eax,DWORD PTR [edi+0x6]",
    0x0045F7EE: "mov DWORD PTR [edi+0xa],eax",
    0x0045F155: "cmp WORD PTR [eax],bx",
    0x0045F15A: "cmp WORD PTR [eax+0x2],si",
    0x0045F160: "cmp WORD PTR [eax+0x4],dx",
    0x0045F1D5: "mov ecx,DWORD PTR [esi+0x6]",
    0x0045F1E7: "cmp eax,DWORD PTR [esi+0x6]",
    0x0045F1FB: "mov eax,DWORD PTR [esi+0xa]",
    0x0045F1FE: "mov DWORD PTR [edi+0x18],eax",
}

_INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+\s*(\S.*)$")


def instructions(disassembly):
    """Return normalized GNU objdump instructions keyed by virtual address."""
    result = {}
    for line in disassembly.splitlines():
        match = _INSTRUCTION.match(line)
        if match:
            result[int(match.group(1), 16)] = " ".join(match.group(2).split())
    return result


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    if not args.executable.is_file() or args.executable.is_symlink():
        raise ValueError("executable must be a regular non-symlink file")
    if sha256_file(args.executable) != EXPECTED_SHA256:
        raise ValueError("unexpected executable SHA-256")
    completed = subprocess.run(
        [args.objdump, "-d", "-Mintel", "--start-address=0x0045f0d0",
         "--stop-address=0x0045f805", str(args.executable)],
        check=True, capture_output=True, text=True)
    observed = instructions(completed.stdout)
    mismatches = {
        hex(address): {"expected": expected, "actual": observed.get(address)}
        for address, expected in EXPECTED_INSTRUCTIONS.items()
        if observed.get(address) != expected
    }
    if mismatches:
        raise ValueError(f"SRSC record field anchors differ: {mismatches}")
    print(f"Verified SRSC record field anchors: {len(EXPECTED_INSTRUCTIONS)}")


if __name__ == "__main__":
    main()
