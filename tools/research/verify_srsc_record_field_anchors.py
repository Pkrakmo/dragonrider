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
    0x0042B0DE: "mov WORD PTR [edi+0x4],ax",
    0x00435606: "test eax,eax",
    0x00435616: "cmp eax,0x30",
    0x00441E29: "push 0x0",
    0x00441E2D: "call 0x45f5d0",
    0x00441E32: "push 0x0",
    0x00441E34: "push 0x51",
    0x00441E38: "call 0x45f600",
}
THIRD_SELECTOR_ACCESSOR = 0x0045FAD0
EXPECTED_THIRD_SELECTOR_CALLERS = frozenset({0x0042B0D9, 0x00435601})
THIRD_SELECTOR_SETTER = 0x0045F5D0
EXPECTED_SETTER_CALLERS = frozenset({0x00441E2D})

_INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+\s*(\S.*)$")
_CALL = re.compile(r"^\s*([0-9a-fA-F]+):.*\bcall\s+0x([0-9a-fA-F]+)\b")
_JMP = re.compile(r"^\s*([0-9a-fA-F]+):.*\bjmp\s+0x([0-9a-fA-F]+)\b")


def instructions(disassembly):
    """Return normalized GNU objdump instructions keyed by virtual address."""
    result = {}
    for line in disassembly.splitlines():
        match = _INSTRUCTION.match(line)
        if match:
            result[int(match.group(1), 16)] = " ".join(match.group(2).split())
    return result


def direct_references(disassembly, mnemonic, target=THIRD_SELECTOR_ACCESSOR):
    """Return instruction addresses for direct calls or jumps to target."""
    pattern = _CALL if mnemonic == "call" else _JMP if mnemonic == "jmp" else None
    if pattern is None:
        raise ValueError("mnemonic must be call or jmp")
    result = set()
    for line in disassembly.splitlines():
        match = pattern.match(line)
        if match and int(match.group(2), 16) == target:
            result.add(int(match.group(1), 16))
    return result


def literal_address_offsets(data, target=THIRD_SELECTOR_ACCESSOR):
    """Find raw little-endian absolute-address literals in file bytes."""
    needle = target.to_bytes(4, "little")
    offsets = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    if not args.executable.is_file() or args.executable.is_symlink():
        raise ValueError("executable must be a regular non-symlink file")
    data = args.executable.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise ValueError("unexpected executable SHA-256")
    completed = subprocess.run(
        [args.objdump, "-d", "-Mintel", str(args.executable)],
        check=True, capture_output=True, text=True)
    observed = instructions(completed.stdout)
    mismatches = {
        hex(address): {"expected": expected, "actual": observed.get(address)}
        for address, expected in EXPECTED_INSTRUCTIONS.items()
        if observed.get(address) != expected
    }
    if mismatches:
        raise ValueError(f"SRSC record field anchors differ: {mismatches}")
    callers = direct_references(completed.stdout, "call")
    jumps = direct_references(completed.stdout, "jmp")
    if callers != EXPECTED_THIRD_SELECTOR_CALLERS:
        raise ValueError(
            "third-selector accessor caller inventory differs "
            f"(expected={[hex(value) for value in sorted(EXPECTED_THIRD_SELECTOR_CALLERS)]}, "
            f"actual={[hex(value) for value in sorted(callers)]})")
    if jumps:
        raise ValueError(
            "unexpected direct jumps to third-selector accessor "
            f"({[hex(value) for value in sorted(jumps)]})")
    setter_calls = direct_references(completed.stdout, "call", THIRD_SELECTOR_SETTER)
    if setter_calls != EXPECTED_SETTER_CALLERS:
        raise ValueError(
            "third-selector setter caller inventory differs "
            f"(expected={[hex(value) for value in sorted(EXPECTED_SETTER_CALLERS)]}, "
            f"actual={[hex(value) for value in sorted(setter_calls)]})")
    address_literals = literal_address_offsets(data)
    if address_literals:
        raise ValueError(
            "unexpected raw absolute-address literals for third-selector accessor "
            f"({[hex(value) for value in address_literals]})")
    print(f"Verified SRSC field anchors: {len(EXPECTED_INSTRUCTIONS)}; "
          f"third-selector accessor: {len(callers)} calls, {len(jumps)} jumps, "
          f"{len(address_literals)} raw address literals; "
          f"third-selector setter: {len(setter_calls)} calls")


if __name__ == "__main__":
    main()
