#!/usr/bin/env python3
"""Verify the pinned direct-call graph feeding the level query's dynamic flag."""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


EXPECTED_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"
QUERY = 0x00420960
WRAPPER = 0x0044C9F0
EXPECTED_QUERY_CALLERS = frozenset({
    0x00403989, 0x00420DF3, 0x004219A8, 0x004219C9, 0x0042868F, 0x0044CA10,
})
EXPECTED_WRAPPER_CALLERS = frozenset({0x0044C940})
EXPECTED_QUERY_JUMPS = frozenset()
EXPECTED_WRAPPER_JUMPS = frozenset()
EXPECTED_INSTRUCTIONS = {
    0x00420D76: "test BYTE PTR [ebp+0x1c],0x2",
    0x00420D7A: "mov eax,DWORD PTR [ebp+0x20]",
    0x00420D7D: "je 0x420db2",
    0x00420D7F: "test eax,eax",
    0x00420D81: "je 0x420d9a",
    0x00420D89: "push eax",
    0x00420D93: "call 0x420e10",
    0x00420D98: "jmp 0x420ddb",
    0x00420DA3: "push 0x5",
    0x00420DAB: "call 0x420e10",
    0x00420DB2: "test eax,eax",
    0x00420DB4: "je 0x420dc5",
    0x00420DCE: "push 0x11",
    0x00420DD6: "call 0x4213f0",
    0x00403952: "push 0x0",
    0x0040395A: "push 0x0",
    0x0040395C: "push 0x0",
    0x00403982: "push edx",
    0x00403983: "push eax",
    0x00403984: "push ecx",
    0x00403988: "push edi",
    0x00403989: "call 0x420960",
    0x0042199E: "push 0x0",
    0x004219A0: "push 0x0",
    0x004219A2: "push 0x0",
    0x004219A4: "push esi",
    0x004219A5: "push edi",
    0x004219A6: "push ebx",
    0x004219A7: "push edx",
    0x004219A8: "call 0x420960",
    0x004219B9: "push 0x0",
    0x004219BB: "push 0x0",
    0x004219BD: "push 0x0",
    0x004219BF: "push esi",
    0x004219C6: "push edi",
    0x004219C7: "push ebx",
    0x004219C8: "push esi",
    0x004219C9: "call 0x420960",
    0x0042866F: "push 0x0",
    0x00428678: "push 0x0",
    0x0042867A: "push edx",
    0x0042867F: "push eax",
    0x00428686: "push ecx",
    0x0042868D: "push edx",
    0x0042868E: "push eax",
    0x0042868F: "call 0x420960",
    0x00420DDB: "mov ecx,DWORD PTR [ebp+0x20]",
    0x00420DE1: "push ecx",
    0x00420DE5: "push edx",
    0x00420DE9: "push ecx",
    0x00420DED: "push edi",
    0x00420DEE: "push edx",
    0x00420DEF: "push ecx",
    0x00420DF0: "push eax",
    0x00420DF3: "call 0x420960",
    0x0044C91A: "push 0x0",
    0x0044C925: "push 0x0",
    0x0044C927: "push edx",
    0x0044C928: "push esi",
    0x0044C940: "call 0x44c9f0",
    0x0044C9F0: "mov eax,DWORD PTR [esp+0x10]",
    0x0044C9F8: "push eax",
    0x0044C9FD: "push edx",
    0x0044C9FE: "push 0x0",
    0x0044CA03: "push edx",
    0x0044CA09: "push edx",
    0x0044CA0E: "push eax",
    0x0044CA0F: "push edx",
    0x0044CA10: "call 0x420960",
}
EXPECTED_PUSH_SEQUENCES = {
    0x00403989: (0x00403952, 0x0040395A, 0x0040395C, 0x00403982,
                 0x00403983, 0x00403984, 0x00403988),
    0x004219A8: (0x0042199E, 0x004219A0, 0x004219A2, 0x004219A4,
                 0x004219A5, 0x004219A6, 0x004219A7),
    0x004219C9: (0x004219B9, 0x004219BB, 0x004219BD, 0x004219BF,
                 0x004219C6, 0x004219C7, 0x004219C8),
    0x0042868F: (0x0042866F, 0x00428678, 0x0042867A, 0x0042867F,
                 0x00428686, 0x0042868D, 0x0042868E),
    0x00420DF3: (0x00420DE1, 0x00420DE5, 0x00420DE9, 0x00420DED,
                 0x00420DEE, 0x00420DEF, 0x00420DF0),
    0x0044CA10: (0x0044C9F8, 0x0044C9FD, 0x0044C9FE, 0x0044CA03,
                 0x0044CA09, 0x0044CA0E, 0x0044CA0F),
}
EXPECTED_WRAPPER_PUSH_SEQUENCE = (0x0044C91A, 0x0044C925, 0x0044C927, 0x0044C928)

_INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+\s*(\S.*)$")
_CALL = re.compile(r"^\s*([0-9a-fA-F]+):.*\bcall\s+0x([0-9a-fA-F]+)\b")
_JMP = re.compile(r"^\s*([0-9a-fA-F]+):.*\bjmp\s+0x([0-9a-fA-F]+)\b")
_STACK_POINTER_CHANGE = re.compile(
    r"^(?:pop(?:\s|f\b|fd\b|fw\b|a\b|ad\b|aw\b)|"
    r"push(?:f\b|fd\b|fw\b|ad\b|aw\b|a\b)|"
    r"enter\b|leave\b|(?:add|sub|and|or|xor|inc|dec|xchg)\s+esp\b|"
    r"mov\s+esp\b|lea\s+esp\b)"
)


def instructions(disassembly):
    """Return whitespace-normalized objdump instructions by address."""
    found = {}
    for line in disassembly.splitlines():
        match = _INSTRUCTION.match(line)
        if match:
            found[int(match.group(1), 16)] = " ".join(match.group(2).split())
    return found


def direct_calls(disassembly, target):
    """Return direct relative CALL instruction addresses to target."""
    found = set()
    for line in disassembly.splitlines():
        match = _CALL.match(line)
        if match and int(match.group(2), 16) == target:
            found.add(int(match.group(1), 16))
    return found


def direct_jumps(disassembly, target):
    """Return direct unconditional JMP instruction addresses to target."""
    found = set()
    for line in disassembly.splitlines():
        match = _JMP.match(line)
        if match and int(match.group(2), 16) == target:
            found.add(int(match.group(1), 16))
    return found


def raw_pointer_offsets(data, target):
    """Find exact little-endian address bytes in the raw executable snapshot."""
    needle = target.to_bytes(4, "little")
    offsets = []
    offset = 0
    while True:
        offset = data.find(needle, offset)
        if offset < 0:
            return offsets
        offsets.append(offset)
        offset += 1


def disassemble_snapshot(data, objdump="objdump"):
    """Run objdump against the exact byte snapshot that passed hash checking."""
    with tempfile.TemporaryDirectory(prefix="dragonrider-level-query-flags-") as temp:
        snapshot = Path(temp) / "Drakan.exe"
        snapshot.write_bytes(data)
        return subprocess.run(
            [objdump, "-d", "-Mintel", str(snapshot)], check=True,
            capture_output=True, text=True).stdout


def verify(disassembly, data=None):
    observed_instructions = instructions(disassembly)
    mismatches = {
        hex(address): {"expected": expected, "actual": observed_instructions.get(address)}
        for address, expected in EXPECTED_INSTRUCTIONS.items()
        if observed_instructions.get(address) != expected
    }
    if mismatches:
        raise ValueError(f"level-query provenance anchors differ: {mismatches}")
    query_callers = direct_calls(disassembly, QUERY)
    wrapper_callers = direct_calls(disassembly, WRAPPER)
    if query_callers != EXPECTED_QUERY_CALLERS:
        raise ValueError(
            "direct query-routine caller inventory differs "
            f"(missing={[hex(x) for x in sorted(EXPECTED_QUERY_CALLERS - query_callers)]}, "
            f"unexpected={[hex(x) for x in sorted(query_callers - EXPECTED_QUERY_CALLERS)]})")
    if wrapper_callers != EXPECTED_WRAPPER_CALLERS:
        raise ValueError(
            "direct wrapper caller inventory differs "
            f"(missing={[hex(x) for x in sorted(EXPECTED_WRAPPER_CALLERS - wrapper_callers)]}, "
            f"unexpected={[hex(x) for x in sorted(wrapper_callers - EXPECTED_WRAPPER_CALLERS)]})")
    query_jumps = direct_jumps(disassembly, QUERY)
    wrapper_jumps = direct_jumps(disassembly, WRAPPER)
    if query_jumps != EXPECTED_QUERY_JUMPS or wrapper_jumps != EXPECTED_WRAPPER_JUMPS:
        raise ValueError(
            "direct unconditional jump inventory differs "
            f"(query={[hex(x) for x in sorted(query_jumps)]}, "
            f"wrapper={[hex(x) for x in sorted(wrapper_jumps)]})")
    if data is not None:
        query_pointers = raw_pointer_offsets(data, QUERY)
        wrapper_pointers = raw_pointer_offsets(data, WRAPPER)
        if query_pointers or wrapper_pointers:
            raise ValueError(
                "unexpected exact raw address literal "
                f"(query={[hex(x) for x in query_pointers]}, "
                f"wrapper={[hex(x) for x in wrapper_pointers]})")
    for call_address, expected_pushes in EXPECTED_PUSH_SEQUENCES.items():
        first_push = expected_pushes[0]
        actual_pushes = tuple(sorted(
            address for address, instruction in observed_instructions.items()
            if first_push <= address < call_address and instruction.startswith("push ")))
        if actual_pushes != expected_pushes:
            raise ValueError(
                f"argument push sequence differs before {hex(call_address)}: "
                f"expected={[hex(x) for x in expected_pushes]}, "
                f"actual={[hex(x) for x in actual_pushes]}")
        if any(instruction.startswith("call ")
               for address, instruction in observed_instructions.items()
               if first_push <= address < call_address):
            raise ValueError(f"nested call occurs within argument setup for {hex(call_address)}")
        if any(_STACK_POINTER_CHANGE.match(instruction)
               for address, instruction in observed_instructions.items()
               if first_push <= address < call_address):
            raise ValueError(f"stack-pointer adjustment occurs within argument setup for {hex(call_address)}")
    wrapper_first = EXPECTED_WRAPPER_PUSH_SEQUENCE[0]
    wrapper_pushes = tuple(sorted(
        address for address, instruction in observed_instructions.items()
        if wrapper_first <= address < 0x0044C940 and instruction.startswith("push ")))
    if wrapper_pushes != EXPECTED_WRAPPER_PUSH_SEQUENCE:
        raise ValueError(
            "wrapper argument push sequence differs "
            f"(expected={[hex(x) for x in EXPECTED_WRAPPER_PUSH_SEQUENCE]}, "
            f"actual={[hex(x) for x in wrapper_pushes]})")
    if any(_STACK_POINTER_CHANGE.match(instruction)
           for address, instruction in observed_instructions.items()
           if wrapper_first <= address < 0x0044C940):
        raise ValueError("stack-pointer adjustment occurs within wrapper argument setup")
    return query_callers, wrapper_callers


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
    query_callers, wrapper_callers = verify(
        disassemble_snapshot(data, args.objdump), data)
    print(f"Verified dynamic-query provenance: {len(query_callers)} direct calls to "
          f"0x{QUERY:08x}; {len(wrapper_callers)} direct call to wrapper "
          f"0x{WRAPPER:08x}; {len(EXPECTED_INSTRUCTIONS)} instruction anchors")
    print("Four direct query roots push seventh argument zero; recursive and wrapper "
          "edges forward their seventh argument")
    print("Verified 0 direct unconditional jumps and 0 exact raw address literals "
          "for the query routine and wrapper")


if __name__ == "__main__":
    main()
