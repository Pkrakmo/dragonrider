#!/usr/bin/env python3
"""Verify the bounded packed-key route into a retail 0x0302 pair lookup."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


EXPECTED_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"

EXPECTED_INSTRUCTIONS = {
    # An input packed value is retained in EBP; on this cache-miss path its
    # high half is matched against the module table before its low half is
    # passed with 0x0302 to the SRSC pair selector.
    0x00432F70: "sub esp,0x54",
    0x00432F93: "mov ebp,DWORD PTR [esp+0x68]",
    0x00432F99: "push ebp",
    0x00432F9A: "call 0x431010",
    0x00432FC0: "mov edx,ebp",
    0x00432FC2: "shr edx,0x10",
    0x00432FCA: "cmp DWORD PTR [edi+0x114],edx",
    0x00432FFF: "mov eax,DWORD PTR [edi+0x15c]",
    0x00433022: "mov edi,DWORD PTR [edi+0x15c]",
    0x00433028: "push ebp",
    0x00433029: "push 0x302",
    0x0043302E: "mov ecx,edi",
    0x00433030: "call 0x45fa10",
    # The success branch passes the returned row to indexed selection. If
    # its object cache misses, the construction path retains the packed key
    # in object offset +0x62.
    0x00433035: "cmp eax,0xffffffff",
    0x00433038: "jne 0x433046",
    0x00433046: "push eax",
    0x00433047: "mov ecx,edi",
    0x00433049: "call 0x45f270",
    0x0043304E: "test eax,eax",
    0x0043305E: "test esi,esi",
    0x00433068: "call 0x430f20",
    0x0043307D: "mov eax,ebp",
    0x00433086: "mov DWORD PTR [esi+0x62],ebp",
    0x00433091: "mov eax,DWORD PTR [ebx+edx*4+0x10]",
    0x00433098: "mov DWORD PTR [ebx+edx*4+0x10],esi",
    # Four thin lookup wrappers preserve the packed value in EDI.
    0x004310B2: "mov edi,DWORD PTR [esp+0xc]",
    0x004310C2: "push eax",
    0x004310C3: "push edi",
    0x004310C4: "mov ecx,esi",
    0x004310C6: "call 0x432f70",
    0x004310F2: "mov edi,DWORD PTR [esp+0xc]",
    0x00431102: "push eax",
    0x00431103: "push edi",
    0x00431106: "call 0x432f70",
    0x00431132: "mov edi,DWORD PTR [esp+0xc]",
    0x00431142: "push eax",
    0x00431143: "push edi",
    0x00431146: "call 0x432f70",
    0x00431172: "mov edi,DWORD PTR [esp+0xc]",
    0x00431182: "push eax",
    0x00431183: "push edi",
    0x00431186: "call 0x432f70",
    # Generic two-argument wrapper forwards the first input value unchanged.
    0x004311A0: "mov eax,DWORD PTR [esp+0x8]",
    0x004311A4: "mov edx,DWORD PTR [esp+0x4]",
    0x004311A8: "push eax",
    0x004311A9: "push edx",
    0x004311AA: "call 0x432f70",
    # Another caller supplies the packed value from object field +0x62.
    0x00432A58: "mov eax,DWORD PTR [edi+0x4]",
    0x00432A61: "mov ecx,DWORD PTR [edi+0x62]",
    0x00432A67: "push eax",
    0x00432A68: "push ecx",
    0x00432A69: "mov ecx,esi",
    0x00432A6B: "call 0x432f70",
    # Remaining callers source the packed value from their stack-local inputs.
    0x00432B07: "mov eax,DWORD PTR [esp+0x38]",
    0x00432B27: "mov ebx,DWORD PTR [esp+0x40]",
    0x00432B2D: "push ebx",
    0x00432B2E: "push eax",
    0x00432B2F: "call 0x432f70",
    0x00432D11: "mov eax,DWORD PTR [esp+0x40]",
    0x00432D15: "mov ecx,DWORD PTR [esp+0x38]",
    0x00432D19: "push eax",
    0x00432D1A: "push ecx",
    0x00432D1B: "mov ecx,edi",
    0x00432D1D: "call 0x432f70",
    # Pair-loader argument slots and compared on-disk selector offsets.
    0x0045FA26: "mov ebx,DWORD PTR [esp+0x14]",
    0x0045FA2A: "mov ebp,DWORD PTR [esp+0x18]",
    0x0045FA2E: "and ebx,0xffff",
    0x0045FA37: "call 0x45fa70",
    0x0045FA3C: "cmp eax,ebx",
    0x0045FA43: "call 0x45faa0",
    0x0045FA48: "mov ecx,ebp",
    0x0045FA4A: "and ecx,0xffff",
    0x0045FA50: "cmp eax,ecx",
    0x0045FA8F: "mov ax,WORD PTR [edx+ecx*2]",
    0x0045FABF: "mov ax,WORD PTR [edx+ecx*2+0x2]",
}

EXPECTED_CALLERS = {
    0x004310C6, 0x00431106, 0x00431146, 0x00431186,
    0x004311AA, 0x00432A6B, 0x00432B2F, 0x00432D1D,
}

DISASSEMBLY_RANGES = (
    (0x004310B0, 0x004311B0),
    (0x00432A50, 0x00432A71),
    (0x00432B07, 0x00432B34),
    (0x00432D11, 0x00432D22),
    (0x00432F70, 0x0043309C),
    (0x0045FA26, 0x0045FA53),
    (0x0045FA8F, 0x0045FAC4),
)

LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+(.+?)\s*$")
DIRECT_CALL_RE = re.compile(r"^call\s+(0x[0-9a-f]+)$", re.IGNORECASE)
DIRECT_JUMP_RE = re.compile(r"^jmp\s+(0x[0-9a-f]+)$", re.IGNORECASE)


def parse_disassembly(text):
    instructions = {}
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if match:
            instructions[int(match.group(1), 16)] = " ".join(match.group(2).split()).lower()
    return instructions


def verify_anchors(disassembly, expected=EXPECTED_INSTRUCTIONS):
    instructions = parse_disassembly(disassembly)
    for address, wanted in expected.items():
        actual = instructions.get(address)
        if actual != wanted.lower():
            raise ValueError(
                f"instruction anchor 0x{address:08x}: expected {wanted!r}, got {actual!r}"
            )
    return len(expected)


def direct_references(disassembly, target, instruction_re):
    return {
        address for address, instruction in parse_disassembly(disassembly).items()
        if (match := instruction_re.fullmatch(instruction))
        and int(match.group(1), 16) == target
    }


def disassemble(snapshot, objdump, start=None, stop=None):
    command = [objdump, "-d", "-Mintel", "-w"]
    if start is not None:
        command.append(f"--start-address=0x{start:x}")
    if stop is not None:
        command.append(f"--stop-address=0x{stop:x}")
    command.append(str(snapshot))
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def verify_direct_callers(disassembly):
    callers = direct_references(disassembly, 0x00432F70, DIRECT_CALL_RE)
    if callers != EXPECTED_CALLERS:
        raise ValueError(
            "direct callers to 0x00432f70 differ "
            f"(missing={[hex(value) for value in sorted(EXPECTED_CALLERS - callers)]}, "
            f"unexpected={[hex(value) for value in sorted(callers - EXPECTED_CALLERS)]})"
        )
    jumps = direct_references(disassembly, 0x00432F70, DIRECT_JUMP_RE)
    if jumps:
        raise ValueError(f"unexpected direct jumps to 0x00432f70: {sorted(jumps)}")
    return callers


def verify_binary(path, objdump="objdump"):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("executable must be a regular non-symlink file")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected executable SHA-256: {digest}")

    with tempfile.TemporaryDirectory(prefix="dragonrider-0302-key-") as temporary:
        snapshot = Path(temporary) / "Drakan.exe"
        snapshot.write_bytes(data)
        windows = [disassemble(snapshot, objdump, start, stop)
                   for start, stop in DISASSEMBLY_RANGES]
        full = disassemble(snapshot, objdump)

    anchor_count = verify_anchors("\n".join(windows))
    callers = verify_direct_callers(full)
    return {
        "sha256": digest,
        "method": "GNU objdump bounded windows and full-image direct-call scan on one verified snapshot",
        "instruction_anchors": anchor_count,
        "packed_value_route": {
            "cache_lookup_argument": "32-bit value held in EBP at 0x00432F93",
            "module_entry_match": "high 16 bits compared with module entry offset 0x114",
            "record_pair_lookup": "low 16 bits compared with record offset 2 alongside first selector 0x0302",
            "lookup_target": "0x0045FA10",
        },
        "caller_argument_sources": {
            "0x004310c6, 0x00431106, 0x00431146, 0x00431186":
                "wrapper stack value copied to EDI and forwarded as first argument",
            "0x004311aa": "first wrapper stack argument forwarded unchanged",
            "0x00432a6b": "DWORD from caller object offset 0x62",
            "0x00432b2f": "stack-local DWORD loaded from [esp+0x38] before argument setup",
            "0x00432d1d": "stack-local DWORD loaded from [esp+0x38] before argument setup",
        },
        "conditional_object_key_store": "cache-miss construction path stores the packed key to object offset +0x62 at 0x00433086",
        "direct_callers_to_0x00432f70": [f"0x{address:08x}" for address in sorted(callers)],
        "direct_unconditional_jumps_to_0x00432f70": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    print(json.dumps(verify_binary(args.executable, args.objdump), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
