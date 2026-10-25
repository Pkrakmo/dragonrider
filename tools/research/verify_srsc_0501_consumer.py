#!/usr/bin/env python3
"""Verify one hash-pinned retail consumer path reached by SRSC selector 0x0501.

The report is bounded to exact instructions in one function. It establishes
static request arithmetic and a repeated stride, not field meanings or runtime
execution.
"""

import argparse
import hashlib
from pathlib import Path
import re
import struct
import subprocess
import tempfile


EXPECTED_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"
EXPECTED_SIZE = 552960
SCALE_CONSTANT_FILE_OFFSET = 0x75600
SCALE_CONSTANT_BYTES = b"\x00\x00\x00\x45"

# Exact instruction anchors from the retail path after the selected record is
# read. Together these show an 8-byte-unit allocation/read, then a
# 52-byte-per-count allocation/read, followed by a loop with a 0x34-byte
# stride that transforms three dwords per unit.
EXPECTED_INSTRUCTIONS = {
    # Other direct callsites to the same pair-selector loader. The first and
    # second arguments are presented in call-site push order and then matched
    # to the loader's stack slots below.
    0x00424760: "mov ebx,DWORD PTR [esi+0x12c]",
    0x00424767: "push 0x200",
    0x0042476C: "mov ecx,ebx",
    0x0042476E: "call 0x45fa10",
    0x00433022: "mov edi,DWORD PTR [edi+0x15c]",
    0x00433028: "push ebp",
    0x00433029: "push 0x302",
    0x0043302E: "mov ecx,edi",
    0x00433030: "call 0x45fa10",
    0x0045F230: "push esi",
    0x0045F231: "mov esi,ecx",
    0x0045F233: "cmp DWORD PTR [esi],0x1",
    0x0045F241: "mov eax,DWORD PTR [esp+0xc]",
    0x0045F245: "mov ecx,DWORD PTR [esp+0x8]",
    0x0045F249: "push eax",
    0x0045F24A: "push ecx",
    0x0045F24B: "mov ecx,esi",
    0x0045F24D: "call 0x45fa10",
    0x0045F252: "test eax,eax",
    0x0045F254: "jge 0x45f25f",
    0x0045F25F: "push eax",
    0x0045F260: "mov ecx,esi",
    0x0045F262: "call 0x45f270",
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
    0x004156A1: "test eax,eax",
    0x004156A3: "jne 0x415763",
    0x004156A9: "push eax",
    0x004156AA: "push eax",
    0x004156AB: "mov ecx,esi",
    0x004156AD: "mov DWORD PTR [edi+0xc],eax",
    0x004156B0: "mov DWORD PTR [edi+0x10],eax",
    0x004156B3: "call 0x45f430",
    0x004156B8: "lea ecx,[esp+0x10]",
    0x004156BF: "mov ebx,0x4",
    0x004156BC: "lea edx,[edi+0x14]",
    0x004156C4: "push ecx",
    0x004156C5: "push edx",
    0x004156C8: "mov DWORD PTR [esp+0x18],ebx",
    0x004156CC: "call 0x45f2d0",
    0x004156D1: "push ebx",
    0x004156D4: "call 0x45f3d0",
    0x004156D9: "lea ebp,[edi+0x18]",
    0x004156DE: "push ebp",
    0x004156DF: "call 0x45f370",
    0x004156E4: "lea eax,[esp+0x10]",
    0x004156E8: "lea ecx,[edi+0x1c]",
    0x004156EB: "push eax",
    0x004156EC: "push ecx",
    0x004156EF: "mov DWORD PTR [esp+0x18],ebx",
    0x004156F3: "call 0x45f2d0",
    0x004156F8: "lea eax,[edi+0x20]",
    0x004156FD: "push eax",
    0x004156FE: "call 0x45f370",
    0x00415786: "mov ecx,esi",
    0x00415788: "push eax",
    0x00415782: "lea eax,[esp+0x28]",
    0x00415789: "call 0x45f3a0",
    0x0041570A: "call 0x45f370",
    0x00415715: "call 0x45f370",
    0x0041574D: "call 0x45f7a0",
    0x00415752: "mov ecx,DWORD PTR [esp+0x18]",
    0x00415756: "inc ecx",
    0x00415757: "push ecx",
    0x0041575A: "call 0x45f270",
    0x0041578E: "mov ebx,DWORD PTR [edi+0x20]",
    0x00415791: "shl ebx,0x3",
    0x00415794: "push ebx",
    0x004157B6: "call 0x45f2d0",
    0x004157C2: "mov eax,DWORD PTR [esp+0x18]",
    0x004157C8: "add eax,0x2",
    0x004157CC: "call 0x45f270",
    0x004157DD: "mov eax,DWORD PTR [ebp+0x0]",
    0x004157E0: "lea edx,[eax+eax*2]",
    0x004157E3: "lea ebx,[eax+edx*4]",
    0x004157E6: "shl ebx,0x2",
    0x004157E9: "push ebx",
    0x0041580B: "call 0x45f2d0",
    0x00415810: "mov edx,DWORD PTR [ebp+0x0]",
    0x00415818: "test edx,edx",
    0x0041581A: "jle 0x41584c",
    0x0041581C: "add eax,0x2c",
    0x0041581F: "fld DWORD PTR [eax-0x4]",
    0x00415822: "fmul DWORD PTR ds:0x475600",
    0x00415829: "add eax,0x34",
    0x0041582C: "fstp DWORD PTR [eax-0x38]",
    0x0041582F: "fld DWORD PTR [eax-0x34]",
    0x00415838: "fstp DWORD PTR [eax-0x34]",
    0x0041583B: "fld DWORD PTR [eax-0x30]",
    0x00415844: "fstp DWORD PTR [eax-0x30]",
    0x00415847: "cmp ecx,DWORD PTR [ebp+0x0]",
    0x0041584A: "jl 0x41581f",
    0x004157D1: "lea ecx,[esp+0x28]",
    0x004157D5: "push ecx",
    0x004157D6: "mov ecx,esi",
    0x004157D8: "call 0x45f3a0",
    0x0045F3A0: "push ecx",
    0x0045F3A1: "mov edx,DWORD PTR [esp+0x8]",
    0x0045F3A5: "lea eax,[esp+0x0]",
    0x0045F3A9: "push eax",
    0x0045F3AA: "push edx",
    0x0045F3AB: "mov DWORD PTR [esp+0x8],0x2",
    0x0045F3B3: "call 0x45f2d0",
    0x0045F3B8: "test eax,eax",
    0x0045F3BA: "jne 0x45f3c9",
    0x0045F3BC: "mov eax,DWORD PTR [esp+0x0]",
    0x0045F3C0: "sub eax,0x2",
    0x0045F3C3: "neg eax",
    0x0045F3C5: "sbb eax,eax",
    0x0045F3C7: "and al,0xfe",
    0x0045F3C9: "pop ecx",
    0x0045F3CA: "ret 0x4",
    # The 0x0501 caller reaches the generic length-prefixed byte reader with
    # null output and zero capacity. That branch skips the full 16-bit span.
    0x0045F430: "sub esp,0x8",
    0x0045F444: "mov DWORD PTR [esp+0x14],0x2",
    0x0045F44C: "call 0x45f2d0",
    0x0045F45D: "and eax,0xffff",
    0x0045F462: "cmp eax,esi",
    0x0045F464: "mov DWORD PTR [esp+0xc],eax",
    0x0045F46A: "mov DWORD PTR [esp+0xc],esi",
    0x0045F46E: "mov edi,DWORD PTR [esp+0x18]",
    0x0045F472: "test edi,edi",
    0x0045F474: "je 0x45f49f",
    0x0045F49F: "xor esi,esi",
    0x0045F4A1: "mov eax,DWORD PTR [esp+0x10]",
    0x0045F4A5: "and eax,0xffff",
    0x0045F4AA: "cmp esi,eax",
    0x0045F4AE: "sub eax,esi",
    0x0045F4B2: "push eax",
    0x0045F4B3: "call 0x45f3d0",
}

DISASSEMBLY_RANGES = (
    (0x00424760, 0x00424774),
    (0x00433022, 0x00433035),
    (0x0045F230, 0x0045F269),
    (0x0045FA26, 0x0045FA53),
    (0x0045FA8F, 0x0045FAC4),
    (0x004156A1, 0x0041584C),
    (0x0045F430, 0x0045F4B8),
    (0x0045F3A0, 0x0045F3CD),
)

LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+(.+?)\s*$")


def parse_disassembly(text):
    instructions = {}
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        instruction = " ".join(match.group(2).split()).lower()
        instructions[address] = instruction
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


def verify_scale_constant(data):
    encoded = data[SCALE_CONSTANT_FILE_OFFSET:SCALE_CONSTANT_FILE_OFFSET + 4]
    if encoded != SCALE_CONSTANT_BYTES:
        raise ValueError("unexpected binary32 scale constant bytes")
    return struct.unpack("<f", encoded)[0]


def verify_binary(path, objdump="objdump"):
    path = Path(path)
    try:
        actual_size = path.stat().st_size
    except OSError as error:
        raise ValueError(f"could not stat executable: {error}") from error
    if actual_size != EXPECTED_SIZE:
        raise ValueError(f"unexpected executable size: {actual_size}")
    # Bound the snapshot read too, in case the input grows after stat().
    with path.open("rb") as source:
        data = source.read(EXPECTED_SIZE + 1)
    if len(data) != EXPECTED_SIZE:
        raise ValueError(f"unexpected executable size while reading: {len(data)}")
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected executable SHA-256: {digest}")
    scale_constant = verify_scale_constant(data)

    with tempfile.TemporaryDirectory(prefix="dragonrider-0501-") as temporary:
        snapshot = Path(temporary) / "Drakan.exe"
        snapshot.write_bytes(data)
        disassemblies = []
        for start, stop in DISASSEMBLY_RANGES:
            result = subprocess.run(
                [objdump, "-d", "-Mintel", "-w",
                 f"--start-address=0x{start:x}",
                 f"--stop-address=0x{stop:x}", str(snapshot)],
                check=True, capture_output=True, text=True,
            )
            disassemblies.append(result.stdout)
    count = verify_anchors("\n".join(disassemblies))
    return {
        "sha256": digest,
        "method": "GNU objdump bounded disassembly with exact instruction anchors",
        "instruction_anchors": count,
        "callsite_8_byte_units": "0x004157B6",
        "callsite_52_byte_units": "0x0041580B",
        "loop_stride_bytes": 0x34,
        "scaled_dwords_per_iteration": 3,
        "scale_constant_file_offset": f"0x{SCALE_CONSTANT_FILE_OFFSET:x}",
        "scale_constant_binary32": scale_constant,
        "length_prefixed_span": "caller passes null output and zero capacity; helper skips the 16-bit length",
        "next_record_selection": "index i + 1 after the anchored fixed-width reads",
        "other_pair_selector_callers": {
            "0x0042476e": {
                "first_argument": "0x0200",
                "second_argument": "EDI at callsite, masked to 16 bits by the pair loader",
            },
            "0x00433030": {
                "first_argument": "0x0302",
                "second_argument": "EBP at callsite, masked to 16 bits by the pair loader",
            },
            "0x0045f24d": {
                "first_argument": "forwarded from wrapper stack argument",
                "second_argument": "forwarded from wrapper stack argument",
                "condition": "wrapper object mode equals 1",
            },
        },
        "pair_lookup_fields": "first argument compares with record offset 0; second argument compares with record offset 2",
        "pair_lookup_search": "loops from table index zero and returns first matching index in current table order",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    import json
    print(json.dumps(verify_binary(args.executable, args.objdump), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
