#!/usr/bin/env python3
"""Verify the bounded packed-key route into a retail 0x0200 pair lookup."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


EXPECTED_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"
EXPECTED_INSTRUCTIONS = {
    0x00424690: "push esi",
    0x00424691: "mov esi,DWORD PTR [esp+0x8]",
    0x00424698: "xor edx,edx",
    0x0042469A: "mov edi,0x59",
    0x0042469F: "div edi",
    0x004246A1: "mov eax,DWORD PTR [ecx+edx*4+0x10]",
    0x004246A9: "cmp DWORD PTR [eax+0x4],esi",
    0x004246B9: "push esi",
    0x004246BA: "call 0x4246d0",
    0x004246D0: "sub esp,0x108",
    0x004246E4: "mov DWORD PTR [esp+0x44],ebp",
    0x004246EA: "mov edi,DWORD PTR [esp+0x11c]",
    0x004246F7: "mov edx,edi",
    0x004246F9: "shr edx,0x10",
    0x00424701: "cmp DWORD PTR [ebx+0x114],edx",
    0x00424720: "mov esi,DWORD PTR [esi+eax*4]",
    0x0042473A: "mov eax,DWORD PTR [esi+0x12c]",
    0x00424744: "push 0x1",
    0x00424748: "call 0x41e470",
    0x00424760: "mov ebx,DWORD PTR [esi+0x12c]",
    0x00424766: "push edi",
    0x00424767: "push 0x200",
    0x0042476C: "mov ecx,ebx",
    0x0042476E: "call 0x45fa10",
    # On lookup success, the returned row index is checked, a related row
    # four positions later is queried, and then the matching and next rows
    # are selected for the following bounded reads.
    0x00424775: "cmp esi,0xffffffff",
    0x00424778: "jne 0x424789",
    0x00424789: "lea eax,[esi+0x4]",
    0x0042478C: "mov ecx,ebx",
    0x0042478E: "push eax",
    0x00424793: "call 0x45fa70",
    0x00424798: "cmp eax,0x208",
    0x004247A1: "call 0x426310",
    0x004247B6: "call 0x426240",
    0x004247C7: "mov ecx,DWORD PTR [esp+0x11c]",
    0x004247CF: "mov DWORD PTR [edi+0x4],ecx",
    0x004247D4: "call 0x45f270",
    0x004247E0: "push 0x40",
    0x004247E5: "call 0x45f430",
    0x004247F0: "push eax",
    0x004247F1: "call 0x45f370",
    0x0042481D: "lea eax,[esi+0x1]",
    0x00424823: "call 0x45f270",
    0x0042482F: "call 0x45f370",
    0x0045FA2E: "and ebx,0xffff",
    0x0045FA3C: "cmp eax,ebx",
    0x0045FA4A: "and ecx,0xffff",
    0x0045FA50: "cmp eax,ecx",
    0x0045FA8F: "mov ax,WORD PTR [edx+ecx*2]",
    0x0045FABF: "mov ax,WORD PTR [edx+ecx*2+0x2]",
}
EXPECTED_CALLERS = {0x004246BA}
RANGES = ((0x00424690, 0x00424834), (0x0045FA2E, 0x0045FA53), (0x0045FA8F, 0x0045FAC4))
LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+(.+?)\s*$")
CALL_RE = re.compile(r"^call\s+(0x[0-9a-f]+)$", re.IGNORECASE)
JUMP_RE = re.compile(r"^jmp\s+(0x[0-9a-f]+)$", re.IGNORECASE)


def parse(text):
    found = {}
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if match:
            found[int(match.group(1), 16)] = " ".join(match.group(2).split()).lower()
    return found


def verify_anchors(text):
    found = parse(text)
    for address, expected in EXPECTED_INSTRUCTIONS.items():
        actual = found.get(address)
        if actual != expected.lower():
            raise ValueError(f"instruction anchor 0x{address:08x}: expected {expected!r}, got {actual!r}")
    return len(EXPECTED_INSTRUCTIONS)


def references(text, target, pattern):
    return {address for address, instruction in parse(text).items()
            if (match := pattern.fullmatch(instruction)) and int(match.group(1), 16) == target}


def disassemble(path, objdump, start=None, stop=None):
    command = [objdump, "-d", "-Mintel", "-w"]
    if start is not None:
        command += [f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}"]
    command.append(str(path))
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def verify_callers(text):
    callers = references(text, 0x004246D0, CALL_RE)
    if callers != EXPECTED_CALLERS:
        raise ValueError(f"direct callers to 0x004246d0 differ (missing={sorted(EXPECTED_CALLERS-callers)}, unexpected={sorted(callers-EXPECTED_CALLERS)})")
    jumps = references(text, 0x004246D0, JUMP_RE)
    if jumps:
        raise ValueError(f"unexpected direct jumps to 0x004246d0: {sorted(jumps)}")
    return callers


def verify_binary(executable, objdump="objdump"):
    executable = Path(executable)
    if not executable.is_file() or executable.is_symlink():
        raise ValueError("executable must be a regular non-symlink file")
    data = executable.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected executable SHA-256: {digest}")
    with tempfile.TemporaryDirectory(prefix="dragonrider-0200-key-") as temporary:
        snapshot = Path(temporary) / "Drakan.exe"
        snapshot.write_bytes(data)
        windows = [disassemble(snapshot, objdump, start, stop) for start, stop in RANGES]
        full = disassemble(snapshot, objdump)
    count = verify_anchors("\n".join(windows))
    callers = verify_callers(full)
    return {
        "sha256": digest,
        "method": "GNU objdump bounded windows and full-image direct-call scan on one verified snapshot",
        "instruction_anchors": count,
        "packed_value_route": {
            "cache_lookup_argument": "32-bit value retained in ESI by 0x00424690 and copied to EDI on loader path",
            "module_entry_match": "high 16 bits compared with module entry offset 0x114",
            "record_pair_lookup": "low 16 bits compared with record offset 2 alongside first selector 0x0200",
            "lookup_target": "0x0045FA10",
        },
        "direct_callers_to_0x004246d0": [f"0x{address:08x}" for address in sorted(callers)],
        "direct_unconditional_jumps_to_0x004246d0": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    print(json.dumps(verify_binary(args.executable, args.objdump), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
