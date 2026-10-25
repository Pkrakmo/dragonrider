#!/usr/bin/env python3
"""Verify hash-pinned CSV string references and formatting calls in gizmo.ocx."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile

EXPECTED_SIZE = 260608
EXPECTED_SHA256 = "79b054b4407cca7cdf52bed2ad63790d6dad13d90069250baa9e30502857b5d2"
LITERALS = {
    "mpusage.csv": (0x2E61C, 0x1002FE1C),
    "mphisto.csv": (0x2E7B4, 0x1002FFB4),
}
IAT_ADDRESS = 0x1004E15C
EXPECTED_INSTRUCTIONS = {
    0x10016F0F: "push dword ptr [ebp-0x4]",
    0x10016F12: "push edx",
    0x10016F13: "call 0x1002069c",
    0x10016F18: "add esp,0x4",
    0x10016F1B: "lea ecx,[ebp-0x46c]",
    0x10016F21: "push eax",
    0x10016F22: "push 0x1",
    0x10016F24: "push ecx",
    0x10016F25: "call dword ptr ds:0x1004e13c",
    0x10016F2B: "add esp,0x10",
    0x10016F2E: "push dword ptr [ebp-0x4]",
    0x10016F31: "call dword ptr ds:0x1004e140",
    0x10016F76: "push 0x1002fe1c",
    0x10016F7B: "push dword ptr [esi+0x984]",
    0x10016F81: "push 0x100273b4",
    0x10016F86: "push ecx",
    0x10016F87: "call dword ptr ds:0x1004e15c",
    0x10016F90: "lea ecx,[ebp-0x588]",
    0x10016F96: "push 0x100273b0",
    0x10016F9B: "push ecx",
    0x10016F9C: "call dword ptr ds:0x1004e134",
    0x10016FA5: "mov dword ptr [ebp-0x4],eax",
    0x10016FA8: "test eax,eax",
    0x10017368: "push 0x1002ffb4",
    0x1001736D: "push dword ptr [eax+0x984]",
    0x10017373: "push 0x100273b4",
    0x10017378: "push edx",
    0x10017379: "call dword ptr ds:0x1004e15c",
    0x10017382: "lea ecx,[ebp-0x20c]",
    0x10017388: "push 0x100273b0",
    0x1001738D: "push ecx",
    0x1001738E: "call dword ptr ds:0x1004e134",
    0x10017397: "mov esi,eax",
    0x10017399: "test esi,esi",
    0x1001739B: "je 0x10017707",
    0x100176B7: "call dword ptr ds:0x1004e13c",
    0x100176BD: "add esp,0x10",
    0x100176F4: "call dword ptr ds:0x1004e13c",
    0x100176FA: "add esp,0x10",
    0x100176FD: "push esi",
    0x100176FE: "call dword ptr ds:0x1004e140",
    0x10017704: "add esp,0x4",
}
EXPECTED_INSTRUCTIONS[0x10016FAA] = "je 0x100170fa"
DISASSEMBLY_RANGES = (
    (0x10016F09, 0x10016FB0),
    (0x10017368, 0x100173A1),
    (0x100176AD, 0x10017707),
)
LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+(.+?)\s*$")


def parse_disassembly(text):
    parsed = {}
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if match:
            parsed[int(match.group(1), 16)] = " ".join(match.group(2).split()).lower()
    return parsed


def verify_anchors(text):
    actual = parse_disassembly(text)
    for address, expected in EXPECTED_INSTRUCTIONS.items():
        if actual.get(address) != expected:
            raise ValueError(f"instruction anchor 0x{address:08x} mismatch")
    return len(EXPECTED_INSTRUCTIONS)


def verify_imports(text):
    return {
        "sprintf": verify_named_import(text, 0x4E15C, "sprintf"),
        "fopen": verify_named_import(text, 0x4E134, "fopen"),
        "fwrite": verify_named_import(text, 0x4E13C, "fwrite"),
        "fclose": verify_named_import(text, 0x4E140, "fclose"),
    }


def verify_data_section(text):
    matches = []
    for line in text.splitlines():
        match = re.match(
            r"^\s*\d+\s+\.data\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
            r"[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+", line)
        if match:
            matches.append(tuple(int(value, 16) for value in match.groups()))
    if matches != [(0xC000, 0x10027000, 0x25800)]:
        raise ValueError("gizmo .data section mapping differs from pinned offsets")
    return {"size": "0xc000", "virtual_address": "0x10027000",
            "file_offset": "0x25800"}


def verify_named_import(text, iat_rva, expected):
    matches = []
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+)\s+<none>\s+\S+\s+(\S+)\s*$", line)
        if match and int(match.group(1), 16) == iat_rva:
            matches.append(match.group(2).lower())
    if matches != [expected]:
        raise ValueError(f"gizmo import at IAT RVA 0x{iat_rva:x} is not {expected}")
    return matches[0]


def verify(path, objdump="objdump"):
    path = Path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("gizmo input is not a singly linked regular file")
    if metadata.st_size != EXPECTED_SIZE:
        raise ValueError(f"unexpected gizmo.ocx size: {metadata.st_size}")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected gizmo.ocx size or SHA-256: {len(data)}, {digest}")
    for filename, (offset, address) in LITERALS.items():
        expected = filename.encode("ascii") + b"\0"
        if data[offset:offset + len(expected)] != expected:
            raise ValueError(f"{filename} literal differs at pinned file offset")
        if address != 0x10027000 + (offset - 0x25800):
            raise ValueError("literal VA does not match the pinned .data mapping")
    for va, expected in ((0x100273B0, b"wb\0"), (0x100273B4, b"%s\\%s\0")):
        offset = 0x25800 + (va - 0x10027000)
        if data[offset:offset + len(expected)] != expected:
            raise ValueError("path format or fopen mode differs at pinned .data offset")

    with tempfile.TemporaryDirectory(prefix="dragonrider-gizmo-csv-") as temporary:
        snapshot = Path(temporary) / "gizmo.ocx"
        snapshot.write_bytes(data)
        disassemblies = []
        for start, stop in DISASSEMBLY_RANGES:
            result = subprocess.run(
                [objdump, "-d", "-Mintel", "-w", f"--start-address=0x{start:x}",
                 f"--stop-address=0x{stop:x}", str(snapshot)],
                check=True, capture_output=True, text=True,
            )
            disassemblies.append(result.stdout)
        imports = subprocess.run([objdump, "-p", str(snapshot)],
                                 check=True, capture_output=True, text=True)
        sections = subprocess.run([objdump, "-h", str(snapshot)],
                                  check=True, capture_output=True, text=True)
    anchors = verify_anchors("\n".join(disassemblies))
    import_names = verify_imports(imports.stdout)
    data_section = verify_data_section(sections.stdout)
    return {
        "gizmo_sha256": digest,
        "literal_file_offsets": {name: f"0x{offset:x}"
                                 for name, (offset, _) in LITERALS.items()},
        "literal_virtual_addresses": {name: f"0x{address:x}"
                                      for name, (_, address) in LITERALS.items()},
        "instruction_anchors": anchors,
        "format_string": "%s\\%s",
        "fopen_mode": "wb",
        "sprintf_iat_virtual_address": f"0x{IAT_ADDRESS:x}",
        "fopen_iat_virtual_address": "0x1004e134",
        "import_names": import_names,
        "data_section": data_section,
        "established_call_effect": "both CSV paths are formatted and passed to fopen in wb mode; their non-null-handle branches reach fwrite and fclose",
        "executed_binary": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gizmo_ocx", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    print(json.dumps(verify(args.gizmo_ocx, args.objdump), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
