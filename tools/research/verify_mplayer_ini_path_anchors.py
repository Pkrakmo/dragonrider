#!/usr/bin/env python3
"""Verify hash-pinned INI basename references in Mplayer PE disassembly."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from measure_level_0001 import safe_inventory_path

FILES = {
    "mpfaux.dll": {
        "path": "English_-_Mplayer_Files/System/mpfaux.dll",
        "size": 120320,
        "sha256": "32c24c813194a98a0220202f4fa71f918fc3f8bbd5b4c989a03dbc2e5bc234c6",
        "data_file_offset": 0x17600,
        "data_va": 0x10019000,
        "literals": {"MplayerLocal.ini": (0x17BB4, 0x100195B4),
                      "MplayerWeb.ini": (0x17BC8, 0x100195C8)},
        "anchors": {
            0x100034AD: "push 0x100195c8",
            0x100034B2: "push edi",
            0x100034B3: "call 0x10004ae0",
            0x100034CA: "push 0x100195b4",
            0x100034CF: "push esi",
            0x100034D0: "call 0x10004ae0",
        },
    },
    "mpics.dll": {
        "path": "English_-_Mplayer_Files/System/mpics.dll",
        "size": 279552,
        "sha256": "8a68e01d823905961212ae48c2ce0b17da8dd1a0f4180ef9e4c3862d9e9f963f",
        "data_file_offset": 0x37800,
        "data_va": 0x10039000,
        "literals": {"MplayerLocal.ini": (0x37CEC, 0x100394EC),
                      "MplayerWeb.ini": (0x37D00, 0x10039500)},
        "anchors": {
            0x10002A68: "push 0x10039500",
            0x10002A6D: "push edi",
            0x10002A6E: "call 0x1000e5b0",
            0x10002A85: "push 0x100394ec",
            0x10002A8A: "push esi",
            0x10002A8B: "call 0x1000e5b0",
            0x1000E5B0: "jmp dword ptr ds:0x100695a0",
            0x10002AD3: "push 0x10067fd0",
            0x10002AD8: "push dword ptr [ebp+0x1c]",
            0x10002ADB: "push ebx",
            0x10002ADC: "push dword ptr [ebp+0x14]",
            0x10002ADF: "push edi",
            0x10002AE0: "push esi",
            0x10002AE4: "call dword ptr ds:0x10069448",
            0x10002B25: "push 0x10067db0",
            0x10002B2A: "push dword ptr [ebp+0x1c]",
            0x10002B2D: "push ebx",
            0x10002B2E: "push dword ptr [ebp+0x14]",
            0x10002B31: "push edi",
            0x10002B32: "push esi",
            0x10002B36: "call dword ptr ds:0x10069448",
        },
    },
}
MPRREAL = {
    "path": "English_-_Mplayer_Files/System/mpreal.dll",
    "size": FILES["mpics.dll"]["size"],
    "sha256": FILES["mpics.dll"]["sha256"],
}
STRCAT_IAT_RVA = 0x695A0
GET_PRIVATE_PROFILE_STRING_IAT_RVA = 0x69448
EXPECTED_PROFILE_CALLERS = {
    0x10002AB7: {0x100026D7, 0x10002D3E, 0x10004BEA},
    0x10002B09: {0x100026BB, 0x10002751, 0x10004BE3},
}
LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+(.+?)\s*$")


def parse_disassembly(text):
    parsed = {}
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if match:
            parsed[int(match.group(1), 16)] = " ".join(match.group(2).split()).lower()
    return parsed


def verify_anchors(text, expected):
    actual = parse_disassembly(text)
    for address, instruction in expected.items():
        if actual.get(address) != instruction:
            raise ValueError(f"instruction anchor 0x{address:08x} mismatch")
    return len(expected)


def verify_data_section(text, file_offset, virtual_address):
    matches = []
    for line in text.splitlines():
        match = re.match(
            r"^\s*\d+\s+\.data\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
            r"[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+", line)
        if match:
            matches.append(tuple(int(value, 16) for value in match.groups()))
    if len(matches) != 1 or matches[0][1:] != (virtual_address, file_offset):
        raise ValueError("pinned .data section mapping changed")
    return matches[0][0]


def verify_named_import(text, iat_rva, expected_name):
    found = []
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+)\s+<none>\s+\S+\s+(\S+)\s*$", line)
        if match and int(match.group(1), 16) == iat_rva:
            found.append(match.group(2).lower())
    if found != [expected_name.lower()]:
        raise ValueError(f"IAT RVA 0x{iat_rva:x} does not resolve to {expected_name}")
    return found[0]


def direct_callers(text, target):
    callers = set()
    for address, instruction in parse_disassembly(text).items():
        match = re.fullmatch(r"call\s+0x([0-9a-f]+)", instruction)
        if match and int(match.group(1), 16) == target:
            callers.add(address)
    return callers


def _verified_snapshot(root, entry):
    path = safe_inventory_path(root, entry["path"])
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("Mplayer PE input is not a singly linked regular file")
    if metadata.st_size != entry["size"]:
        raise ValueError("unexpected Mplayer PE file size")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != entry["size"] or digest != entry["sha256"]:
        raise ValueError("Mplayer PE size or SHA-256 mismatch")
    return data


def verify(root, entries, objdump="objdump"):
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or not isinstance(entries, list):
        raise ValueError("invalid retail root or inventory")
    index = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid inventory entry")
        if entry["path"] in index:
            raise ValueError("duplicate inventory path")
        index[entry["path"]] = entry

    snapshots = {}
    for name, expected in FILES.items():
        entry = index.get(expected["path"])
        if entry is None or entry.get("size") != expected["size"] or entry.get("sha256") != expected["sha256"]:
            raise ValueError(f"private inventory mismatch for {name}")
        data = _verified_snapshot(root, expected)
        for literal, (offset, address) in expected["literals"].items():
            encoded = b"\\" + literal.encode("ascii") + b"\0"
            if data[offset:offset + len(encoded)] != encoded:
                raise ValueError(f"{literal} literal differs at pinned offset")
            if address != expected["data_va"] + offset - expected["data_file_offset"]:
                raise ValueError("literal VA does not match pinned .data mapping")
        snapshots[name] = data

    copy_entry = index.get(MPRREAL["path"])
    if (copy_entry is None or copy_entry.get("size") != MPRREAL["size"]
            or copy_entry.get("sha256") != MPRREAL["sha256"]):
        raise ValueError("private inventory mismatch for mpreal.dll")
    copy_data = _verified_snapshot(root, MPRREAL)
    if copy_data != snapshots["mpics.dll"]:
        raise ValueError("mpics.dll and mpreal.dll are not byte-identical")

    with tempfile.TemporaryDirectory(prefix="dragonrider-mplayer-ini-") as temporary:
        paths = {}
        for name, data in snapshots.items():
            snapshot = Path(temporary) / name
            snapshot.write_bytes(data)
            paths[name] = snapshot
        disassemblies = {}
        section_outputs = {}
        for name in FILES:
            ranges = ((0x10002A30, 0x10002B5A), (0x1000E5B0, 0x1000E5B6)) if name == "mpics.dll" else (
                (0x10003470, 0x100034E5),
            )
            result_text = []
            for start, stop in ranges:
                result = subprocess.run(
                    [objdump, "-d", "-Mintel", "-w", f"--start-address=0x{start:x}",
                     f"--stop-address=0x{stop:x}", str(paths[name])],
                    check=True, capture_output=True, text=True,
                )
                result_text.append(result.stdout)
            disassemblies[name] = "\n".join(result_text)
            section_outputs[name] = subprocess.run(
                [objdump, "-h", str(paths[name])], check=True,
                capture_output=True, text=True,
            ).stdout
        imports = subprocess.run([objdump, "-p", str(paths["mpics.dll"])],
                                 check=True, capture_output=True, text=True)
        full_disassembly = subprocess.run(
            [objdump, "-d", "-Mintel", "-w", str(paths["mpics.dll"])],
            check=True, capture_output=True, text=True,
        )

    anchors = {name: verify_anchors(disassemblies[name], expected["anchors"])
               for name, expected in FILES.items()}
    sections = {name: verify_data_section(section_outputs[name],
                                          expected["data_file_offset"],
                                          expected["data_va"])
                for name, expected in FILES.items()}
    import_names = {
        "strcat": verify_named_import(imports.stdout, STRCAT_IAT_RVA, "strcat"),
        "GetPrivateProfileStringA": verify_named_import(
            imports.stdout, GET_PRIVATE_PROFILE_STRING_IAT_RVA,
            "GetPrivateProfileStringA"),
    }
    caller_sets = {
        f"0x{target:08x}": [f"0x{address:08x}" for address in sorted(
            direct_callers(full_disassembly.stdout, target))]
        for target in EXPECTED_PROFILE_CALLERS
    }
    if any(set(caller_sets[f"0x{target:08x}"]) != {
            f"0x{address:08x}" for address in expected}
           for target, expected in EXPECTED_PROFILE_CALLERS.items()):
        raise ValueError("direct callers of profile-string helpers changed")
    return {
        "verified_program_sha256": {name: FILES[name]["sha256"] for name in FILES},
        "mpreal_sha256": MPRREAL["sha256"],
        "mpics_mpreal_byte_identical": True,
        "verified_instruction_anchors": anchors,
        "data_section_sizes": {name: f"0x{size:x}" for name, size in sections.items()},
        "mpics_strcat_iat_rva": f"0x{STRCAT_IAT_RVA:x}",
        "profile_string_iat_rva": f"0x{GET_PRIVATE_PROFILE_STRING_IAT_RVA:x}",
        "verified_imports": import_names,
        "direct_callers_of_profile_helpers": caller_sets,
        "mpfaux_helper_target": "0x10004ae0",
        "executed_programs": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="installed US extraction root")
    parser.add_argument("inventory", type=Path, help="private hash inventory JSON")
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("invalid retail inventory document")
    print(json.dumps(verify(args.root, manifest["files"], args.objdump), indent=2))


if __name__ == "__main__":
    main()
