#!/usr/bin/env python3
"""Verify one pinned selector consumer and measure its tuple in a private inventory."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from measure_level_0001 import safe_inventory_path

EXPECTED_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"
SELECTOR = (0x22, 0, 0)
CONSUMER_ENTRY = 0x0040E3B0
LOOKUP_ROUTINE = 0x0045F0D0
EXPECTED_LOOKUP_CALLERS = 26
EXPECTED_LOOKUP_SITE = 0x0040E3CA
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED = {
    0x0040E3B8: "xor ebp,ebp",
    0x0040E3C4: "push ebp",
    0x0040E3C5: "push ebp",
    0x0040E3C6: "push 0x22",
    0x0040E3CA: "call 0x45f0d0",
    0x0040E3CF: "test eax,eax",
    0x0040E3D1: "je 0x40e3e1",
    0x0040E425: "call 0x45f370",
    0x0040E450: "push 0x200",
    0x0040E458: "call 0x45f430",
    0x0040E477: "call DWORD PTR [eax+0x4]",
    0x0040E494: "call DWORD PTR [eax+0x30]",
    0x0045F37B: "mov DWORD PTR [esp+0x8],0x4",
    0x0045F383: "call 0x45f2d0",
}

_INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+\s*(\S.*)$")


def parse_instructions(text):
    result = {}
    for line in text.splitlines():
        match = _INSTRUCTION.match(line)
        if match:
            result[int(match.group(1), 16)] = " ".join(match.group(2).split())
    return result


def direct_references(instructions, mnemonic, target):
    if mnemonic not in {"call", "jmp"}:
        raise ValueError("mnemonic must be call or jmp")
    pattern = re.compile(rf"^{mnemonic} 0x([0-9a-fA-F]+)$")
    return {address for address, line in instructions.items()
            if (match := pattern.fullmatch(line)) and int(match.group(1), 16) == target}


def selector_records(data):
    """Return bounded (record index, payload offset, payload size) tuple matches."""
    if len(data) < 12 or data[:4] != b"SRSC":
        raise ValueError("invalid SRSC header")
    version, table, count = struct.unpack_from("<HIH", data, 4)
    if version != 0x100 or table < 12 or table > len(data) or count > (len(data) - table) // 14:
        raise ValueError("invalid SRSC table bounds")
    matches = []
    for index, (first, second, third, offset, size) in enumerate(
            struct.iter_unpack("<HHHII", data[table:table + count * 14])):
        if (first, second, third) == SELECTOR:
            if offset > len(data) or size > len(data) - offset:
                raise ValueError("selected payload outside file bounds")
            matches.append((index, offset, size))
    return matches


def verify_executable(path, objdump="objdump"):
    if path.is_symlink() or not path.is_file():
        raise ValueError("executable must be a regular non-symlink file")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError("unexpected executable SHA-256")
    with tempfile.TemporaryDirectory(prefix="dragonrider-selector-0022-") as temporary:
        snapshot = Path(temporary) / "verified.exe"
        snapshot.write_bytes(data)
        disassembly = subprocess.run([objdump, "-d", "-Mintel", str(snapshot)],
                                     check=True, capture_output=True, text=True).stdout
    observed = parse_instructions(disassembly)
    mismatches = {hex(address): {"expected": expected, "actual": observed.get(address)}
                  for address, expected in EXPECTED.items()
                  if observed.get(address) != expected}
    if mismatches:
        raise ValueError(f"selector consumer instruction anchors differ: {mismatches}")
    lookup_calls = direct_references(observed, "call", LOOKUP_ROUTINE)
    lookup_jumps = direct_references(observed, "jmp", LOOKUP_ROUTINE)
    consumer_calls = direct_references(observed, "call", CONSUMER_ENTRY)
    consumer_jumps = direct_references(observed, "jmp", CONSUMER_ENTRY)
    if len(lookup_calls) != EXPECTED_LOOKUP_CALLERS or EXPECTED_LOOKUP_SITE not in lookup_calls:
        raise ValueError("direct-call references to the selected lookup have changed")
    if lookup_jumps or consumer_calls or consumer_jumps:
        raise ValueError("unexpected direct jump/caller to the bounded consumer addresses")
    return {"sha256": digest, "lookup_direct_calls": len(lookup_calls),
            "lookup_direct_jumps": len(lookup_jumps),
            "consumer_entry_direct_calls": len(consumer_calls),
            "consumer_entry_direct_jumps": len(consumer_jumps)}


def measure_inventory(root, entries):
    root = root.resolve(strict=True)
    files = Counter()
    selectors = Counter()
    by_extension = Counter()
    seen_paths = set()
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("status") != "examined":
            raise ValueError("inventory contains an unexamined or invalid entry")
        relative = entry.get("path")
        if not isinstance(relative, str):
            raise ValueError("invalid inventory path")
        if relative in seen_paths:
            raise ValueError("inventory contains duplicate paths")
        path = safe_inventory_path(root, relative)
        data = path.read_bytes()
        expected_hash = entry.get("sha256")
        expected_size = entry.get("file_size", entry.get("size"))
        if (not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash)
                or type(expected_size) is not int or expected_size < 0
                or len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_hash):
            raise ValueError("inventory file size or SHA-256 mismatch")
        seen_paths.add(relative)
        matches = selector_records(data)
        files["total"] += 1
        by_extension[path.suffix.lower() or "<none>"] += 1
        if matches:
            files["with_selector"] += 1
            selectors["records"] += len(matches)
            selectors["files"] += 1
    return {"files": dict(files), "selector_records": dict(selectors),
            "files_by_extension": dict(sorted(by_extension.items()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    binary_evidence = verify_executable(args.executable, args.objdump)
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("inventory must contain a nonempty files list")
    result = measure_inventory(args.root, files)
    print(json.dumps({"edition": "US retail", "executable_sha256": binary_evidence["sha256"],
                      "method": "GNU objdump bounded instruction anchors; inventory size/hash-checked SRSC scan",
                      "callsite": "0x0040E3CA", "selector": ["0x0022", "0x0000", "0x0000"],
                      "direct_reference_scan": {k: v for k, v in binary_evidence.items()
                                                 if k != "sha256"},
                      **result}, indent=2))


if __name__ == "__main__":
    main()
