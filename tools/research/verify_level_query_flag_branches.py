#!/usr/bin/env python3
"""Verify bounded static flag-branch anchors in the level query helper.

The check is limited to documented instruction addresses in the hash-pinned US
retail executable. It does not model control flow, caller values, or runtime
reachability.
"""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess


EXPECTED_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"
EXPECTED_INSTRUCTIONS = {
    0x0042106A: "test bl,0x10",
    0x0042106F: "cmp DWORD PTR [edx+0x28],0x2",
    0x004212E3: "test bl,0x8",
    0x004212F1: "test bl,0x20",
    0x00421346: "test bl,0x4",
    0x00421349: "jne 0x421392",
    0x00421350: "test bl,0x20",
}

_INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+\s*(\S.*)$")


def instructions(disassembly):
    """Return GNU objdump's normalized instruction text keyed by address."""
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
        [args.objdump, "-d", "-Mintel", "--start-address=0x00420e10",
         "--stop-address=0x004213ea", str(args.executable)],
        check=True, capture_output=True, text=True)
    observed = instructions(completed.stdout)
    mismatches = {
        hex(address): {"expected": expected, "actual": observed.get(address)}
        for address, expected in EXPECTED_INSTRUCTIONS.items()
        if observed.get(address) != expected
    }
    if mismatches:
        raise ValueError(f"query flag-branch anchors differ: {mismatches}")
    print(f"Verified level query flag-branch anchors: {len(EXPECTED_INSTRUCTIONS)}")


if __name__ == "__main__":
    main()
