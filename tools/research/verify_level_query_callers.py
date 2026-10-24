#!/usr/bin/env python3
"""Verify the documented direct-call inventory for the level query helper.

This is a narrow, static regression check for the unpatched US executable. It
does not identify function boundaries, infer argument values, or rule out
indirect callers.
"""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess


EXPECTED_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"
QUERY_HELPER = 0x00420E10
EXPECTED_CALLERS = frozenset({
    0x00403623, 0x0040374E, 0x00403820, 0x004038D2, 0x004039A9,
    0x00403A23, 0x0040489C, 0x0041F62E, 0x0041F7C3, 0x004205DF,
    0x00420694, 0x004207F0, 0x00420D93, 0x00420DAB, 0x0043FEF2,
    0x00441444, 0x00441734, 0x0044C49F, 0x0044C5D2, 0x0044C742,
    0x0044C8A0, 0x0044C95F, 0x0044CB63,
})

_CALL = re.compile(r"^\s*([0-9a-fA-F]+):.*\bcall\s+0x([0-9a-fA-F]+)\b")
_JMP = re.compile(r"^\s*([0-9a-fA-F]+):.*\bjmp\s+0x([0-9a-fA-F]+)\b")


def direct_callers(disassembly, target=QUERY_HELPER):
    """Extract direct call addresses to *target* from GNU objdump text."""
    result = set()
    for line in disassembly.splitlines():
        match = _CALL.match(line)
        if match and int(match.group(2), 16) == target:
            result.add(int(match.group(1), 16))
    return result


def direct_jumps(disassembly, target=QUERY_HELPER):
    """Extract direct unconditional jumps to *target* from GNU objdump text."""
    result = set()
    for line in disassembly.splitlines():
        match = _JMP.match(line)
        if match and int(match.group(2), 16) == target:
            result.add(int(match.group(1), 16))
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
    actual_hash = sha256_file(args.executable)
    if actual_hash != EXPECTED_SHA256:
        raise ValueError("unexpected executable SHA-256")
    completed = subprocess.run(
        [args.objdump, "-d", "-Mintel", str(args.executable)],
        check=True, capture_output=True, text=True)
    observed = direct_callers(completed.stdout)
    jumps = direct_jumps(completed.stdout)
    if observed != EXPECTED_CALLERS:
        missing = sorted(EXPECTED_CALLERS - observed)
        unexpected = sorted(observed - EXPECTED_CALLERS)
        raise ValueError(
            "direct query-helper caller inventory differs "
            f"(missing={[hex(value) for value in missing]}, "
            f"unexpected={[hex(value) for value in unexpected]})")
    if jumps:
        raise ValueError(
            "unexpected direct query-helper jumps "
            f"({[hex(value) for value in sorted(jumps)]})")
    print(f"Verified direct transfers to 0x{QUERY_HELPER:08x}: "
          f"{len(observed)} calls, {len(jumps)} unconditional jumps")


if __name__ == "__main__":
    main()
