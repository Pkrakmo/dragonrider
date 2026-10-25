#!/usr/bin/env python3
"""Compare a bounded Ghidra reference report with the pinned direct-call set."""

import argparse
from pathlib import Path
import re

from verify_srsc_read_helper_callers import EXPECTED_CALLERS, EXPECTED_SHA256


HEADER = re.compile(
    r"edition=US retail; sha256=([0-9a-f]{64}); Ghidra=12\.1\.4; "
    r"method=analyzed disposable import; read-only reference-manager query; "
    r"confidence=database-dependent"
)
REFERENCE = re.compile(
    r"^\s*([0-9a-fA-F]{8})\s+(\S+)\s+0(?:\s+\(GhidraScript\))?\s*$"
)


def verify_report(text):
    """Validate report provenance and equality with pinned objdump callers."""
    headers = [match for line in text.splitlines()
               if (match := HEADER.search(line)) is not None]
    if len(headers) != 1:
        raise ValueError("expected one US retail Ghidra report header")
    if headers[0].group(1) != EXPECTED_SHA256:
        raise ValueError("Ghidra report executable SHA-256 mismatch")

    lines = text.splitlines()
    target_lines = [i for i, line in enumerate(lines)
                    if "REFERENCES_TO 0045f2d0" in line]
    count_lines = [i for i, line in enumerate(lines)
                   if re.search(r"\bCOUNT\s+[0-9]+\b", line)]
    if len(target_lines) != 1 or len(count_lines) != 1:
        raise ValueError("expected one bounded read-helper reference section")
    start, end = target_lines[0] + 1, count_lines[0]
    if end < start:
        raise ValueError("malformed Ghidra reference section")
    if any("TRUNCATED" in line for line in lines[start:end + 1]):
        raise ValueError("Ghidra reference output was truncated")

    references = []
    for line in lines[start:end]:
        stripped = line.split(">", 1)[-1].strip()
        if not stripped:
            continue
        match = REFERENCE.fullmatch(stripped)
        if match is None:
            raise ValueError("unrecognized Ghidra reference entry")
        address, ref_type = match.groups()
        if ref_type != "UNCONDITIONAL_CALL":
            raise ValueError("non-call reference to bounded read helper")
        references.append(int(address, 16))

    count_match = re.search(r"\bCOUNT\s+([0-9]+)\b", lines[count_lines[0]])
    declared_count = int(count_match.group(1))
    if declared_count != len(references):
        raise ValueError("Ghidra declared reference count does not match entries")
    if len(references) != len(set(references)):
        raise ValueError("duplicate Ghidra call reference")
    observed = set(references)
    if observed != EXPECTED_CALLERS:
        missing = sorted(EXPECTED_CALLERS - observed)
        unexpected = sorted(observed - EXPECTED_CALLERS)
        raise ValueError(
            "Ghidra/objdump direct-call address sets differ "
            f"(missing={[hex(value) for value in missing]}, "
            f"unexpected={[hex(value) for value in unexpected]})"
        )
    return {"sha256": EXPECTED_SHA256, "ghidra_version": "12.1.4",
            "target": "0x0045F2D0", "references": len(references),
            "matched_objdump_addresses": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ghidra_script_log", type=Path)
    args = parser.parse_args()
    report = verify_report(args.ghidra_script_log.read_text(encoding="utf-8"))
    print("Verified Ghidra read-helper xrefs against pinned objdump census: "
          f"{report['references']} matching direct calls; "
          f"SHA-256 {report['sha256']}")


if __name__ == "__main__":
    main()
