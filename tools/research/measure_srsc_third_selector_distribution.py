#!/usr/bin/env python3
"""Measure aggregate third-selector relationships in hash-checked SRSC tables.

The output deliberately contains only selector-kind labels and aggregate counts.
It neither reads payload bytes nor reports container paths, hashes, selector values,
or payload contents.  A relationship is a same-file comparison to a second
selector word; it is not a claim about runtime lookup or field semantics.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct


SELECTED_KINDS = (0x0101, 0x0102, 0x0200, 0x0201, 0x0301, 0x0302)
CROSS_KIND_TARGETS = {0x0102: 0x0101, 0x0200: 0x0201, 0x0302: 0x0301}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RECORD = struct.Struct("<HHHII")
_HEADER = struct.Struct("<4sHIH")


def _new_counts():
    return Counter({
        "records": 0,
        "third_zero": 0,
        "third_nonzero": 0,
        "nonzero_no_second_match": 0,
        "nonzero_one_second_match": 0,
        "nonzero_multiple_second_matches": 0,
    })


def _add_relationship(counts, matches):
    if matches == 0:
        counts["nonzero_no_second_match"] += 1
    elif matches == 1:
        counts["nonzero_one_second_match"] += 1
    else:
        counts["nonzero_multiple_second_matches"] += 1


def measure(records):
    """Return aggregate own- and selected-cross-kind second-word relationships."""
    seconds = {kind: Counter() for kind in SELECTED_KINDS}
    for kind, second, _, _, _ in records:
        if kind in seconds:
            seconds[kind][second] += 1

    own = {f"{kind:04x}": _new_counts() for kind in SELECTED_KINDS}
    cross = {
        f"{source:04x}_to_{target:04x}": _new_counts()
        for source, target in CROSS_KIND_TARGETS.items()
    }
    for kind, second, third, _, _ in records:
        if kind not in seconds:
            continue
        own_counts = own[f"{kind:04x}"]
        own_counts["records"] += 1
        if third == 0:
            own_counts["third_zero"] += 1
        else:
            own_counts["third_nonzero"] += 1
            _add_relationship(own_counts, seconds[kind][third])

        target = CROSS_KIND_TARGETS.get(kind)
        if target is None:
            continue
        cross_counts = cross[f"{kind:04x}_to_{target:04x}"]
        cross_counts["records"] += 1
        if third == 0:
            cross_counts["third_zero"] += 1
        else:
            cross_counts["third_nonzero"] += 1
            _add_relationship(cross_counts, seconds[target][third])
    return {"own_kind": own, "selected_cross_kind": cross}


def _relative_path(root, value):
    if not isinstance(value, str) or not value:
        raise ValueError("invalid inventory path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("invalid inventory path")
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ValueError("invalid inventory path") from error
    if not resolved.is_file():
        raise ValueError("inventory path is not a regular file")
    return resolved


def read_verified_records(root, entry):
    """Validate one inventory entry and return only its five table fields."""
    if not isinstance(entry, dict) or entry.get("status") != "examined":
        raise ValueError("inventory contains unexamined file")
    expected = entry.get("sha256")
    if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
        raise ValueError("invalid inventory hash")
    path = _relative_path(root, entry.get("path"))
    size = path.stat().st_size
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != expected:
        raise ValueError("inventory hash mismatch")

    with path.open("rb") as stream:
        header = stream.read(_HEADER.size)
        if len(header) != _HEADER.size:
            raise ValueError("short SRSC header")
        magic, version, table_offset, count = _HEADER.unpack(header)
        if magic != b"SRSC" or version != 0x0100 or count == 0:
            raise ValueError("invalid SRSC header")
        table_size = count * _RECORD.size
        table_end = table_offset + table_size
        if table_offset < _HEADER.size or table_end > size:
            raise ValueError("invalid bounded table")
        stream.seek(table_offset)
        raw = stream.read(table_size)
        if len(raw) != table_size:
            raise ValueError("short SRSC table")
    records = list(_RECORD.iter_unpack(raw))
    for _, _, _, start, length in records:
        payload_end = start + length
        if start < _HEADER.size or start > table_offset or payload_end > table_offset:
            raise ValueError("record payload outside pre-table region")
    return records


def load_entries(inventory):
    try:
        decoded = json.loads(inventory.read_text(encoding="utf-8"))
        entries = decoded["files"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("invalid inventory") from error
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty or invalid inventory")
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root is not a directory")
    totals = measure(())
    for entry in load_entries(args.inventory):
        per_file = measure(read_verified_records(root, entry))
        for scope in totals:
            for key, counts in totals[scope].items():
                counts.update(per_file[scope][key])
    print(json.dumps({"files_examined": len(load_entries(args.inventory)), **totals},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
