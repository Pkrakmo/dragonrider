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
import struct

from measure_level_0001 import safe_inventory_path


SELECTED_KINDS = (0x0030, 0x0051, 0x0101, 0x0102, 0x0200, 0x0201, 0x0301, 0x0302)
CROSS_KIND_TARGETS = {0x0102: 0x0101, 0x0200: 0x0201, 0x0302: 0x0301}
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


def read_verified_records(root, entry):
    """Validate one file once and return records from that byte snapshot."""
    if not isinstance(entry, dict) or entry.get("status") != "examined":
        raise ValueError("inventory contains unexamined file")
    expected_size = entry.get("file_size")
    expected = entry.get("sha256")
    if type(expected_size) is not int or expected_size < 0:
        raise ValueError("invalid inventory file size")
    if not isinstance(expected, str) or len(expected) != 64 or any(
            character not in "0123456789abcdef" for character in expected):
        raise ValueError("invalid inventory hash")
    path = safe_inventory_path(root, entry.get("path"))
    data = path.read_bytes()
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("inventory size or hash mismatch")
    if len(data) < _HEADER.size:
        raise ValueError("short SRSC header")
    magic, version, table_offset, count = _HEADER.unpack_from(data)
    if magic != b"SRSC" or version != 0x0100 or count == 0:
        raise ValueError("invalid SRSC header")
    table_size = count * _RECORD.size
    table_end = table_offset + table_size
    if table_offset < _HEADER.size or table_end > len(data):
        raise ValueError("invalid bounded table")
    raw = data[table_offset:table_end]
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
    entries = load_entries(args.inventory)
    totals = measure(())
    seen_paths = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid inventory path")
        if entry["path"] in seen_paths:
            raise ValueError("duplicate inventory path")
        seen_paths.add(entry["path"])
        per_file = measure(read_verified_records(root, entry))
        for scope in totals:
            for key, counts in totals[scope].items():
                counts.update(per_file[scope][key])
    print(json.dumps({"files_examined": len(entries), **totals},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
