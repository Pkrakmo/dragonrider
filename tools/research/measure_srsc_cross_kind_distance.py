#!/usr/bin/env python3
"""Measure aggregate table-index distances for selected SRSC relationships.

The private inventory is hash-checked before parsing.  Output contains only
documented kind-pair labels and aggregate categories: never paths, hashes,
selector values, table indexes, or payload bytes.  A same-file second-word
equality is structural evidence only; it does not establish lookup semantics.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct


KIND_PAIRS = (
    ("0102_to_0101", 0x0102, 0x0101),
    ("0200_to_0201", 0x0200, 0x0201),
    ("0302_to_0301", 0x0302, 0x0301),
)
_HEADER = struct.Struct("<4sHIH")
_RECORD = struct.Struct("<HHHII")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_SNAPSHOT_SIZE = 256 * 1024 * 1024


def _safe_path(root, value):
    if not isinstance(value, str) or not value:
        raise ValueError("invalid inventory path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("invalid inventory path")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink in inventory path")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ValueError("invalid inventory path") from error
    if not resolved.is_file():
        raise ValueError("inventory path is not a regular file")
    return resolved


def read_verified_records(root, entry):
    """Return a complete validated record table for one examined inventory item."""
    if not isinstance(entry, dict) or entry.get("status") != "examined":
        raise ValueError("inventory contains unexamined file")
    expected = entry.get("sha256")
    if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
        raise ValueError("invalid inventory hash")
    relative = entry.get("path")
    path = _safe_path(root, relative)
    expected_size = entry.get("file_size", entry.get("size"))
    if expected_size is not None and (type(expected_size) is not int or expected_size < 0):
        raise ValueError("invalid inventory size")
    size = path.stat().st_size if expected_size is None else expected_size
    if size > MAX_SNAPSHOT_SIZE:
        raise ValueError("inventory size exceeds snapshot limit")
    if path.stat().st_size != size:
        raise ValueError("inventory hash mismatch or size mismatch")
    with path.open("rb") as stream:
        contents = stream.read(size + 1)
    if len(contents) != size or hashlib.sha256(contents).hexdigest() != expected:
        raise ValueError("inventory hash mismatch or size mismatch")
    if len(contents) < _HEADER.size:
        raise ValueError("short SRSC header")
    magic, version, table_offset, count = _HEADER.unpack_from(contents)
    if magic != b"SRSC" or version != 0x0100 or count == 0:
        raise ValueError("invalid SRSC header")
    table_size = count * _RECORD.size
    table_end = table_offset + table_size
    if table_offset < _HEADER.size or table_end > size:
        raise ValueError("invalid bounded table")
    records = list(_RECORD.iter_unpack(contents[table_offset:table_end]))
    if len(records) != count:
        raise ValueError("short SRSC table")
    for _, _, _, payload_offset, payload_length in records:
        payload_end = payload_offset + payload_length
        if (payload_offset < _HEADER.size or payload_offset > table_offset or
                payload_end > table_offset):
            raise ValueError("record payload outside pre-table region")
    return records


def _counts():
    return Counter({
        "source_records": 0,
        "unique_relations": 0,
        "missing_targets": 0,
        "ambiguous_targets": 0,
        "target_before_source": 0,
        "source_before_target": 0,
        "distance_zero": 0,
        "distance_1": 0,
        "distance_2_to_4": 0,
        "distance_5_to_16": 0,
        "distance_17_plus": 0,
    })


def _distance_bucket(distance):
    if distance == 0:
        return "distance_zero"
    if distance == 1:
        return "distance_1"
    if distance <= 4:
        return "distance_2_to_4"
    if distance <= 16:
        return "distance_5_to_16"
    return "distance_17_plus"


def measure(records):
    """Classify only selected unique same-file links by direction and distance."""
    result = {}
    for label, source_kind, target_kind in KIND_PAIRS:
        targets = defaultdict(list)
        for index, (kind, second, _, _, _) in enumerate(records):
            if kind == target_kind:
                targets[second].append(index)
        counts = _counts()
        for source_index, (kind, _, third, _, _) in enumerate(records):
            if kind != source_kind:
                continue
            counts["source_records"] += 1
            matches = targets[third]
            if not matches:
                counts["missing_targets"] += 1
            elif len(matches) != 1:
                counts["ambiguous_targets"] += 1
            else:
                target_index = matches[0]
                counts["unique_relations"] += 1
                if target_index < source_index:
                    counts["target_before_source"] += 1
                elif source_index < target_index:
                    counts["source_before_target"] += 1
                counts[_distance_bucket(abs(target_index - source_index))] += 1
        result[label] = counts
    return result


def add_file_categories(records, totals):
    """Aggregate per-file complete/missing/ambiguous categories without file IDs."""
    per_file = measure(records)
    for label, counts in per_file.items():
        if not counts["source_records"]:
            continue
        category = totals[label]
        category["files_with_sources"] += 1
        category["files_complete"] += counts["unique_relations"] == counts["source_records"]
        category["files_with_missing_targets"] += counts["missing_targets"] > 0
        category["files_with_ambiguous_targets"] += counts["ambiguous_targets"] > 0
    return per_file


def load_entries(inventory):
    try:
        document = json.loads(inventory.read_text(encoding="utf-8"))
        entries = document["files"]
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
    totals = {label: _counts() for label, _, _ in KIND_PAIRS}
    categories = {label: Counter() for label, _, _ in KIND_PAIRS}
    for entry in entries:
        per_file = add_file_categories(read_verified_records(root, entry), categories)
        for label, counts in per_file.items():
            totals[label].update(counts)
    print(json.dumps({"files_examined": len(entries), "kind_pairs": totals,
                      "per_file_categories": categories}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
