#!/usr/bin/env python3
"""Measure aggregate table ordering of selected cross-kind SRSC links.

The inventory is private.  This tool deliberately emits only documented kind
pair labels and aggregate counts; it never prints inventory paths, file hashes,
selector values, record indexes, or payload bytes.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct


# These are the selected, previously measured same-file relationships.  They
# are labels in output rather than evidence of a semantic interpretation.
KIND_PAIRS = (
    ("0102_to_0101", 0x0102, 0x0101),
    ("0200_to_0201", 0x0200, 0x0201),
    ("0302_to_0301", 0x0302, 0x0301),
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _safe_inventory_path(root, value):
    if not isinstance(value, str):
        raise ValueError("invalid inventory path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("invalid inventory path")
    candidate = root / relative
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError("invalid inventory path") from error
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink in inventory path")
    if not candidate.is_file():
        raise ValueError("inventory path is not a regular file")
    return candidate


def read_records(root, entry):
    """Return bounded table triples from one size/hash-verified file snapshot."""
    if not isinstance(entry, dict) or entry.get("status") != "examined":
        raise ValueError("inventory contains unexamined files")
    expected_size = entry.get("file_size")
    expected_hash = entry.get("sha256")
    if type(expected_size) is not int or expected_size < 0:
        raise ValueError("invalid inventory file size")
    if not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash):
        raise ValueError("invalid inventory hash")
    path = _safe_inventory_path(root, entry.get("path"))
    data = path.read_bytes()
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("inventory size or hash mismatch")
    if len(data) < 12 or data[:4] != b"SRSC":
        raise ValueError("not an SRSC header")
    version, table_offset, count = struct.unpack_from("<HIH", data, 4)
    if version != 0x0100 or not count or table_offset < 12:
        raise ValueError("invalid SRSC header")
    if table_offset > len(data) or count > (len(data) - table_offset) // 14:
        raise ValueError("invalid bounded table")
    table_end = table_offset + count * 14
    raw = data[table_offset:table_end]
    if len(raw) != count * 14:
        raise ValueError("short table read")
    records = list(struct.iter_unpack("<HHHII", raw))
    for _, _, _, payload_offset, payload_length in records:
        if (payload_offset < 12 or payload_offset > table_offset or
                payload_length > table_offset - payload_offset):
            raise ValueError("payload range outside pre-table region")
    return [record[:3] for record in records]


def measure(records):
    """Classify selected cross-kind links by target table position."""
    result = {}
    for label, source_kind, target_kind in KIND_PAIRS:
        targets = defaultdict(list)
        for index, (first, second, _) in enumerate(records):
            if first == target_kind:
                targets[second].append(index)
        counts = Counter({
            "source_records": 0,
            "unique_relations": 0,
            "missing_targets": 0,
            "duplicate_targets": 0,
            "target_before_source": 0,
            "source_before_target": 0,
            "same_position": 0,
        })
        for source_index, (first, _, third) in enumerate(records):
            if first != source_kind:
                continue
            counts["source_records"] += 1
            matches = targets[third]
            if not matches:
                counts["missing_targets"] += 1
            elif len(matches) != 1:
                counts["duplicate_targets"] += 1
            else:
                counts["unique_relations"] += 1
                target_index = matches[0]
                if target_index < source_index:
                    counts["target_before_source"] += 1
                elif source_index < target_index:
                    counts["source_before_target"] += 1
                else:
                    counts["same_position"] += 1
        result[label] = counts
    return result


def measure_0200_plus_four_first_selector(records):
    """Measure the row i+4 first selector for first-match 0x0200 pair keys."""
    first_matches = {}
    for index, (first, second, _) in enumerate(records):
        if first == 0x0200:
            first_matches.setdefault((first, second), index)
    pair_rows = sum(first == 0x0200 for first, _, _ in records)
    counts = Counter({
        "0200_pair_rows": pair_rows,
        "unique_pair_keys": len(first_matches),
        "duplicate_pair_rows": pair_rows - len(first_matches),
        "first_selector_0208_rows": sum(first == 0x0208 for first, _, _ in records),
        "successor_in_bounds": 0,
        "successor_first_selector_0208": 0,
        "successor_first_selector_other": 0,
        "successor_out_of_bounds": 0,
    })
    for index in first_matches.values():
        successor = index + 4
        if successor >= len(records):
            counts["successor_out_of_bounds"] += 1
            continue
        counts["successor_in_bounds"] += 1
        if records[successor][0] == 0x0208:
            counts["successor_first_selector_0208"] += 1
        else:
            counts["successor_first_selector_other"] += 1
    return counts


def aggregate_file_completeness(records, totals):
    """Update per-file relationship completeness without retaining file IDs."""
    per_file = measure(records)
    for label, counts in per_file.items():
        if not counts["source_records"]:
            continue
        aggregate = totals[label]
        aggregate["files_with_sources"] += 1
        aggregate["files_all_sources_unique"] += (
            counts["unique_relations"] == counts["source_records"])
        aggregate["files_with_missing_targets"] += counts["missing_targets"] > 0
        aggregate["files_with_duplicate_targets"] += counts["duplicate_targets"] > 0
    return per_file


def load_inventory(path):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
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
    entries = load_inventory(args.inventory)
    relationship_totals = {label: Counter() for label, _, _ in KIND_PAIRS}
    completeness = {label: Counter() for label, _, _ in KIND_PAIRS}
    successor_totals = Counter()
    for entry in entries:
        records = read_records(root, entry)
        successor_totals.update(measure_0200_plus_four_first_selector(records))
        per_file = aggregate_file_completeness(records, completeness)
        for label, counts in per_file.items():
            relationship_totals[label].update(counts)
    print(json.dumps({
        "files_examined": len(entries),
        "kind_pairs": relationship_totals,
        "per_file_completeness": completeness,
        "0200_first_match_i_plus_4_first_selector": successor_totals,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
