#!/usr/bin/env python3
"""Measure record-range layout across an explicitly hash-checked SRSC inventory.

The output is an aggregate observation, not an SRSC acceptance validator.
"""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from measure_0102_model_candidates import table as parse_table
from measure_level_0001 import load_inventory, safe_inventory_path


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def read_verified(root, entry):
    if not isinstance(entry, dict) or entry.get("status") != "examined":
        raise ValueError("inventory contains an unexamined file")
    size = entry.get("file_size")
    digest = entry.get("sha256")
    if type(size) is not int or size < 0:
        raise ValueError("invalid inventory file size")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError("invalid inventory hash")
    path = safe_inventory_path(root, entry.get("path"))
    data = path.read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("inventory size or hash mismatch")
    return data


def measure_file(data):
    table_offset, records = parse_table(data)
    table_end = table_offset + len(records) * 14
    ranges = [(start, start + length) for _, _, _, start, length in records]
    pairs = list(zip(ranges, ranges[1:]))
    within = [12 <= start <= end <= table_offset for start, end in ranges]
    transitions = Counter(
        "contiguous" if left[1] == right[0]
        else "gap" if left[1] < right[0]
        else "overlap"
        for left, right in pairs
    )
    return {
        "records": len(records),
        "ranges_within_payload": sum(within),
        "invalid_ranges": len(ranges) - sum(within),
        "zero_lengths": sum(start == end for start, end in ranges),
        "maximum_start_offset": max(start for start, _ in ranges),
        "maximum_range_end": max(end for _, end in ranges),
        "maximum_range_length": max(end - start for start, end in ranges),
        "first_starts_at_header_end": ranges[0][0] == 12,
        "last_ends_at_table_start": ranges[-1][1] == table_offset,
        "table_ends_at_eof": table_end == len(data),
        "nondecreasing_starts": sum(left[0] <= right[0] for left, right in pairs),
        "pairs": len(pairs),
        "transitions": dict(transitions),
    }


def measure_inventory(root, entries):
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty or invalid SRSC inventory")
    by_extension = defaultdict(Counter)
    seen_paths = set()
    files = 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid inventory path")
        if entry["path"] in seen_paths:
            raise ValueError("duplicate inventory path")
        seen_paths.add(entry["path"])
        data = read_verified(root, entry)
        files += 1
        metrics = measure_file(data)
        result = by_extension[Path(entry["path"]).suffix.lower()]
        result["files"] += 1
        for key in ("records", "ranges_within_payload", "invalid_ranges", "zero_lengths",
                    "nondecreasing_starts", "pairs"):
            result[key] += metrics[key]
        for key in ("maximum_start_offset", "maximum_range_end", "maximum_range_length"):
            result[key] = max(result[key], metrics[key])
        for key in ("first_starts_at_header_end", "last_ends_at_table_start", "table_ends_at_eof"):
            result[f"files_{key}"] += metrics[key]
        for transition, count in metrics["transitions"].items():
            result[f"pair_{transition}"] += count
        is_partition = (
            metrics["invalid_ranges"] == 0
            and metrics["first_starts_at_header_end"]
            and metrics["last_ends_at_table_start"]
            and metrics["transitions"].get("contiguous", 0) == metrics["pairs"]
        )
        result["files_partitioning_payload"] += is_partition
    return files, {key: dict(value) for key, value in sorted(by_extension.items())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root is not a directory")
    files, by_extension = measure_inventory(root, load_inventory(args.inventory))
    print(json.dumps({"files_examined": files, "by_extension": by_extension}, indent=2))


if __name__ == "__main__":
    main()
