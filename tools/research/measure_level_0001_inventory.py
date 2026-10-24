#!/usr/bin/env python3
"""Measure selector (1,0,0) block storage across a hash-checked SRSC inventory."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from measure_0102_model_candidates import table as parse_srsc_table
from measure_level_0001 import safe_inventory_path
from measure_level_blocks import measure


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


def measure_inventory(root, entries):
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty or invalid SRSC inventory")
    candidates = defaultdict(Counter)
    file_count = 0
    for entry in entries:
        data = read_verified(root, entry)
        file_count += 1
        table_offset, records = parse_srsc_table(data)
        selected = [record for record in records if record[:3] == (1, 0, 0)]
        if not selected:
            continue
        if len(selected) != 1:
            raise ValueError("expected at most one (1,0,0) record per file")
        _, _, _, start, length = selected[0]
        if start < 12 or start > len(data) or length > len(data) - start:
            raise ValueError("selected level payload is outside file")
        table_end = table_offset + len(records) * 14
        if start < table_end and table_offset < start + length:
            raise ValueError("selected level payload overlaps SRSC table")
        stats = measure(data[start:start + length])
        extension = Path(entry["path"]).suffix.lower()
        summary = candidates[extension]
        summary["files"] += 1
        summary[f"storage_word_{stats[0]}"] += 1
        summary["blocks"] += stats[1]
        summary["zlib_streams"] += stats[2]
    return file_count, candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root is not a directory")
    try:
        entries = json.loads(args.inventory.read_text(encoding="utf-8"))["files"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("invalid inventory") from error
    files, candidates = measure_inventory(root, entries)
    print(json.dumps({
        "files_examined": files,
        "files_with_selector_1_0_0": sum(c["files"] for c in candidates.values()),
        "by_extension": {key: dict(value) for key, value in sorted(candidates.items())},
    }, indent=2))


if __name__ == "__main__":
    main()
