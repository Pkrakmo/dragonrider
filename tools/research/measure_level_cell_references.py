#!/usr/bin/env python3
"""Aggregate selector (1,0,0) cell reference pairs from verified levels."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from measure_0102_model_candidates import table
from measure_level_0001 import safe_inventory_path
from measure_level_blocks import measure

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def measure_inventory(root, entries):
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty or invalid inventory")
    summary = Counter()
    identifiers = set()
    selected_files = 0
    selected_paths = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid inventory entry")
        if Path(entry["path"]).suffix.lower() != ".lvl":
            continue
        if entry["path"] in selected_paths:
            raise ValueError("duplicate level inventory path")
        selected_paths.add(entry["path"])
        digest, size = entry.get("sha256"), entry.get("size")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError("invalid inventory hash")
        if type(size) is not int or size < 12:
            raise ValueError("invalid inventory size")
        data = safe_inventory_path(root, entry["path"]).read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("inventory size or hash mismatch")
        _, records = table(data)
        matches = [record for record in records if record[:3] == (1, 0, 0)]
        if len(matches) != 1:
            raise ValueError("expected one (1,0,0) record per level")
        _, _, _, start, length = matches[0]
        if start < 12 or start > len(data) or length > len(data) - start:
            raise ValueError("level payload outside file")
        cells = 0

        def inspect_cell(_entry, _prefix, _index, cell):
            nonlocal cells
            flags, first, second = cell[:3]
            cells += 1
            summary["flagged_cells"] += bool(flags)
            summary["equal_reference_pairs"] += first == second
            for value in (first, second):
                summary["reference_values"] += 1
                # The shared decoder exposes these two dwords as signed i32.
                # Negative therefore indicates the serialized high bit is set.
                summary["high_bit_reference_values"] += value < 0
                summary["zero_reference_values"] += value == 0
                identifiers.add(value)

        measure(data[start:start + length], on_cell_detail=inspect_cell)
        selected_files += 1
        summary["cells"] += cells
    if selected_files == 0:
        raise ValueError("inventory contains no level candidates")
    summary["selected_levels"] = selected_files
    summary["distinct_reference_values"] = len(identifiers)
    summary["different_reference_pairs"] = summary["cells"] - summary["equal_reference_pairs"]
    return dict(sorted(summary.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    try:
        entries = json.loads(args.inventory.read_text(encoding="utf-8"))["files"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise SystemExit(f"invalid inventory: {error}") from error
    print(json.dumps(measure_inventory(root, entries), indent=2))


if __name__ == "__main__":
    main()
