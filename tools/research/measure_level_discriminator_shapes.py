#!/usr/bin/env python3
"""Measure raw `(1,0,0)` entry dimensions by observed discriminator value.

This is a bounded inventory measurement, not a claim that any field is a
world-space coordinate, object class, or rendering mode.
"""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import struct

from measure_0102_model_candidates import table
from measure_level_0001 import load_inventory
from measure_level_entry_modes import level_inventory_entries, read_verified_level


_MAX_ENTRIES = 4096
_MAX_DIMENSION = 32 * 1024 * 1024


def decode(payload):
    """Return raw dimensions and discriminator values from the traced prefix."""
    cursor = 0

    def take(size):
        nonlocal cursor
        if size < 0 or size > len(payload) - cursor:
            raise ValueError("truncated level prefix")
        value = payload[cursor:cursor + size]
        cursor += size
        return value

    def u32():
        return struct.unpack("<I", take(4))[0]

    count = u32()
    if count > _MAX_ENTRIES:
        raise ValueError("outer entry count exceeds measurement limit")
    entries = []
    for _ in range(count):
        first = struct.unpack("<7I", take(28))
        width, height, discriminator = first[1], first[2], first[3]
        if width > _MAX_DIMENSION or height > _MAX_DIMENSION:
            raise ValueError("dimension exceeds measurement limit")
        name_length = struct.unpack("<H", take(2))[0]
        take(name_length)
        take(24)
        inner_count = u32()
        if inner_count > _MAX_ENTRIES:
            raise ValueError("inner entry count exceeds measurement limit")
        take(inner_count * 4)
        entries.append((width, height, discriminator))
    return entries, len(payload) - cursor


def measure(data):
    table_offset, records = table(data)
    selected = [record for record in records if record[:3] == (1, 0, 0)]
    if len(selected) != 1:
        raise ValueError("expected exactly one (1,0,0) record")
    _, _, _, start, length = selected[0]
    if start < 12 or start > len(data) or length > len(data) - start:
        raise ValueError("level payload outside file")
    table_end = table_offset + len(records) * 14
    if start < table_end and table_offset < start + length:
        raise ValueError("level payload overlaps SRSC table")
    return decode(memoryview(data)[start:start + length])


def summarize(entries):
    """Aggregate dimensions without emitting private file paths or raw values."""
    result = defaultdict(Counter)
    for width, height, discriminator in entries:
        summary = result[discriminator]
        summary["entries"] += 1
        summary["zero_width"] += width == 0
        summary["zero_height"] += height == 0
        summary["zero_area"] += width == 0 or height == 0
        summary["grid_items"] += (width + 1) * (height + 1)
        summary["cell_items"] += width * height
        summary["max_width"] = max(summary["max_width"], width)
        summary["max_height"] = max(summary["max_height"], height)
    return {str(key): dict(value) for key, value in sorted(result.items())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root is not a directory")
    all_entries = []
    trailing = 0
    files = level_inventory_entries(load_inventory(args.inventory))
    for item in files:
        entries, remaining = measure(read_verified_level(root, item))
        all_entries.extend(entries)
        trailing += remaining
    print(json.dumps({
        "files_examined": len(files),
        "entries": len(all_entries),
        "unparsed_trailing_bytes": trailing,
        "by_discriminator": summarize(all_entries),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
