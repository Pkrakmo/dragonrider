#!/usr/bin/env python3
"""Measure aggregate reuse of selector (1,0,0) cell keys across US levels.

The report contains only counts. It does not expose key values or file paths,
and does not infer that equal serialized values identify equal runtime objects.
"""

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
MAX_INPUT_SIZE = 256 * 1024 * 1024  # Per-file ceiling; snapshots read at most expected size + 1.


def measure_inventory(root, entries):
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty or invalid inventory")

    keys_by_level = []
    seen_paths = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid inventory entry")
        path = entry["path"]
        if Path(path).suffix.lower() != ".lvl":
            continue
        if path in seen_paths:
            raise ValueError("duplicate level inventory path")
        seen_paths.add(path)

        size, digest = entry.get("size"), entry.get("sha256")
        if type(size) is not int or size < 12:
            raise ValueError("invalid inventory size")
        if size > MAX_INPUT_SIZE:
            raise ValueError("inventory file exceeds 256 MiB limit")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError("invalid inventory hash")
        source = safe_inventory_path(root, path)
        actual_size = source.stat().st_size
        if actual_size > MAX_INPUT_SIZE:
            raise ValueError("input file exceeds 256 MiB limit")
        if actual_size != size:
            raise ValueError("inventory size or hash mismatch")
        with source.open("rb") as stream:
            data = stream.read(size + 1)
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("inventory size or hash mismatch")

        _, records = table(data)
        matches = [record for record in records if record[:3] == (1, 0, 0)]
        if len(matches) != 1:
            raise ValueError("expected one (1,0,0) record per level")
        _, _, _, start, length = matches[0]
        if start < 12 or start > len(data) or length > len(data) - start:
            raise ValueError("level payload outside file")

        keys = set()

        def collect(_entry, _prefix, _index, cell):
            keys.update(cell[1:3])

        measure(data[start:start + length], on_cell_detail=collect)
        keys_by_level.append(keys)

    if not keys_by_level:
        raise ValueError("inventory contains no level candidates")

    level_counts = Counter()
    for keys in keys_by_level:
        level_counts.update(keys)
    pairwise_sharing = sum(
        bool(keys_by_level[left] & keys_by_level[right])
        for left in range(len(keys_by_level))
        for right in range(left + 1, len(keys_by_level))
    )
    return {
        "selected_levels": len(keys_by_level),
        "distinct_keys_within_levels_total": sum(map(len, keys_by_level)),
        "distinct_keys_across_levels": len(level_counts),
        "keys_present_in_multiple_levels": sum(count > 1 for count in level_counts.values()),
        "extra_level_occurrences": sum(count - 1 for count in level_counts.values()),
        "level_pairs_with_shared_keys": pairwise_sharing,
        "possible_level_pairs": len(keys_by_level) * (len(keys_by_level) - 1) // 2,
        "maximum_levels_sharing_one_key": max(level_counts.values(), default=0),
    }


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
        raise SystemExit(f"invalid inventory: {error}") from error
    print(json.dumps(measure_inventory(root, entries), indent=2))


if __name__ == "__main__":
    main()
