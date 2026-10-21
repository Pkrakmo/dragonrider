#!/usr/bin/env python3
"""Measure only the first selector-0x20 object lookup dword in US levels.

This does not parse subsequent variable-length objects or infer runtime state.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified
from verify_level_entry import selected


def first_lookup_dword(payload):
    """Return (declared object count, first raw lookup dword or None)."""
    if len(payload) < 2:
        raise ValueError("selector-0x20 payload has no count")
    count = struct.unpack_from("<H", payload)[0]
    if not count:
        return count, None
    # The traced reader takes two preceding dwords, then the lookup dword.
    if len(payload) < 14:
        raise ValueError("selector-0x20 first object prefix is truncated")
    return count, struct.unpack_from("<I", payload, 10)[0]


def selected_payload(data):
    end, records = table(data)
    matches = [record for record in records if record[:3] == (0x20, 0, 0)]
    if len(matches) != 1:
        raise ValueError("expected exactly one selector-(0x20,0,0) record")
    _, _, _, start, length = matches[0]
    if start < 12 or start > end or length > end - start:
        raise ValueError("selector-0x20 record exceeds payload region")
    return memoryview(data)[start:start + length]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    items = json.loads(args.inventory.read_text(encoding="utf-8"))["files"]
    levels = [item for item in items if Path(item["path"]).suffix.lower() == ".lvl"]
    if not levels or any(item["status"] != "examined" for item in levels):
        raise ValueError("empty or incomplete level inventory")
    counts = Counter()
    for item in levels:
        data = read_verified(root, item)
        count, value = first_lookup_dword(selected_payload(data))
        counts["level_files"] += 1
        counts["declared_objects_total"] += count
        if value is None:
            counts["empty_object_lists"] += 1
            continue
        _, entries = selected(data)
        level_values = [int(entry["Prefix dwords"].split()[0], 16) for entry in entries]
        matches = level_values.count(value)
        counts["first_objects"] += 1
        counts["first_key_zero"] += value == 0
        counts["first_key_all_ones"] += value == 0xffffffff
        counts["first_key_no_same_level_match"] += matches == 0
        counts["first_key_one_same_level_match"] += matches == 1
        counts["first_key_multiple_same_level_matches"] += matches > 1
    print(json.dumps(dict(sorted(counts.items())), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
