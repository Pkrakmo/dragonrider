#!/usr/bin/env python3
"""Measure three statically transformed float32 slots in selected US 0x0502 rows."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import struct

from measure_srsc_0501_payloads import validate_unique_inventory_paths
from measure_srsc_lookup import read_snapshot

EXPECTED_FILES = 178
ROW_SIZE = 52
FLOAT_OFFSETS = (40, 44, 48)
SCALE = 2048.0


def summarize_0502_payload(payload):
    """Aggregate raw float32 values at the three observed row offsets."""
    if len(payload) < 2:
        raise ValueError("0x0502 payload is shorter than its count prefix")
    count = struct.unpack_from("<H", payload)[0]
    required = count * ROW_SIZE
    if required > len(payload) - 2:
        raise ValueError("0x0502 rows exceed payload bounds")
    stats = [Counter() for _ in FLOAT_OFFSETS]
    minima = [math.inf] * len(FLOAT_OFFSETS)
    maxima = [-math.inf] * len(FLOAT_OFFSETS)
    for row_index in range(count):
        row = 2 + row_index * ROW_SIZE
        for slot, offset in enumerate(FLOAT_OFFSETS):
            value = struct.unpack_from("<f", payload, row + offset)[0]
            if not math.isfinite(value):
                stats[slot]["non_finite"] += 1
                continue
            stats[slot]["finite"] += 1
            minima[slot] = min(minima[slot], value)
            maxima[slot] = max(maxima[slot], value)
    result = []
    for slot, offset in enumerate(FLOAT_OFFSETS):
        finite_count = stats[slot]["finite"]
        result.append({
            "row_offset": offset,
            "finite_count": finite_count,
            "non_finite_count": stats[slot]["non_finite"],
            "minimum_before_scale": minima[slot] if finite_count else None,
            "maximum_before_scale": maxima[slot] if finite_count else None,
        })
    return {
        "row_count": count,
        "consumed_bytes": 2 + required,
        "trailing_bytes": len(payload) - 2 - required,
        "slots": result,
    }


def measure_file(data, selectors):
    """Select first pair-key 0x0501 trios under stable second-word ordering."""
    if len(data) < 12 or data[:4] != b"SRSC":
        raise ValueError("not an SRSC snapshot")
    version, table_offset, count = struct.unpack_from("<HIH", data, 4)
    if version != 0x0100 or not count or table_offset < 12:
        raise ValueError("invalid SRSC table header")
    if table_offset > len(data) or count > (len(data) - table_offset) // 14 or table_offset + count * 14 != len(data):
        raise ValueError("invalid bounded SRSC table")
    rows = list(struct.iter_unpack("<HHHII", data[table_offset:]))
    if len(selectors) != count or any(selectors[i] != row[:3]
                                      for i, row in enumerate(rows)):
        raise ValueError("selector snapshot differs from SRSC table")
    for row in rows:
        offset, length = row[3:]
        if offset < 12 or offset > table_offset or length > table_offset - offset:
            raise ValueError("SRSC payload range exceeds table boundary")
    order = sorted(range(count), key=lambda index: rows[index][1])
    all_0502_rows = sum(row[0] == 0x0502 for row in rows)
    seen = set()
    aggregate = [Counter() for _ in FLOAT_OFFSETS]
    minima = [math.inf] * len(FLOAT_OFFSETS)
    maxima = [-math.inf] * len(FLOAT_OFFSETS)
    totals = Counter()
    trio_count = 0
    for position, index in enumerate(order):
        row = rows[index]
        if row[0] != 0x0501 or row[1] in seen:
            continue
        seen.add(row[1])
        if position + 2 >= count:
            continue
        trio = [row, rows[order[position + 1]], rows[order[position + 2]]]
        if ([item[0] for item in trio] != [0x0501, 0x0503, 0x0502]
                or any(item[1] != row[1] for item in trio)):
            continue
        selected = trio[2]
        payload = data[selected[3]:selected[3] + selected[4]]
        summary = summarize_0502_payload(payload)
        trio_count += 1
        totals["rows"] += summary["row_count"]
        totals["trailing_bytes"] += summary["trailing_bytes"]
        for slot, stat in enumerate(summary["slots"]):
            aggregate[slot]["finite"] += stat["finite_count"]
            aggregate[slot]["non_finite"] += stat["non_finite_count"]
            if stat["finite_count"]:
                minima[slot] = min(minima[slot], stat["minimum_before_scale"])
                maxima[slot] = max(maxima[slot], stat["maximum_before_scale"])
    return {
        "matched_trios": trio_count,
        "all_0502_rows": all_0502_rows,
        "selected_0502_rows": trio_count,
        "unselected_0502_rows": all_0502_rows - trio_count,
        "rows": totals["rows"],
        "payload_trailing_bytes": totals["trailing_bytes"],
        "scale_factor": SCALE,
        "slots": [
            {
                "row_offset": offset,
                "finite_count": aggregate[slot]["finite"],
                "non_finite_count": aggregate[slot]["non_finite"],
                "minimum_before_scale": minima[slot] if aggregate[slot]["finite"] else None,
                "maximum_before_scale": maxima[slot] if aggregate[slot]["finite"] else None,
            }
            for slot, offset in enumerate(FLOAT_OFFSETS)
        ],
    }


def inventory(root, entries):
    root = Path(root).resolve(strict=True)
    if not isinstance(entries, list) or len(entries) != EXPECTED_FILES:
        raise ValueError(f"expected {EXPECTED_FILES} SRSC inventory entries")
    validate_unique_inventory_paths(root, entries)
    per_file = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("status") != "examined":
            raise ValueError("inventory contains an unexamined entry")
        data, selectors = read_snapshot(root, entry)
        per_file.append(measure_file(data, selectors))
    totals = [Counter() for _ in FLOAT_OFFSETS]
    minima = [math.inf] * len(FLOAT_OFFSETS)
    maxima = [-math.inf] * len(FLOAT_OFFSETS)
    for file_result in per_file:
        for slot, stat in enumerate(file_result["slots"]):
            totals[slot]["finite"] += stat["finite_count"]
            totals[slot]["non_finite"] += stat["non_finite_count"]
            if stat["finite_count"]:
                minima[slot] = min(minima[slot], stat["minimum_before_scale"])
                maxima[slot] = max(maxima[slot], stat["maximum_before_scale"])
    return {
        "files_examined": len(per_file),
        "files_with_trios": sum(item["matched_trios"] > 0 for item in per_file),
        "matched_trios": sum(item["matched_trios"] for item in per_file),
        "all_0502_rows": sum(item["all_0502_rows"] for item in per_file),
        "selected_0502_rows": sum(item["selected_0502_rows"] for item in per_file),
        "unselected_0502_rows": sum(item["unselected_0502_rows"] for item in per_file),
        "rows": sum(item["rows"] for item in per_file),
        "payload_trailing_bytes": sum(item["payload_trailing_bytes"] for item in per_file),
        "scale_factor": SCALE,
        "slots": [
            {
                "row_offset": offset,
                "finite_count": totals[slot]["finite"],
                "non_finite_count": totals[slot]["non_finite"],
                "minimum_before_scale": minima[slot] if totals[slot]["finite"] else None,
                "maximum_before_scale": maxima[slot] if totals[slot]["finite"] else None,
            }
            for slot, offset in enumerate(FLOAT_OFFSETS)
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    print(json.dumps(inventory(args.root, manifest.get("files")), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
