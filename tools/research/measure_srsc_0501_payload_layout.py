#!/usr/bin/env python3
"""Measure bounded payload extents around US SRSC 0x0501 selector trios."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_lookup import read_snapshot
from measure_srsc_0501_payloads import validate_unique_inventory_paths


EXPECTED_FILES = 178


def measure_file(data, selectors):
    """Return aggregate extent relationships for first-match 0501 trios."""
    if len(data) < 12 or data[:4] != b"SRSC":
        raise ValueError("not an SRSC snapshot")
    version, table, count = struct.unpack_from("<HIH", data, 4)
    if version != 0x0100 or not count or table < 12 or table > len(data):
        raise ValueError("invalid SRSC table header")
    if (count > (len(data) - table) // 14 or table + count * 14 != len(data)
            or len(selectors) != count):
        raise ValueError("invalid bounded SRSC table or selector count")

    rows = list(struct.iter_unpack("<HHHII", data[table:table + count * 14]))
    for index, row in enumerate(rows):
        if selectors[index] != row[:3]:
            raise ValueError("selector snapshot differs from SRSC table")
        offset, size = row[3:]
        if offset < 12 or offset > table or size > table - offset:
            raise ValueError("payload range exceeds input or table boundary")

    order = sorted(range(count), key=lambda index: rows[index][1])
    seen_second_words = set()
    expected_trios = 0
    internal_gaps = Counter()
    group_ranges = []
    kind_lengths = {kind: Counter() for kind in (0x0501, 0x0503, 0x0502)}
    count_metrics = Counter()
    prefix_extent_deltas = Counter()
    suffix16_values = Counter()

    for position, row_index in enumerate(order):
        row = rows[row_index]
        if row[0] != 0x0501 or row[1] in seen_second_words:
            continue
        seen_second_words.add(row[1])
        if position + 2 >= count:
            continue
        trio = [row, rows[order[position + 1]], rows[order[position + 2]]]
        if ([item[0] for item in trio] != [0x0501, 0x0503, 0x0502]
                or any(item[1] != row[1] for item in trio)):
            continue

        expected_trios += 1
        extents = [(item[3], item[3] + item[4]) for item in trio]
        internal_gaps[extents[1][0] - extents[0][1]] += 1
        internal_gaps[extents[2][0] - extents[1][1]] += 1
        group_ranges.append((min(start for start, _ in extents),
                             max(end for _, end in extents)))
        for item in trio:
            kind_lengths[item[0]][item[4]] += 1

        payload_0501 = data[trio[0][3]:trio[0][3] + trio[0][4]]
        payload_0503 = data[trio[1][3]:trio[1][3] + trio[1][4]]
        payload_0502 = data[trio[2][3]:trio[2][3] + trio[2][4]]
        if len(payload_0501) >= 2:
            prefix_length = struct.unpack_from("<H", payload_0501)[0]
            if prefix_length <= len(payload_0501) - 30:
                suffix = payload_0501[30 + prefix_length:]
                prefix_extent_deltas[
                    len(payload_0501) - (30 + prefix_length)
                ] += 1
                if len(suffix) == 16:
                    suffix16_values[suffix] += 1
            fields_offset = 2 + prefix_length
            if fields_offset <= len(payload_0501) - 20:
                count_metrics["bounded_0501_count_fields"] += 1
                count_52 = struct.unpack_from("<I", payload_0501,
                                              fields_offset + 8)[0]
                count_8 = struct.unpack_from("<I", payload_0501,
                                             fields_offset + 16)[0]
                if len(payload_0503) >= 2:
                    prefix_8 = struct.unpack_from("<H", payload_0503)[0]
                    count_metrics["0503_prefix_matches_0501_count"] += (
                        prefix_8 == count_8
                    )
                    count_metrics["0503_length_matches_2_plus_8_count"] += (
                        len(payload_0503) == 2 + 8 * prefix_8
                    )
                if len(payload_0502) >= 2:
                    prefix_52 = struct.unpack_from("<H", payload_0502)[0]
                    count_metrics["0502_prefix_matches_0501_count"] += (
                        prefix_52 == count_52
                    )
                    count_metrics["0502_length_matches_2_plus_52_count"] += (
                        len(payload_0502) == 2 + 52 * prefix_52
                    )

    group_ranges.sort()
    group_gaps = Counter(
        group_ranges[index + 1][0] - group_ranges[index][1]
        for index in range(len(group_ranges) - 1)
    )
    side = sorted((row for row in rows if row[0] in (0x0500, 0x0402)),
                  key=lambda row: row[3])
    side_footer = bool(
        group_ranges and len(side) == 2
        and [row[:3] for row in side]
        == [(0x0500, 0, 0), (0x0402, 0, 0)]
        and [row[4] for row in side] == [6, 4]
        and side[0][3] == group_ranges[-1][1]
        and side[1][3] == side[0][3] + side[0][4]
        and side[1][3] + side[1][4] == table
    )
    return {
        "first_match_keys": len(seen_second_words),
        "expected_trios": expected_trios,
        "internal_gap_values": internal_gaps,
        "group_count": len(group_ranges),
        "group_gaps": group_gaps,
        "first_group_offset": group_ranges[0][0] if group_ranges else None,
        "last_group_end": group_ranges[-1][1] if group_ranges else None,
        "table_offset": table,
        "kind_lengths": kind_lengths,
        "count_metrics": count_metrics,
        "prefix_extent_deltas": prefix_extent_deltas,
        "suffix16_values": suffix16_values,
        "side_footer_0500_0402": side_footer,
    }


def inventory(root, entries):
    """Aggregate verified file measurements without emitting paths or bytes."""
    root = Path(root).resolve(strict=True)
    if not isinstance(entries, list) or len(entries) != EXPECTED_FILES:
        raise ValueError(f"expected {EXPECTED_FILES} SRSC inventory entries")
    validate_unique_inventory_paths(root, entries)
    summary = Counter()
    internal_gaps = Counter()
    group_gaps = Counter()
    first_group_offsets = Counter()
    trio_tail_lengths = Counter()
    side_footer_files = 0
    files_with_trios = 0
    count_metrics = Counter()
    prefix_extent_deltas = Counter()
    suffix16_values = Counter()
    total_kind_lengths = {kind: Counter() for kind in (0x0501, 0x0503, 0x0502)}

    for entry in entries:
        if not isinstance(entry, dict) or entry.get("status") != "examined":
            raise ValueError("inventory contains an unexamined entry")
        data, selectors = read_snapshot(root, entry)
        result = measure_file(data, selectors)
        summary.update({
            "files_examined": 1,
            "first_match_keys": result["first_match_keys"],
            "expected_trios": result["expected_trios"],
            "group_count": result["group_count"],
        })
        if not result["group_count"]:
            continue
        files_with_trios += 1
        internal_gaps.update(result["internal_gap_values"])
        group_gaps.update(result["group_gaps"])
        count_metrics.update(result["count_metrics"])
        prefix_extent_deltas.update(result["prefix_extent_deltas"])
        suffix16_values.update(result["suffix16_values"])
        first_group_offsets[result["first_group_offset"]] += 1
        trio_tail_lengths[result["table_offset"] - result["last_group_end"]] += 1
        for kind, lengths in result["kind_lengths"].items():
            total_kind_lengths[kind].update(lengths)

        if result["side_footer_0500_0402"]:
            side_footer_files += 1

    return {
        **dict(summary),
        "files_with_trios": files_with_trios,
        "internal_gap_values": dict(sorted(internal_gaps.items())),
        "inter_group_gap_values": dict(sorted(group_gaps.items())),
        "first_group_offsets": dict(sorted(first_group_offsets.items())),
        "table_distance_after_last_trio": dict(sorted(trio_tail_lengths.items())),
        "files_with_0500_0402_contiguous_footer": side_footer_files,
        "count_relationships": dict(sorted(count_metrics.items())),
        "0501_payload_length_minus_30_plus_prefix": dict(
            sorted(prefix_extent_deltas.items())
        ),
        "unconsumed_0501_suffix16": {
            "occurrences": sum(suffix16_values.values()),
            "distinct_values": len(suffix16_values),
            "duplicate_occurrences": sum(suffix16_values.values()) - len(suffix16_values),
            "maximum_multiplicity": max(suffix16_values.values(), default=0),
            "all_zero_values": sum(
                count for suffix, count in suffix16_values.items()
                if not any(suffix)
            ),
            "constant_byte_positions": sum(
                len({suffix[index] for suffix in suffix16_values}) == 1
                for index in range(16)
            ) if suffix16_values else 0,
        },
        "trio_payload_length_ranges": {
            hex(kind): {"min": min(lengths), "max": max(lengths),
                        "distinct": len(lengths)}
            for kind, lengths in total_kind_lengths.items() if lengths
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("invalid SRSC inventory document")
    print(json.dumps(inventory(args.root, manifest.get("files")),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
