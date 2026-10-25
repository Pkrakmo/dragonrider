#!/usr/bin/env python3
"""Count exact 0x0501 16-byte suffix matches in other SRSC payloads."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_lookup import read_snapshot
from measure_srsc_0501_payloads import validate_unique_inventory_paths


EXPECTED_FILES = 178
FOLLOWER_KINDS = (0x0503, 0x0502)


def measure_file(data, selectors):
    """Return aggregate exact-byte matches for validated first-match trios."""
    if len(data) < 12 or data[:4] != b"SRSC":
        raise ValueError("not an SRSC snapshot")
    version, table, count = struct.unpack_from("<HIH", data, 4)
    if version != 0x0100 or not count or table < 12 or table > len(data):
        raise ValueError("invalid SRSC table header")
    if count > (len(data) - table) // 14 or len(selectors) != count:
        raise ValueError("invalid bounded SRSC table or selector count")

    rows = list(struct.iter_unpack("<HHHII", data[table:table + count * 14]))
    for index, row in enumerate(rows):
        if selectors[index] != row[:3]:
            raise ValueError("selector snapshot differs from SRSC table")
        offset, size = row[3:]
        if offset < 12 or offset > table or size > table - offset:
            raise ValueError("payload range exceeds input or table boundary")

    order = sorted(range(count), key=lambda index: rows[index][1])
    seen = set()
    results = Counter({
        "trios_with_16_byte_suffix": 0,
        "suffix_records_found_in_0503": 0,
        "suffix_records_found_in_0502": 0,
        "suffix_occurrences_in_0503": 0,
        "suffix_occurrences_in_0502": 0,
        "distinct_suffix_values_found_in_0503": 0,
        "distinct_suffix_values_found_in_0502": 0,
        "suffix_records_found_in_other_0501_payloads": 0,
        "suffix_occurrences_in_other_0501_payloads": 0,
        "distinct_suffix_values_found_in_other_0501_payloads": 0,
        "suffix_records_found_in_other_0501_same_second": 0,
        "suffix_occurrences_in_other_0501_same_second": 0,
        "distinct_suffix_values_found_in_other_0501_same_second": 0,
        "suffix_records_found_in_other_0501_different_second": 0,
        "suffix_occurrences_in_other_0501_different_second": 0,
        "distinct_suffix_values_found_in_other_0501_different_second": 0,
        "suffix_records_found_in_non_0501_payloads": 0,
        "suffix_occurrences_in_non_0501_payloads": 0,
        "distinct_suffix_values_found_in_non_0501_payloads": 0,
    })
    distinct_found = {kind: set() for kind in FOLLOWER_KINDS}
    other_0501_found = set()
    same_second_found = set()
    different_second_found = set()
    non_0501_found = set()

    for position, row_index in enumerate(order):
        row = rows[row_index]
        if row[0] != 0x0501 or row[1] in seen:
            continue
        seen.add(row[1])
        if position + 2 >= count:
            continue
        trio = [rows[order[position + offset]] for offset in range(3)]
        if ([item[0] for item in trio] != [0x0501, 0x0503, 0x0502]
                or any(item[1] != row[1] for item in trio)):
            continue

        source = trio[0]
        payload = data[source[3]:source[3] + source[4]]
        if len(payload) < 2:
            continue
        prefix_length = struct.unpack_from("<H", payload)[0]
        suffix_start = 30 + prefix_length
        if len(payload) != suffix_start + 16:
            continue
        suffix = payload[suffix_start:]
        results["trios_with_16_byte_suffix"] += 1

        for kind, follower in zip(FOLLOWER_KINDS, trio[1:]):
            target = data[follower[3]:follower[3] + follower[4]]
            occurrences = target.count(suffix)
            if occurrences:
                results[f"suffix_records_found_in_{kind:04x}"] += 1
                results[f"suffix_occurrences_in_{kind:04x}"] += occurrences
                distinct_found[kind].add(suffix)

        found_other_0501 = False
        found_non_0501 = False
        found_same_second = False
        found_different_second = False
        for other_index, other in enumerate(rows):
            if other_index == row_index:
                continue
            target = data[other[3]:other[3] + other[4]]
            occurrences = target.count(suffix)
            if occurrences:
                if other[0] == 0x0501:
                    found_other_0501 = True
                    results["suffix_occurrences_in_other_0501_payloads"] += occurrences
                    if other[1] == source[1]:
                        found_same_second = True
                        results["suffix_occurrences_in_other_0501_same_second"] += occurrences
                    else:
                        found_different_second = True
                        results["suffix_occurrences_in_other_0501_different_second"] += occurrences
                else:
                    found_non_0501 = True
                    results["suffix_occurrences_in_non_0501_payloads"] += occurrences
        if found_other_0501:
            results["suffix_records_found_in_other_0501_payloads"] += 1
            other_0501_found.add(suffix)
        if found_same_second:
            results["suffix_records_found_in_other_0501_same_second"] += 1
            same_second_found.add(suffix)
        if found_different_second:
            results["suffix_records_found_in_other_0501_different_second"] += 1
            different_second_found.add(suffix)
        if found_non_0501:
            results["suffix_records_found_in_non_0501_payloads"] += 1
            non_0501_found.add(suffix)

    for kind in FOLLOWER_KINDS:
        results[f"distinct_suffix_values_found_in_{kind:04x}"] = len(distinct_found[kind])
    results["distinct_suffix_values_found_in_other_0501_payloads"] = len(other_0501_found)
    results["distinct_suffix_values_found_in_other_0501_same_second"] = len(same_second_found)
    results["distinct_suffix_values_found_in_other_0501_different_second"] = len(different_second_found)
    results["distinct_suffix_values_found_in_non_0501_payloads"] = len(non_0501_found)
    return results


def inventory(root, entries):
    """Aggregate hash-verified suffix match counts without emitting byte data."""
    root = Path(root).resolve(strict=True)
    if not isinstance(entries, list) or len(entries) != EXPECTED_FILES:
        raise ValueError(f"expected {EXPECTED_FILES} SRSC inventory entries")
    validate_unique_inventory_paths(root, entries)
    summary = Counter()
    files_with_matches = Counter()
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("status") != "examined":
            raise ValueError("inventory contains an unexamined entry")
        data, selectors = read_snapshot(root, entry)
        result = measure_file(data, selectors)
        summary["files_examined"] += 1
        for key, value in result.items():
            summary[key] += value
        if result["suffix_records_found_in_0503"]:
            files_with_matches["files_with_matches_in_0503"] += 1
        if result["suffix_records_found_in_0502"]:
            files_with_matches["files_with_matches_in_0502"] += 1
    summary.update(files_with_matches)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("inventory must contain a files list")
    print(json.dumps(dict(sorted(inventory(args.root, manifest["files"]).items())), indent=2))


if __name__ == "__main__":
    main()
