#!/usr/bin/env python3
"""Measure bounded US SRSC records selected by first word 0x0501.

Output is aggregate-only. Each file is size/hash checked and decoded from one
immutable snapshot by the shared SRSC inventory reader. Payload bytes are kept
only in memory while calculating exact duplicate and byte-shape aggregates.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_level_0001 import safe_inventory_path
from measure_srsc_lookup import read_snapshot


def validate_unique_inventory_paths(root, files):
    """Reject repeated resolved files before counting the inventory."""
    seen = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("invalid inventory entry")
        path = safe_inventory_path(root, entry.get("path")).resolve(strict=True)
        if path in seen:
            raise ValueError("duplicate inventory path")
        seen.add(path)


def summarize_stable_order_neighbors(selectors):
    """Count selector kinds immediately following 0x0501 after stable sort."""
    if any(not isinstance(item, tuple) or len(item) != 3 or
           any(type(word) is not int or not 0 <= word <= 0xFFFF for word in item)
           for item in selectors):
        raise ValueError("invalid selector triple")
    order = sorted(range(len(selectors)), key=lambda index: selectors[index][1])
    result = Counter()
    seen_second_words = set()
    for position, original_index in enumerate(order):
        first, second, _ = selectors[original_index]
        if first != 0x0501:
            continue
        result["records_0501"] += 1
        is_first_pair_match = second not in seen_second_words
        if is_first_pair_match:
            seen_second_words.add(second)
            result["first_match_pairs_in_files"] += 1
        if position + 2 >= len(order):
            continue
        following = [selectors[index] for index in order[position + 1:position + 3]]
        result["with_two_following"] += 1
        if (following[0][0], following[1][0]) == (0x0503, 0x0502):
            result["kind_sequence_0503_0502"] += 1
        if following[0][1] == second and following[1][1] == second:
            result["same_second_word"] += 1
        if is_first_pair_match:
            result["first_match_pair_with_two_following_in_files"] += 1
            if ((following[0][0], following[1][0]) == (0x0503, 0x0502)
                    and following[0][1] == second
                    and following[1][1] == second):
                result["first_match_pair_with_expected_sequence_in_files"] += 1
    return dict(result)


def measure_0501_payloads(data, selectors, payload_sink=None):
    """Summarize selector and payload-length distributions for first word 501."""
    if len(data) < 12 or data[:4] != b"SRSC":
        raise ValueError("not an SRSC snapshot")
    _, table_offset, count = struct.unpack_from("<HIH", data, 4)
    table_size = count * 14
    if not count or table_offset < 12 or table_offset > len(data) - table_size:
        raise ValueError("invalid bounded SRSC table")
    if len(selectors) != count:
        raise ValueError("selector count differs from table count")

    second_words = Counter()
    third_words = Counter()
    payload_lengths = Counter()
    selector_lengths = {}
    matches = 0
    for index, (first, second, third, offset, length) in enumerate(
            struct.iter_unpack("<HHHII", data[table_offset:table_offset + table_size])):
        if selectors[index] != (first, second, third):
            raise ValueError("selector snapshot differs from SRSC table")
        if first != 0x0501:
            continue
        if offset > len(data) or length > len(data) - offset:
            raise ValueError("selected payload exceeds input length")
        matches += 1
        second_words[second] += 1
        third_words[third] += 1
        payload_lengths[length] += 1
        selector_lengths.setdefault(second, Counter())[length] += 1
        if payload_sink is not None:
            payload_sink.append(data[offset:offset + length])

    return {
        "records_0501": matches,
        "second_word_values": len(second_words),
        "third_word_values": len(third_words),
        "payload_bytes": sum(length * occurrences
                              for length, occurrences in payload_lengths.items()),
        "payload_length_min": min(payload_lengths, default=None),
        "payload_length_max": max(payload_lengths, default=None),
        "payload_length_values": len(payload_lengths),
        "second_word_occurrences": second_words,
        "third_word_occurrences": third_words,
        "payload_length_occurrences": payload_lengths,
        "selector_length_occurrences": selector_lengths,
    }


def summarize_payload_shapes(payloads):
    """Return aggregate-only exact duplicate and bounded byte-shape counts."""
    payloads = list(payloads)
    exact_counts = Counter(payloads)
    first_nul_offsets = Counter()
    printable_prefixes = 0
    early_printable_prefixes = 0
    early_nul = 0
    aligned_slots = {}
    for payload in payloads:
        nul = payload.find(b"\0", 2)
        if nul >= 0:
            first_nul_offsets[nul] += 1
            is_printable = all(0x20 <= byte <= 0x7E for byte in payload[2:nul])
            printable_prefixes += is_printable
            if nul < 18:
                early_nul += 1
                early_printable_prefixes += is_printable
        for offset in range(0, len(payload) - 1, 2):
            counts = aligned_slots.setdefault(offset, Counter())
            counts[int.from_bytes(payload[offset:offset + 2], "little")] += 1

    slots = {}
    for offset, counts in sorted(aligned_slots.items()):
        value, frequency = counts.most_common(1)[0]
        slots[str(offset)] = {
            "distinct_values": len(counts),
            "zero_count": counts.get(0, 0),
            "value_0x3f80_count": counts.get(0x3F80, 0),
            "most_common_value": value,
            "most_common_count": frequency,
        }
    return {
        "unique_exact_payloads": len(exact_counts),
        "duplicate_occurrences": len(payloads) - len(exact_counts),
        "maximum_exact_payload_multiplicity": max(exact_counts.values(), default=0),
        "first_nul_before_offset_18": early_nul,
        "fully_printable_prefixes": printable_prefixes,
        "fully_printable_prefixes_before_early_nul": early_printable_prefixes,
        "first_nul_distinct_offsets": len(first_nul_offsets),
        "aligned_u16_slots": slots,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != 178:
        raise ValueError("expected the 178-entry private US SRSC inventory")
    validate_unique_inventory_paths(args.root, files)

    per_file = []
    extension_counts = Counter()
    selected_payloads = []
    selector_lengths = {}
    neighbor_counts = Counter()
    for entry in files:
        if not isinstance(entry, dict) or entry.get("status") != "examined":
            raise ValueError("inventory contains an unexamined entry")
        data, selectors = read_snapshot(args.root, entry)
        result = measure_0501_payloads(data, selectors, selected_payloads)
        per_file.append(result)
        neighbor_counts.update(summarize_stable_order_neighbors(selectors))
        for selector, lengths in result["selector_length_occurrences"].items():
            selector_lengths.setdefault(selector, Counter()).update(lengths)
        if result["records_0501"]:
            extension_counts[Path(entry["path"]).suffix.lower()] += result["records_0501"]

    output = {
        "files_examined": len(per_file),
        "files_with_0501": sum(item["records_0501"] > 0 for item in per_file),
        "records_0501": sum(item["records_0501"] for item in per_file),
        "payload_bytes": sum(item["payload_bytes"] for item in per_file),
        "payload_length_min": min(
            (item["payload_length_min"] for item in per_file
             if item["payload_length_min"] is not None), default=None),
        "payload_length_max": max(
            (item["payload_length_max"] for item in per_file
             if item["payload_length_max"] is not None), default=None),
        "second_word_values": len(set().union(
            *(item["second_word_occurrences"].keys() for item in per_file))),
        "third_word_values": len(set().union(
            *(item["third_word_occurrences"].keys() for item in per_file))),
        "third_word_unique_values": sorted(set().union(
            *(item["third_word_occurrences"].keys() for item in per_file))),
        "payload_length_values": len(set().union(
            *(item["payload_length_occurrences"].keys() for item in per_file))),
        "second_selectors_with_multiple_payload_lengths": sum(
            len(lengths) > 1 for lengths in selector_lengths.values()),
        "maximum_payload_lengths_per_second_selector": max(
            (len(lengths) for lengths in selector_lengths.values()), default=0),
        "record_counts_by_extension": dict(sorted(extension_counts.items())),
        "stable_second_order_neighbors": dict(sorted(neighbor_counts.items())),
        **summarize_payload_shapes(selected_payloads),
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
