#!/usr/bin/env python3
"""Measure selected same-file SRSC third-to-second word correlations.

This is aggregate structural evidence only. It does not claim that a loader
resolves these values or that the words are identifiers.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

from measure_srsc_third_selector_distribution import load_entries, read_verified_records

PAIRS = ((0x0207, 0x0201), (0x0208, 0x0201), (0x0209, 0x0201))


def _empty():
    return Counter({
        "source_records": 0,
        "files_with_source": 0,
        "third_zero": 0,
        "nonzero_no_match": 0,
        "nonzero_unique_match": 0,
        "nonzero_multiple_matches": 0,
        "unique_target_before_source": 0,
        "unique_target_after_source": 0,
    })


def measure_file(records):
    """Return per-pair counts for one validated table in original table order."""
    target_positions = {
        target: {} for _, target in PAIRS
    }
    for index, (kind, second, _, _, _) in enumerate(records):
        if kind in target_positions:
            target_positions[kind].setdefault(second, []).append(index)

    output = {f"{source:04x}_to_{target:04x}": _empty()
              for source, target in PAIRS}
    for source, target in PAIRS:
        counts = output[f"{source:04x}_to_{target:04x}"]
        targets = target_positions[target]
        for index, (kind, _, third, _, _) in enumerate(records):
            if kind != source:
                continue
            counts["source_records"] += 1
            if third == 0:
                counts["third_zero"] += 1
                continue
            matches = targets.get(third, ())
            if not matches:
                counts["nonzero_no_match"] += 1
            elif len(matches) > 1:
                counts["nonzero_multiple_matches"] += 1
            else:
                counts["nonzero_unique_match"] += 1
                if matches[0] < index:
                    counts["unique_target_before_source"] += 1
                else:
                    counts["unique_target_after_source"] += 1
        if counts["source_records"]:
            counts["files_with_source"] = 1
    return output


def measure_inventory(root, entries):
    """Verify and aggregate each inventory file from one byte snapshot."""
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty or invalid SRSC inventory")
    totals = {key: _empty() for key in
              (f"{source:04x}_to_{target:04x}" for source, target in PAIRS)}
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid inventory entry")
        if entry["path"] in seen:
            raise ValueError("duplicate inventory path")
        seen.add(entry["path"])
        per_file = measure_file(read_verified_records(root, entry))
        for key in totals:
            totals[key].update(per_file[key])
    return {"files_examined": len(entries), "relationships": {
        key: dict(counts) for key, counts in totals.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="hash-checked installed US data root")
    parser.add_argument("inventory", type=Path, help="private SRSC inventory JSON")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root is not a directory")
    print(json.dumps(measure_inventory(root, load_entries(args.inventory)),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
