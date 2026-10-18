#!/usr/bin/env python3
"""Count same-file third-to-second selector matches for selected SRSC kinds."""
import argparse
from collections import Counter
import json
from pathlib import Path

from measure_srsc_lookup import read_records


KIND_PAIRS = ((0x0102, 0x0101), (0x0200, 0x0201), (0x0302, 0x0301))


def measure_same_kind(records, kind):
    targets = Counter(second for first, second, _ in records if first == kind)
    counts = Counter({'records': 0, 'third_zero': 0, 'nonzero_no_matches': 0,
                      'nonzero_one_match': 0, 'nonzero_multiple_matches': 0,
                      'nonzero_self_match': 0})
    for first, second, third in records:
        if first != kind:
            continue
        counts['records'] += 1
        if third == 0:
            counts['third_zero'] += 1
            continue
        matches = targets[third]
        counts['nonzero_no_matches'] += matches == 0
        counts['nonzero_one_match'] += matches == 1
        counts['nonzero_multiple_matches'] += matches > 1
        counts['nonzero_self_match'] += second == third
    return counts


def measure_same_kind_chains(records, kind):
    by_second = {}
    for first, second, third in records:
        if first == kind:
            by_second.setdefault(second, []).append(third)
    counts = Counter({'chains': 0, 'end_zero': 0, 'end_missing': 0,
                      'end_ambiguous': 0, 'end_cycle': 0})
    for first, second, third in records:
        if first != kind:
            continue
        counts['chains'] += 1
        visited = {second}
        while third:
            matches = by_second.get(third, [])
            if not matches:
                counts['end_missing'] += 1
                break
            if len(matches) != 1:
                counts['end_ambiguous'] += 1
                break
            if third in visited:
                counts['end_cycle'] += 1
                break
            visited.add(third)
            third = matches[0]
        else:
            counts['end_zero'] += 1
    return counts


def measure_cross_kind_chains(records, source_kind, target_kind):
    targets = {}
    for first, second, third in records:
        if first == target_kind:
            targets.setdefault(second, []).append(third)
    counts = Counter({'chains': 0, 'end_zero': 0, 'end_missing': 0,
                      'end_ambiguous': 0, 'end_cycle': 0})
    for first, _, third in records:
        if first != source_kind:
            continue
        counts['chains'] += 1
        visited = set()
        while third:
            matches = targets.get(third, [])
            if not matches:
                counts['end_missing'] += 1
                break
            if len(matches) != 1:
                counts['end_ambiguous'] += 1
                break
            if third in visited:
                counts['end_cycle'] += 1
                break
            visited.add(third)
            third = matches[0]
        else:
            counts['end_zero'] += 1
    return counts


def measure(records):
    result = {}
    for source_kind, target_kind in KIND_PAIRS:
        targets = Counter(second for first, second, _ in records if first == target_kind)
        counts = Counter({'records': 0, 'no_matches': 0, 'one_match': 0, 'multiple_matches': 0})
        for first, _, third in records:
            if first != source_kind:
                continue
            matches = targets[third]
            counts['records'] += 1
            counts['no_matches'] += matches == 0
            counts['one_match'] += matches == 1
            counts['multiple_matches'] += matches > 1
        result[f'{source_kind:04x}_to_{target_kind:04x}'] = counts
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    totals = {f'{source:04x}_to_{target:04x}': Counter() for source, target in KIND_PAIRS}
    same_kind = {f'{target:04x}': Counter() for _, target in KIND_PAIRS}
    chains = {f'{target:04x}': Counter() for _, target in KIND_PAIRS}
    cross_chains = {f'{source:04x}_to_{target:04x}': Counter() for source, target in KIND_PAIRS}
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        records = read_records(root, entry)
        for key, counts in measure(records).items():
            totals[key].update(counts)
        for source, target in KIND_PAIRS:
            same_kind[f'{target:04x}'].update(measure_same_kind(records, target))
            chains[f'{target:04x}'].update(measure_same_kind_chains(records, target))
            cross_chains[f'{source:04x}_to_{target:04x}'].update(
                measure_cross_kind_chains(records, source, target))
    print(json.dumps({'files_examined': len(entries), 'kind_pairs': totals,
                      'same_kind': same_kind, 'same_kind_chains': chains,
                      'cross_kind_chains': cross_chains},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
