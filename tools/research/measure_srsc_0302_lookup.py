#!/usr/bin/env python3
"""Compare first-pair and zero-third lookups for SRSC 0x0302 records."""
import argparse
from collections import Counter
import json
from pathlib import Path

from measure_srsc_lookup import read_records


def measure(records):
    ordered = sorted(records, key=lambda record: record[1])
    first_pair = {}
    first_zero = {}
    occurrences = Counter()
    result = Counter({key: 0 for key in (
        'records', 'nonzero_third', 'pairs', 'duplicate_pair_occurrences',
        'zero_third_not_found', 'first_match_differs')})
    for index, (kind, second, third) in enumerate(ordered):
        if kind != 0x0302:
            continue
        result['records'] += 1
        result['nonzero_third'] += third != 0
        occurrences[second] += 1
        first_pair.setdefault(second, index)
        if third == 0:
            first_zero.setdefault(second, index)
    result['pairs'] = len(first_pair)
    result['duplicate_pair_occurrences'] = sum(count - 1 for count in occurrences.values())
    for second, index in first_pair.items():
        if second not in first_zero:
            result['zero_third_not_found'] += 1
        elif first_zero[second] != index:
            result['first_match_differs'] += 1
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    totals = Counter()
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        result = measure(read_records(root, entry))
        totals.update(result)
        totals['files_examined'] += 1
        totals['files_with_0302'] += result['records'] > 0
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
