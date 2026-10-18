#!/usr/bin/env python3
"""Compare first-pair and zero-third texture selector lookups in SRSC tables."""
import argparse
from collections import Counter
import json
from pathlib import Path
from measure_srsc_lookup import read_records


def measure(records):
    ordered = sorted(records, key=lambda record: record[1])
    by_pair = {}
    by_triple = {}
    result = Counter({key: 0 for key in ('texture_records', 'texture_nonzero_third',
        'lookup_pairs', 'first_lookup_disagreements', 'zero_third_not_found',
        'duplicate_pair_occurrences')})
    counts = Counter()
    for index, (kind, selector, third) in enumerate(ordered):
        if kind != 0x40:
            continue
        result['texture_records'] += 1
        result['texture_nonzero_third'] += third != 0
        counts[selector] += 1
        by_pair.setdefault(selector, index)
        if third == 0:
            by_triple.setdefault(selector, index)
    result['lookup_pairs'] = len(by_pair)
    result['duplicate_pair_occurrences'] = sum(count - 1 for count in counts.values())
    for selector, index in by_pair.items():
        if selector not in by_triple:
            result['zero_third_not_found'] += 1
        else:
            result['first_lookup_disagreements'] += index != by_triple[selector]
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
        for key, value in result.items():
            totals[key] += value
        totals['files_examined'] += 1
        totals['files_with_texture_records'] += result['texture_records'] > 0
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
