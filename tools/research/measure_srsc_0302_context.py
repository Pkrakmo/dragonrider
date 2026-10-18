#!/usr/bin/env python3
"""Measure same-file presence of the 0x0402 precondition and 0x0302 tuple."""
import argparse
from collections import Counter
import json
from pathlib import Path

from measure_srsc_lookup import read_records


def measure(records):
    """Return only booleans/counts needed for the traced reader context."""
    has_0402_zero = (0x0402, 0, 0) in records
    has_0302 = any(kind == 0x0302 for kind, _, _ in records)
    has_0302_zero = (0x0302, 0, 0) in records
    return {
        'has_0402_zero_tuple': has_0402_zero,
        'has_0302': has_0302,
        'has_0302_zero_tuple': has_0302_zero,
        'has_both_0402_and_0302': has_0402_zero and has_0302,
    }


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
        totals['files'] += 1
        totals['files_with_0402_zero_tuple'] += result['has_0402_zero_tuple']
        totals['files_with_0302'] += result['has_0302']
        totals['files_with_both_0402_and_0302'] += result['has_both_0402_and_0302']
        totals['files_with_0302_zero_tuple'] += result['has_0302_zero_tuple']
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
