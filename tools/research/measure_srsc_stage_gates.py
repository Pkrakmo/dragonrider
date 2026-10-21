#!/usr/bin/env python3
"""Compare observed loader-stage gate values with hash-checked SRSC files."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import struct

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified

# Conditional loader index-to-suffix paths; values are static stage comparisons.
EXPECTED = {'.odb': 0x102, '.txd': 0x204, '.adb': 0x102,
            '.mod': 0x10a, '.sdb': 0x104, '.ssd': 0x102}


def measure(data, expected):
    end, entries = table(data)
    gates = []
    for first, second, third, start, length in entries:
        if (first, second, third) != (0x402, 0, 0):
            continue
        if start < 12 or start > end or length > end - start:
            raise ValueError('gate payload outside pre-table region')
        gates.append(memoryview(data)[start:start + length])
    counts = Counter(files=1, gates=len(gates))
    if not gates:
        counts['missing'] += 1
    elif len(gates) > 1:
        counts['duplicate'] += 1
    else:
        if len(gates[0]) < 4:
            counts['short'] += 1
        elif struct.unpack_from('<I', gates[0])[0] == expected:
            counts['match'] += 1
        else:
            counts['different'] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not entries:
        raise ValueError('empty inventory')
    totals = defaultdict(Counter)
    ignored = 0
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        extension = Path(entry['path']).suffix.lower()
        data = read_verified(root, entry)
        if extension not in EXPECTED:
            ignored += 1
            continue
        totals[extension].update(measure(data, EXPECTED[extension]))
    print(json.dumps({'files_examined': len(entries), 'other_extensions': ignored,
                      'by_extension': {ext: dict(sorted(counts.items()))
                                       for ext, counts in sorted(totals.items())}}, indent=2))


if __name__ == '__main__':
    main()
