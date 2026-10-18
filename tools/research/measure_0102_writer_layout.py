#!/usr/bin/env python3
"""Compare sampled 0x0102 sizes and same-file gate values to a writer trace."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified


def measure(data):
    end, entries = table(data)
    counts = Counter({key: 0 for key in ('records', 'shorter', 'equal', 'longer',
        'gate_missing', 'gate_multiple', 'gate_short', 'gate_0102', 'gate_4',
        'gate_other')})
    gates = []
    records = []
    for kind, second, third, start, length in entries:
        if kind != 0x0102 and (kind, second, third) != (0x0402, 0, 0):
            continue
        if start < 12 or start > end or length > end - start:
            raise ValueError('selected payload outside pre-table region')
        if kind == 0x0102:
            records.append(length)
        else:
            gates.append((start, length))
    if not gates:
        gate = 'gate_missing'
    elif len(gates) != 1:
        gate = 'gate_multiple'
    elif gates[0][1] < 4:
        gate = 'gate_short'
    else:
        value = struct.unpack_from('<I', data, gates[0][0])[0]
        gate = 'gate_0102' if value == 0x102 else 'gate_4' if value == 4 else 'gate_other'
    for length in records:
        counts['records'] += 1
        counts['shorter' if length < 136 else 'equal' if length == 136 else 'longer'] += 1
        counts[gate] += 1
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
    totals = Counter()
    files_with_records = 0
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        counts = measure(read_verified(root, entry))
        totals.update(counts)
        files_with_records += counts['records'] > 0
    print(json.dumps({'files_examined': len(entries), 'files_with_records': files_with_records,
                      'counts': dict(sorted(totals.items()))}, indent=2))


if __name__ == '__main__':
    main()
