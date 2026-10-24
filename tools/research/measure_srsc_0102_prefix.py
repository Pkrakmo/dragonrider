#!/usr/bin/env python3
"""Measure bounded 0x0102 payload prefixes and selector comparisons."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_lookup import read_snapshot


def classify(payload, record_length, third):
    result = Counter({'records': 1})
    if len(payload) < 2:
        result['short_prefix'] += 1
        return result
    length = int.from_bytes(payload[:2], 'little')
    if length > record_length - 2:
        result['prefix_exceeds_payload'] += 1
        return result
    if len(payload) < length + 2:
        raise ValueError('short prefix read')
    result['prefix_fits'] += 1
    label = payload[2:2 + length]
    result['prefix_zero'] += not label
    if label:
        result['prefix_printable_or_nul'] += all(32 <= b <= 126 or b == 0 for b in label)
        result['prefix_trailing_nul'] += label[-1] == 0
    if record_length - 2 - length < 10:
        result['following_fewer_than_10_bytes'] += 1
        return result
    if len(payload) < length + 12:
        raise ValueError('short following bytes read')
    result['following_at_least_10_bytes'] += 1
    high = int.from_bytes(payload[length + 6:length + 8], 'little')
    result['payload_high_zero'] += high == 0
    result['third_zero'] += third == 0
    result['payload_high_equals_third'] += high == third
    result['payload_high_equals_nonzero_third'] += high == third and third != 0
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
        data, records = read_snapshot(root, entry)
        totals['files_examined'] += 1
        totals['files_with_0102'] += any(kind == 0x0102 for kind, _, _ in records)
        _, table, count = struct.unpack_from('<HIH', data, 4)
        raw = data[table:table + count * 14]
        if len(raw) != count * 14 or count != len(records):
            raise ValueError('table changed during measurement')
        for i, (kind, second, third, start, length) in enumerate(struct.iter_unpack('<HHHII', raw)):
            if (kind, second, third) != records[i]:
                raise ValueError('table changed during measurement')
            if kind != 0x0102:
                continue
            if start < 12 or start + length > table:
                raise ValueError('selected payload outside pre-table range')
            amount = min(length, 65547)
            payload = data[start:start + amount]
            if len(payload) != amount:
                raise ValueError('short payload read')
            totals.update(classify(payload, length, third))
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
