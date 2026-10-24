#!/usr/bin/env python3
"""Measure 0x0302 length-prefixed payload heads without exporting contents."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_lookup import read_snapshot


def classify(payload, record_length=None):
    if record_length is None:
        record_length = len(payload)
    result = Counter({'records': 1, 'short_prefix': 0, 'prefix_exceeds_payload': 0,
                      'prefix_fits': 0, 'prefix_zero': 0, 'prefix_printable_or_nul': 0,
                      'prefix_trailing_nul': 0, 'prefix_embedded_nul': 0,
                      'following_at_least_24_bytes': 0})
    if len(payload) < 2:
        result['short_prefix'] = 1
        return result
    length = int.from_bytes(payload[:2], 'little')
    if length > record_length - 2:
        result['prefix_exceeds_payload'] = 1
        return result
    if len(payload) < length + 2:
        raise ValueError('short prefix read')
    result['prefix_fits'] = 1
    result['prefix_zero'] = length == 0
    result['following_at_least_24_bytes'] = record_length - 2 - length >= 24
    label = payload[2:2 + length]
    if label:
        result['prefix_printable_or_nul'] = all(32 <= byte <= 126 or byte == 0 for byte in label)
        result['prefix_trailing_nul'] = label[-1] == 0
        result['prefix_embedded_nul'] = 0 in label[:-1]
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
        totals['files_with_0302'] += any(kind == 0x0302 for kind, _, _ in records)
        _, table, count = struct.unpack_from('<HIH', data, 4)
        raw = data[table:table + count * 14]
        if count != len(records):
            raise ValueError('table changed during measurement')
        for i, (kind, second, third, start, length) in enumerate(struct.iter_unpack('<HHHII', raw)):
            if (kind, second, third) != records[i]:
                raise ValueError('table changed during measurement')
            if kind != 0x0302:
                continue
            if start < 12 or start + length > table:
                raise ValueError('selected payload outside pre-table range')
            amount = min(length, 65537)
            payload = data[start:start + amount]
            if len(payload) != amount:
                raise ValueError('short prefix read')
            totals.update(classify(payload, length))
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
