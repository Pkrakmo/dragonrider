#!/usr/bin/env python3
"""Measure bounded 0x0400 payloads and a traced byte transform, without content output."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_lookup import read_snapshot


MAX_PAYLOAD = 65536


def classify(payload, third):
    result = Counter({'records': 1, 'third_zero': third == 0,
                      'empty': not payload, 'plain_printable': False,
                      'transformed_printable': False, 'plain_nul': False,
                      'transformed_nul': False, 'transformed_trailing_nul': False,
                      'transformed_control': False, 'transformed_high': False})
    state = 0x5fdd390d
    transformed = bytearray()
    for value in payload:
        transformed.append(value ^ (state & 0xff))
        state = ((state << 3) | (state >> 29)) & 0xffffffff
    if payload:
        result['plain_printable'] = all(32 <= value <= 126 for value in payload)
        result['transformed_printable'] = all(32 <= value <= 126 for value in transformed)
        result['plain_nul'] = 0 in payload
        result['transformed_nul'] = 0 in transformed
        result['transformed_trailing_nul'] = transformed[-1] == 0
        result['transformed_control'] = any(value < 32 or value == 127 for value in transformed)
        result['transformed_high'] = any(value >= 128 for value in transformed)
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
        totals['files_with_0400'] += any(kind == 0x0400 for kind, _, _ in records)
        _, table, count = struct.unpack_from('<HIH', data, 4)
        raw = data[table:table + count * 14]
        if count != len(records):
            raise ValueError('table changed during measurement')
        for i, (kind, second, third, start, length) in enumerate(struct.iter_unpack('<HHHII', raw)):
            if (kind, second, third) != records[i]:
                raise ValueError('table changed during measurement')
            if kind != 0x0400:
                continue
            if start < 12 or start + length > table or length > MAX_PAYLOAD:
                raise ValueError('selected payload exceeds bounded pre-table range or limit')
            payload = data[start:start + length]
            if len(payload) != length:
                raise ValueError('short payload read')
            totals.update(classify(payload, third))
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
