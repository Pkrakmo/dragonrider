#!/usr/bin/env python3
"""Measure selected SRSC payload framing without exporting payload contents."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_lookup import read_records


KINDS = (0x0101, 0x0201, 0x0301)


def classify(payload):
    counts = Counter({'records': 1, 'short_prefix': 0, 'length_exact': 0,
                      'length_too_large': 0, 'length_shorter': 0,
                      'nonempty_printable_or_nul': 0, 'trailing_nul': 0,
                      'embedded_nul': 0, 'length_even': 0})
    if len(payload) < 2:
        counts['short_prefix'] = 1
        return counts
    length = int.from_bytes(payload[:2], 'little')
    counts['length_even'] = length % 2 == 0
    counts['length_exact'] = length == len(payload) - 2
    counts['length_too_large'] = length > len(payload) - 2
    counts['length_shorter'] = length < len(payload) - 2
    if length and length <= len(payload) - 2:
        text_bytes = payload[2:2 + length]
        counts['nonempty_printable_or_nul'] = all(32 <= b <= 126 or b == 0 for b in text_bytes)
        counts['trailing_nul'] = text_bytes[-1] == 0
        counts['embedded_nul'] = 0 in text_bytes[:-1]
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    totals = {f'{kind:04x}': Counter() for kind in KINDS}
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        read_records(root, entry)  # Validate and hash each file before parsing payloads.
        with (root / entry['path']).open('rb') as stream:
            header = stream.read(12)
            _, table, count = struct.unpack_from('<HIH', header, 4)
            stream.seek(table)
            raw = stream.read(count * 14)
            if len(raw) != count * 14:
                raise ValueError('short table read')
            for kind, _, _, start, length in struct.iter_unpack('<HHHII', raw):
                if kind not in KINDS:
                    continue
                if start < 12 or start + length > table:
                    raise ValueError('payload outside bounded pre-table range')
                # Only 16-bit string lengths are measured; refuse larger payloads.
                if length > 65537:
                    raise ValueError('selected payload exceeds measurement limit')
                stream.seek(start)
                payload = stream.read(length)
                if len(payload) != length:
                    raise ValueError('short payload read')
                totals[f'{kind:04x}'].update(classify(payload))
    print(json.dumps({'files_examined': len(entries), 'kinds': totals}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
