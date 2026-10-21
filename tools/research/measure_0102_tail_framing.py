#!/usr/bin/env python3
"""Test bounded candidate string framing after the 0x0102 array; emit aggregates only."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified

MAX_ITEMS = 65536


def candidate(tail, count):
    """Treat count as the number of little-endian u16-length-prefixed byte strings."""
    if count > MAX_ITEMS:
        return 'count_limit', 0
    pos = 4
    for _ in range(count):
        if len(tail) - pos < 2:
            return 'short_length', pos
        size = struct.unpack_from('<H', tail, pos)[0]
        pos += 2
        if size > len(tail) - pos:
            return 'short_body', pos
        pos += size
    return ('exact' if pos == len(tail) else 'remaining'), pos


def measure(data):
    end, entries = table(data)
    counts = Counter()
    for kind, _, _, start, length in entries:
        if kind != 0x0102:
            continue
        if start < 12 or start > end or length > end - start:
            raise ValueError('selected payload outside pre-table region')
        counts['records'] += 1
        payload = memoryview(data)[start:start + length]
        if len(payload) < 2:
            counts['short_prefix'] += 1
            continue
        pos = 2 + struct.unpack_from('<H', payload)[0] + 10
        if pos > len(payload) or len(payload) - pos < 8:
            counts['short_fields'] += 1
            continue
        n = struct.unpack_from('<I', payload, pos + 4)[0]
        pos += 8
        if n > (len(payload) - pos) // 4:
            counts['short_array'] += 1
            continue
        tail = payload[pos + n * 4:]
        if not tail:
            counts['empty_tail'] += 1
            continue
        if len(tail) < 4:
            counts['short_tail'] += 1
            continue
        counts['tails'] += 1
        value = struct.unpack_from('<I', tail)[0]
        # Separately test two consecutive frames, independent of the count guess.
        pos = 4
        for number in (1, 2):
            if len(tail) - pos < 2:
                counts[f'frame{number}_short_length'] += 1
                break
            size = struct.unpack_from('<H', tail, pos)[0]
            pos += 2
            if size > len(tail) - pos:
                counts[f'frame{number}_short_body'] += 1
                break
            body = tail[pos:pos + size]
            counts[f'frame{number}_fits'] += 1
            counts[f'frame{number}_nul_terminated'] += bool(body) and body[-1] == 0
            counts[f'frame{number}_exact'] += pos + size == len(tail)
            pos += size
        # Continue until the record boundary; progress is at least two bytes.
        pos = 4
        frames = 0
        while pos < len(tail) and frames < MAX_ITEMS:
            if len(tail) - pos < 2:
                counts['greedy_short_length'] += 1
                break
            size = struct.unpack_from('<H', tail, pos)[0]
            pos += 2
            if size > len(tail) - pos:
                counts['greedy_short_body'] += 1
                break
            frames += 1
            pos += size
        else:
            counts['greedy_exact' if pos == len(tail) else 'greedy_limit'] += 1
        counts['greedy_frames'] += frames
        for name, count in (('full', value), ('low12', value & 0xfff)):
            result, _ = candidate(tail, count)
            counts[f'{name}_{result}'] += 1
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
