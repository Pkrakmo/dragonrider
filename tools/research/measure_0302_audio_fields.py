#!/usr/bin/env python3
"""Measure 0x0302 candidate waveform fields; emit aggregate values only."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified


def classify(payload):
    if len(payload) < 2:
        raise ValueError('short prefix')
    pos = 2 + struct.unpack_from('<H', payload)[0]
    if pos > len(payload) or len(payload) - pos < 32:
        raise ValueError('short fixed fields')
    _, channels, bits, rate, _, _, _, size, mode = struct.unpack_from('<IHHIIIIII', payload, pos)
    block = (channels * (bits >> 3)) & 0xffff
    counts = Counter(records=1)
    counts[f'channels_{channels}'] += 1
    counts[f'bits_{bits}'] += 1
    counts[f'rate_{rate}'] += 1
    counts[f'mode_{mode}'] += 1
    counts['bits_multiple_of_8'] += bits % 8 == 0
    counts['block_nonzero'] += block != 0
    counts['size_multiple_of_block'] += block != 0 and size % block == 0
    counts['rate_nonzero'] += rate != 0
    counts['average_product_fits_u32'] += block * rate <= 0xffffffff
    counts['size_nonzero'] += size != 0
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    items = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not items or any(item['status'] != 'examined' for item in items):
        raise ValueError('empty or incomplete inventory')
    counts = Counter()
    for item in items:
        data = read_verified(root, item)
        end, records = table(data)
        for kind, _, _, offset, length in records:
            if kind != 0x0302:
                continue
            if offset < 12 or offset > end or length > end - offset:
                raise ValueError('selected record outside payload')
            counts.update(classify(data[offset:offset + length]))
    print(json.dumps({'files': len(items), 'counts': dict(sorted(counts.items()))}, indent=2))


if __name__ == '__main__':
    main()
