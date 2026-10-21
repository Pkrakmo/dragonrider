#!/usr/bin/env python3
"""Measure candidate mono PCM values without exporting audio samples."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_0102_model_candidates import table
from measure_0302_body_duplicates import decode_body
from measure_srsc_prefix_selector import read_verified


def measure(fmt, body):
    channels, bits, _ = fmt
    if channels != 1 or bits not in (8, 16):
        return Counter(unsupported_format=1)
    if len(body) % (bits // 8):
        raise ValueError('body is not aligned to candidate sample width')
    if bits == 8:
        samples = (value - 128 for value in body)
        min_value, max_value = -128, 127
    else:
        samples = (value for (value,) in struct.iter_unpack('<h', body))
        min_value, max_value = -32768, 32767
    sample_count = zero_count = endpoint_count = 0
    previous = None
    changes = 0
    for value in samples:
        sample_count += 1
        zero_count += value == 0
        endpoint_count += value == min_value or value == max_value
        if previous is not None and value != previous:
            changes += 1
        previous = value
    return Counter(records=1, samples=sample_count, zero_samples=zero_count,
                   endpoint_samples=endpoint_count, records_with_changes=changes > 0,
                   records_all_zero=sample_count > 0 and zero_count == sample_count)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not entries or any(e['status'] != 'examined' for e in entries):
        raise ValueError('empty or incomplete inventory')
    counts = Counter()
    for entry in entries:
        data = read_verified(root, entry)
        end, records = table(data)
        for kind, _, _, offset, length in records:
            if kind != 0x0302:
                continue
            if offset < 12 or offset > end or length > end - offset:
                raise ValueError('selected record outside payload')
            fmt, _, body, trailing = decode_body(data[offset:offset + length])
            if trailing:
                raise ValueError('candidate body has trailing record bytes')
            counts.update(measure(fmt, body))
    print(json.dumps({'files': len(entries), 'counts': dict(sorted(counts.items()))}, indent=2))


if __name__ == '__main__':
    main()
