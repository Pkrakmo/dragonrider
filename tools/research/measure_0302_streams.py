#!/usr/bin/env python3
"""Measure bounded zlib candidate streams in 0x0302 new-object frames."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
import zlib

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified

LIMIT = 32 * 1024 * 1024


def classify(payload):
    if len(payload) < 2:
        raise ValueError('short prefix')
    pos = 2 + int.from_bytes(payload[:2], 'little')
    if pos > len(payload) or len(payload) - pos < 32:
        raise ValueError('short fixed fields')
    size, mode = struct.unpack_from('<II', payload, pos + 24)
    if mode == 0:
        return Counter(zero_mode=1)
    if len(payload) - pos < 36:
        raise ValueError('short stored length')
    stored = struct.unpack_from('<I', payload, pos + 32)[0]
    pos += 36
    if stored > len(payload) - pos:
        raise ValueError('stored body exceeds record')
    counts = Counter(nonzero_mode=1)
    if size > LIMIT or stored > LIMIT:
        counts['limit_skipped'] += 1
        return counts
    stream = zlib.decompressobj()
    try:
        decoded = stream.decompress(payload[pos:pos + stored], size + 1)
    except zlib.error:
        counts['zlib_error'] += 1
        return counts
    counts['decoded_exact_size'] += len(decoded) == size
    counts['decoded_over_size'] += len(decoded) > size
    counts['stream_eof'] += stream.eof
    counts['complete_exact_size'] += stream.eof and len(decoded) == size
    counts['unused_input'] += bool(stream.unused_data or stream.unconsumed_tail)
    counts['trailing_record_bytes'] += pos + stored < len(payload)
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not entries or any(e['status'] != 'examined' for e in entries):
        raise ValueError('empty or incomplete inventory')
    totals = Counter()
    for entry in entries:
        data = read_verified(root, entry)
        end, records = table(data)
        for kind, _, _, offset, length in records:
            if kind != 0x0302:
                continue
            if offset < 12 or offset > end or length > end - offset:
                raise ValueError('selected record outside payload')
            totals.update(classify(data[offset:offset + length]))
    print(json.dumps({'files': len(entries), 'counts': dict(sorted(totals.items()))}, indent=2))


if __name__ == '__main__':
    main()
