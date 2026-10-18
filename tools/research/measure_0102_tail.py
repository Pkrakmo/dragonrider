#!/usr/bin/env python3
"""Measure the conditional 0x0102 post-prefix dwords and bounded data."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_prefix_selector import read_verified


def measure(data):
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('invalid SRSC header')
    version, table, count = struct.unpack_from('<HIH', data, 4)
    if version != 0x100 or not count or table < 12 or count * 14 > len(data) - table:
        raise ValueError('invalid SRSC table')
    counts = Counter({k: 0 for k in ('records', 'short_prefix', 'short_fields',
        'short_tail_header', 'declared_data_exceeds_record', 'fits', 'zero_count',
        'nonzero_count', 'extra_tail', 'first_dword_zero', 'first_equals_count',
        'first_zero_count_nonzero', 'first_nonzero_count_zero', 'array_words',
        'array_zero_words', 'count_multiply_wraps_32bit')})
    count_histogram = Counter()
    extra_histogram = Counter()
    for kind, _, _, start, length in struct.iter_unpack('<HHHII', data[table:table + count * 14]):
        if kind != 0x0102:
            continue
        if start < 12 or start > table or length > table - start:
            raise ValueError('selected payload outside pre-table region')
        counts['records'] += 1
        payload = memoryview(data)[start:start + length]
        if length < 2:
            counts['short_prefix'] += 1
            continue
        prefix = struct.unpack_from('<H', payload)[0]
        end = 2 + prefix
        if end > length or length - end < 10:
            counts['short_fields'] += 1
            continue
        pos = end + 10
        if length - pos < 8:
            counts['short_tail_header'] += 1
            continue
        first, n = struct.unpack_from('<II', payload, pos)
        counts['first_dword_zero'] += first == 0
        counts['first_equals_count'] += first == n
        counts['first_zero_count_nonzero'] += first == 0 and n != 0
        counts['first_nonzero_count_zero'] += first != 0 and n == 0
        counts['count_multiply_wraps_32bit'] += n > 0x3fffffff
        if n > (length - pos - 8) // 4:
            counts['declared_data_exceeds_record'] += 1
            continue
        counts['fits'] += 1
        counts['array_words'] += n
        counts['array_zero_words'] += sum(value == 0 for (value,) in
            struct.iter_unpack('<I', payload[pos + 8:pos + 8 + n * 4]))
        counts['zero_count'] += n == 0
        counts['nonzero_count'] += n != 0
        count_histogram[n] += 1
        extra = length - pos - 8 - 4 * n
        counts['extra_tail'] += extra != 0
        extra_histogram[extra] += 1
    return counts, count_histogram, extra_histogram


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
    count_histogram = Counter()
    extra_histogram = Counter()
    files_with_records = 0
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        counts, per_count, per_extra = measure(read_verified(root, entry))
        totals.update(counts)
        count_histogram.update(per_count)
        extra_histogram.update(per_extra)
        files_with_records += counts['records'] > 0
    print(json.dumps({'files_examined': len(entries), 'files_with_records': files_with_records,
                      'counts': dict(sorted(totals.items())),
                      'count_histogram': dict(sorted(count_histogram.items())),
                      'extra_bytes_histogram': dict(sorted(extra_histogram.items()))}, indent=2))


if __name__ == '__main__':
    main()
