#!/usr/bin/env python3
"""Compare duplicate-selector payload ranges without exporting their contents."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import struct

from measure_srsc_lookup import read_records


MAX_COMPARISON_BYTES = 64 * 1024 * 1024
CHUNK = 65536


def same_bytes(stream, first, other):
    """Compare two bounded ranges, including zero lengths and truncated input."""
    start_a, size_a = first
    start_b, size_b = other
    if min(start_a, start_b, size_a, size_b) < 0:
        raise ValueError('negative payload range')
    if size_a != size_b:
        return False
    if size_a > MAX_COMPARISON_BYTES:
        raise ValueError('comparison exceeds limit')
    for position in range(0, size_a, CHUNK):
        count = min(CHUNK, size_a - position)
        stream.seek(start_a + position)
        a = stream.read(count)
        stream.seek(start_b + position)
        b = stream.read(count)
        if len(a) != count or len(b) != count:
            raise ValueError('short payload read')
        if a != b:
            return False
    return True


def compare_groups(records, stream):
    groups = defaultdict(list)
    for kind, second, third, start, length in records:
        groups[(kind, second, third)].append((start, length))
    result = Counter({key: 0 for key in ('groups', 'occurrences_after_first',
                      'same_start', 'same_length', 'different_length',
                      'identical_bytes', 'different_bytes')})
    for ranges in groups.values():
        if len(ranges) < 2:
            continue
        result['groups'] += 1
        first = ranges[0]
        for other in ranges[1:]:
            result['occurrences_after_first'] += 1
            result['same_start'] += first[0] == other[0]
            result['same_length'] += first[1] == other[1]
            result['different_length'] += first[1] != other[1]
            identical = same_bytes(stream, first, other)
            result['identical_bytes'] += identical
            result['different_bytes'] += not identical
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
        selectors = read_records(root, entry)
        with (root / entry['path']).open('rb') as stream:
            header = stream.read(12)
            _, table, count = struct.unpack_from('<HIH', header, 4)
            stream.seek(table)
            raw = stream.read(count * 14)
            if len(raw) != count * 14 or count != len(selectors):
                raise ValueError('table changed during measurement')
            records = list(struct.iter_unpack('<HHHII', raw))
            for i, (kind, second, third, start, length) in enumerate(records):
                if (kind, second, third) != selectors[i]:
                    raise ValueError('table changed during measurement')
                if start < 12 or start + length > table:
                    raise ValueError('record outside bounded pre-table range')
            result = compare_groups(records, stream)
            totals.update(result)
            totals['files_examined'] += 1
            totals['files_with_duplicates'] += result['groups'] > 0
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
