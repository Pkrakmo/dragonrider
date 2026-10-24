#!/usr/bin/env python3
"""Compare duplicate-selector payload ranges without exporting their contents."""
import argparse
from collections import Counter, defaultdict
import hashlib
import io
import json
from pathlib import Path
import re
import struct

from measure_level_0001 import safe_inventory_path


MAX_COMPARISON_BYTES = 64 * 1024 * 1024
CHUNK = 65536
_SHA256 = re.compile(r'[0-9a-f]{64}\Z')


def read_verified_records(root, entry):
    """Return one immutable file snapshot and its bounded SRSC records."""
    if not isinstance(entry, dict) or entry.get('status') != 'examined':
        raise ValueError('inventory contains an unexamined file')
    size = entry.get('file_size')
    digest = entry.get('sha256')
    if type(size) is not int or size < 0:
        raise ValueError('invalid inventory file size')
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError('invalid inventory hash')
    path = safe_inventory_path(root, entry.get('path'))
    data = path.read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('inventory size or hash mismatch')
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('not an SRSC header')
    version, table, count = struct.unpack_from('<HIH', data, 4)
    table_end = table + count * 14
    if version != 0x100 or not count or table < 12 or table_end > len(data):
        raise ValueError('invalid bounded table')
    records = list(struct.iter_unpack('<HHHII', data[table:table_end]))
    for _, _, _, start, length in records:
        if start < 12 or start > table or length > table - start:
            raise ValueError('record outside bounded pre-table range')
    return data, records


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
    seen_paths = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get('path'), str):
            raise ValueError('invalid inventory path')
        if entry['path'] in seen_paths:
            raise ValueError('duplicate inventory path')
        seen_paths.add(entry['path'])
        data, records = read_verified_records(root, entry)
        result = compare_groups(records, io.BytesIO(data))
        totals.update(result)
        totals['files_examined'] += 1
        totals['files_with_duplicates'] += result['groups'] > 0
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
