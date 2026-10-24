#!/usr/bin/env python3
"""Measure selector lookup ambiguity and second-word ordering in SRSC tables."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from measure_level_0001 import safe_inventory_path


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

def measure(records):
    """Compare table-order first matches with a stable second-word ordering."""
    ordered = sorted(range(len(records)), key=lambda i: records[i][1])
    pair = Counter((a, b) for a, b, _ in records)
    triple = Counter(records)
    pair_first = {}
    triple_first = {}
    pair_thirds = {}
    for i, (a, b, c) in enumerate(records):
        pair_first.setdefault((a, b), i)
        triple_first.setdefault((a, b, c), i)
        pair_thirds.setdefault((a, b), set()).add(c)
    sorted_first = {}
    sorted_pair_first = {}
    for i in ordered:
        sorted_first.setdefault(records[i], i)
        sorted_pair_first.setdefault(records[i][:2], i)
    return {
        'records': len(records),
        'duplicate_pair_occurrences': sum(n - 1 for n in pair.values()),
        'duplicate_triple_occurrences': sum(n - 1 for n in triple.values()),
        'pairs_with_multiple_third_words': sum(len(values) > 1 for values in pair_thirds.values()),
        'pair_first_changes_after_stable_sort': sum(sorted_pair_first[k] != v for k, v in pair_first.items()),
        'triple_first_changes_after_stable_sort': sum(sorted_first[k] != v for k, v in triple_first.items()),
        'records_reordered': sum(i != original for i, original in enumerate(ordered)),
        'adjacent_second_word_decreases': sum(a[1] > b[1] for a, b in zip(records, records[1:])),
    }


def read_snapshot(root, entry):
    if not isinstance(entry, dict):
        raise ValueError('invalid inventory entry')
    relative = entry.get('path')
    expected_hash = entry.get('sha256')
    if not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash):
        raise ValueError('invalid inventory hash')
    path = safe_inventory_path(root, relative)
    data = path.read_bytes()
    expected_size = entry.get('file_size', entry.get('size'))
    if expected_size is not None and (type(expected_size) is not int or expected_size < 0):
        raise ValueError('invalid inventory size')
    if ((expected_size is not None and len(data) != expected_size)
            or hashlib.sha256(data).hexdigest() != expected_hash):
        raise ValueError('inventory hash mismatch or size mismatch: ' + str(relative))
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('not an SRSC header')
    version, table, count = struct.unpack_from('<HIH', data, 4)
    if version != 0x100 or not count or table < 12 or table > len(data):
        raise ValueError('invalid bounded table')
    if count > (len(data) - table) // 14:
        raise ValueError('invalid bounded table')
    raw = data[table:table + count * 14]
    records = [item[:3] for item in struct.iter_unpack('<HHHII', raw)]
    return data, records


def read_records(root, entry):
    """Return selector tuples from the verified snapshot."""
    return read_snapshot(root, entry)[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    summary = Counter()
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        result = measure(read_records(root, entry))
        summary.update(result)
        summary['files'] += 1
        summary['files_with_reordering'] += result['records_reordered'] > 0
        summary['files_with_duplicate_pairs'] += result['duplicate_pair_occurrences'] > 0
        summary['files_with_duplicate_triples'] += result['duplicate_triple_occurrences'] > 0
    print(json.dumps(dict(sorted(summary.items())), indent=2))


if __name__ == '__main__':
    main()
