#!/usr/bin/env python3
"""Measure selector lookup ambiguity and second-word ordering in SRSC tables."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


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


def read_records(root, entry):
    relative = Path(entry['path'])
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('invalid inventory path')
    path = root / relative
    if any(p.is_symlink() for p in [path, *path.parents] if p != root and root in p.parents):
        raise ValueError('symlink in inventory path')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        header = stream.read(12)
        if len(header) != 12 or header[:4] != b'SRSC':
            raise ValueError('not an SRSC header')
        version, table, count = struct.unpack_from('<HIH', header, 4)
        if version != 0x100 or not count or table < 12 or table + count * 14 > path.stat().st_size:
            raise ValueError('invalid bounded table')
        stream.seek(0)
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        if digest.hexdigest() != entry['sha256']:
            raise ValueError('inventory hash mismatch: ' + str(relative))
        stream.seek(table)
        raw = stream.read(count * 14)
        if len(raw) != count * 14:
            raise ValueError('short table read')
    return [item[:3] for item in struct.iter_unpack('<HHHII', raw)]


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
