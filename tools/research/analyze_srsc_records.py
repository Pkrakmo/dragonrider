#!/usr/bin/env python3
"""Measure candidate SRSC table properties; write private aggregate metadata.

This is an observation tool, not a format validator. Interpretations at offsets
0, 2, 6 and 10 within each entry are hypotheses to test against samples.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


def inspect(path, root):
    with path.open('rb') as stream:
        header = stream.read(12)
        if len(header) < 12 or header[:4] != b'SRSC':
            return None
        data = header + stream.read()
    size = len(data)
    version, table, count = struct.unpack_from('<HIH', data, 4)
    end = table + count * 14
    if version != 0x100 or not count or table < 12 or end > size:
        return {'path': path.relative_to(root).as_posix(), 'status': 'skipped_invalid_header'}
    raw = data[table:end]
    if len(raw) != count * 14:
        raise OSError(f'truncated table: {path}')
    entries = list(struct.iter_unpack('<HIII', raw))
    ranges = [(entry[2], entry[2] + entry[3]) for entry in entries]
    pairs = list(zip(ranges, ranges[1:]))
    keys = [(entry[0], entry[1]) for entry in entries]
    return {'path': path.relative_to(root).as_posix(), 'sha256': hashlib.sha256(data).hexdigest(),
            'file_size': size, 'table_offset': table, 'count': count, 'status': 'examined',
            'ranges_within_payload': sum(12 <= a <= b <= table for a, b in ranges),
            'zero_lengths': sum(a == b for a, b in ranges),
            'first_range_starts_at_12': ranges[0][0] == 12,
            'last_range_ends_at_table': ranges[-1][1] == table,
            'adjacent_pairs': sum(a[1] == b[0] for a, b in pairs),
            'nondecreasing_starts': sum(a[0] <= b[0] for a, b in pairs),
            'duplicate_keys': len(keys) - len(set(keys)),
            'table_ends_at_eof': end == size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error('root must be a directory')
    results = []
    for path in sorted(args.root.rglob('*')):
        if path.is_file() and not path.is_symlink():
            item = inspect(path, args.root)
            if item is not None:
                results.append(item)
    examined = [x for x in results if x['status'] == 'examined']
    summary = {'files_examined': len(examined), 'files_skipped': len(results)-len(examined),
               'records': sum(x['count'] for x in examined),
               'ranges_within_payload': sum(x['ranges_within_payload'] for x in examined),
               'zero_lengths': sum(x['zero_lengths'] for x in examined),
               'files_first_range_starts_at_12': sum(x['first_range_starts_at_12'] for x in examined),
               'files_last_range_ends_at_table': sum(x['last_range_ends_at_table'] for x in examined),
               'adjacent_pairs': sum(x['adjacent_pairs'] for x in examined),
               'pairs': sum(x['count'] - 1 for x in examined),
               'nondecreasing_starts': sum(x['nondecreasing_starts'] for x in examined),
               'duplicate_keys': sum(x['duplicate_keys'] for x in examined),
               'files_table_ends_at_eof': sum(x['table_ends_at_eof'] for x in examined),
               'extensions': dict(sorted(Counter(Path(x['path']).suffix.lower() for x in examined).items()))}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'root': str(args.root), 'summary': summary, 'files': results}, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))
    print('private output:', args.output)


if __name__ == '__main__':
    main()
