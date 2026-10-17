#!/usr/bin/env python3
"""Measure prefixes of candidate SRSC 0x0040 ranges, without decoding them."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


def inspect(path, root):
    size = path.stat().st_size
    with path.open('rb') as stream:
        header = stream.read(12)
        if len(header) != 12 or header[:4] != b'SRSC':
            return None
        version, table, count = struct.unpack_from('<HIH', header, 4)
        if version != 0x100 or not count or table < 12 or table + count * 14 > size:
            return {'path': path.relative_to(root).as_posix(), 'status': 'skipped_header'}
        stream.seek(table)
        entries = stream.read(count * 14)
        if len(entries) != count * 14:
            raise OSError(f'truncated table: {path}')
        measured = []
        invalid = 0
        for index, (tag, key, start, length) in enumerate(struct.iter_unpack('<HIII', entries)):
            if tag != 0x40:
                continue
            if start < 12 or length < 16 or start + length > table:
                invalid += 1
                continue
            stream.seek(start)
            prefix = stream.read(16)
            if len(prefix) != 16:
                raise OSError(f'truncated prefix: {path}')
            a, b, c, d = struct.unpack('<IIII', prefix)
            measured.append({'index': index, 'key': key, 'start': start, 'length': length,
                             'a': a, 'b': b, 'c': c, 'd': d})
        if not measured and not invalid:
            return None
        stream.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return {'path': path.relative_to(root).as_posix(), 'status': 'examined',
            'sha256': digest.hexdigest(), 'invalid_ranges': invalid, 'records': measured}


def power_of_two(value):
    return value > 0 and value & (value - 1) == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error('root must be a directory')
    files = []
    for path in sorted(args.root.rglob('*')):
        if path.is_file() and not path.is_symlink():
            result = inspect(path, args.root)
            if result is not None:
                files.append(result)
    records = [record for f in files if f['status'] == 'examined' for record in f['records']]
    summary = {
        'files_examined': sum(f['status'] == 'examined' for f in files),
        'headers_skipped': sum(f['status'] == 'skipped_header' for f in files),
        'invalid_ranges': sum(f.get('invalid_ranges', 0) for f in files),
        'records': len(records),
        'd_values': dict(sorted(Counter(str(r['d']) for r in records).items())),
        'c_times_8_equals_a_times_d_low16': sum(r['c'] * 8 == r['a'] * (r['d'] & 0xffff) for r in records),
        'equal_a_b': sum(r['a'] == r['b'] for r in records),
        'both_power_of_two': sum(power_of_two(r['a']) and power_of_two(r['b']) for r in records),
        'length_less_than_a_times_b_times_2': sum(r['length'] < r['a'] * r['b'] * 2 for r in records),
    }
    extensions = Counter()
    for f in files:
        if f['status'] == 'examined':
            extensions[Path(f['path']).suffix.lower()] += len(f['records'])
    summary['records_by_extension'] = dict(sorted(extensions.items()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'root': str(args.root), 'summary': summary, 'files': files}, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))
    print('private output:', args.output)


if __name__ == '__main__':
    main()
