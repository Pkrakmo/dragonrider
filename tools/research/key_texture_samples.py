#!/usr/bin/env python3
"""Measure texture offset-18 values and depth-8 byte equality, without exporting rows."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import zlib

LIMIT = 16 * 1024 * 1024
SENTINEL = 0xffffffff


def inspect_payload(payload):
    if len(payload) < 50:
        return {'status': 'short_header'}
    width, height, stride, depth = struct.unpack_from('<IIIH', payload)
    key = struct.unpack_from('<I', payload, 18)[0]
    result = {'status': 'header', 'depth': depth, 'key': key}
    if depth != 8:
        return result
    if stride < width:
        result['status'] = 'short_stride'
        return result
    expected = stride * height
    if expected > LIMIT:
        result['status'] = 'output_cap'
        return result
    storage = struct.unpack_from('<i', payload, 46)[0]
    if storage <= 0:
        if expected > len(payload) - 50:
            result['status'] = 'short_rows'
            return result
        rows = payload[50:50 + expected]
    elif storage == 1:
        if len(payload) < 54:
            result['status'] = 'short_stream_length'
            return result
        n = struct.unpack_from('<I', payload, 50)[0]
        if n > len(payload) - 54:
            result['status'] = 'short_stream'
            return result
        decoder = zlib.decompressobj()
        try:
            rows = decoder.decompress(payload[54:54+n], expected + 1)
        except zlib.error:
            result['status'] = 'zlib_error'
            return result
        if len(rows) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            result['status'] = 'zlib_mismatch'
            return result
    else:
        result['status'] = 'unsupported_storage'
        return result
    # Full-width equality matters: the device getter may return a dword > 255.
    matches = 0
    if key < 256 and width:
        for y in range(height):
            matches += rows[y * stride:y * stride + width].count(key)
    result.update(status='measured', visible_indices=width * height, matches=matches)
    return result


def scan(root):
    summary = Counter()
    files = []
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        size = path.stat().st_size
        with path.open('rb') as stream:
            header = stream.read(12)
            if len(header) != 12 or header[:4] != b'SRSC':
                continue
            version, table, count = struct.unpack_from('<HIH', header, 4)
            if version != 0x100 or table < 12 or table + count * 14 > size:
                summary['skipped_header'] += 1
                continue
            stream.seek(table)
            entries = stream.read(count * 14)
            if len(entries) != count * 14:
                raise OSError('truncated record table')
            records = []
            for index, (selector, _, _, start, length) in enumerate(struct.iter_unpack('<HHHII', entries)):
                if selector != 0x40:
                    continue
                summary['records_selected'] += 1
                if start < 12 or start + length > table:
                    result = {'status': 'range'}
                elif length > LIMIT:
                    result = {'status': 'input_cap'}
                else:
                    stream.seek(start)
                    payload = stream.read(length)
                    if len(payload) != length:
                        raise OSError('truncated texture payload')
                    result = inspect_payload(payload)
                result['index'] = index
                records.append(result)
                summary['status_' + result['status']] += 1
                if 'key' not in result:
                    continue
                depth, key = result['depth'], result['key']
                category = 'sentinel' if key == SENTINEL else 'byte' if key < 256 else 'other'
                summary[f'depth_{depth}_{category}'] += 1
                if result['status'] == 'measured':
                    summary[f'depth8_{category}_records_with_matches'] += result['matches'] > 0
                    summary[f'depth8_{category}_matches'] += result['matches']
                    summary[f'depth8_{category}_visible'] += result['visible_indices']
            if records:
                stream.seek(0)
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
                files.append({'path': path.relative_to(root).as_posix(), 'sha256': digest.hexdigest(), 'records': records})
    return {'root': str(root), 'summary': dict(sorted(summary.items())), 'files': files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error('root must be a directory')
    report = scan(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report['summary'], indent=2))
    print('private output:', args.output)


if __name__ == '__main__':
    main()
