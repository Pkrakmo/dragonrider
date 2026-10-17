#!/usr/bin/env python3
"""Measure bounded 0x0040 retail header layouts and optional blocks; no pixel interpretation."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
import zlib

from analyze_srsc_payloads import inspect

LIMIT = 16 * 1024 * 1024


def measure(payload):
    if len(payload) < 50:
        return {'status': 'short_header'}
    width, height, row, depth, *words = struct.unpack_from('<IIIH9I', payload)
    result = {'width': width, 'height': height, 'row': row, 'depth': depth,
              'words': words, 'row_relation': row * 8 == width * depth}
    expected = height * row
    if expected > LIMIT:
        return {**result, 'status': 'output_cap'}
    if words[8] == 0:
        result['status'] = 'raw'
        result['available_exact'] = len(payload) == 50 + expected
        return result
    if words[8] != 1 or len(payload) < 54:
        return {**result, 'status': 'unsupported_storage_or_short'}
    n = struct.unpack_from('<I', payload, 50)[0]
    if n > len(payload) - 54:
        return {**result, 'status': 'stream_range'}
    decoder = zlib.decompressobj()
    try:
        decoded = decoder.decompress(payload[54:54 + n], expected + 1)
    except zlib.error:
        return {**result, 'status': 'zlib_error'}
    if len(decoded) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        return {**result, 'status': 'zlib_mismatch'}
    result['status'] = 'zlib'
    trailing = payload[54 + n:]
    result['trailing_length'] = len(trailing)
    if len(trailing) >= 4:
        length = struct.unpack_from('<I', trailing)[0]
        result['tail_length_matches'] = length == len(trailing) - 4
        for name, window in (('tail_is_complete_zlib', zlib.MAX_WBITS),
                             ('tail_is_complete_raw_deflate', -zlib.MAX_WBITS)):
            try:
                extra = zlib.decompressobj(window)
                extra_decoded = extra.decompress(trailing[4:], LIMIT + 1)
                result[name] = (len(extra_decoded) <= LIMIT and extra.eof
                                and not extra.unused_data and not extra.unconsumed_tail)
            except zlib.error:
                result[name] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error('root must be a directory')
    counts = Counter()
    files = []
    for path in sorted(args.root.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        f = inspect(path, args.root)
        if not f or f['status'] != 'examined':
            continue
        out = {'path': f['path'], 'sha256': f['sha256'], 'records': []}
        counts['invalid_ranges'] += f['invalid_ranges']
        with path.open('rb') as stream:
            for record in f['records']:
                if record['length'] > LIMIT:
                    measurement = {'status': 'input_cap'}
                else:
                    stream.seek(record['start'])
                    payload = stream.read(record['length'])
                    if len(payload) != record['length']:
                        raise OSError(f'truncated payload: {path}')
                    measurement = measure(payload)
                counts['records'] += 1
                counts['status_' + measurement['status']] += 1
                if 'depth' in measurement:
                    counts[f"depth_{measurement['depth']}"] += 1
                    counts['row_relation_true'] += int(measurement['row_relation'])
                    counts['flag_0x100'] += int(bool(measurement['words'][5] & 0x100))
                    counts['trailing_nonzero'] += int(measurement.get('trailing_length', 0) > 0)
                out['records'].append({'index': record['index'], 'start': record['start'],
                                       'length': record['length'], **measurement})
        files.append(out)
    output = {'root': str(args.root), 'summary': dict(sorted(counts.items())), 'files': files}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(output['summary'], indent=2))
    print('private output:', args.output)


if __name__ == '__main__':
    main()
