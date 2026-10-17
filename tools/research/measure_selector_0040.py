#!/usr/bin/env python3
"""Measure two candidate storage layouts in bounded SRSC selector-0x0040 samples."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
import zlib

from analyze_srsc_payloads import inspect

MAX_BYTES = 16 * 1024 * 1024


def measure(payload, expected):
    result = {'length': len(payload), 'expected_product': expected}
    if len(payload) < 50:
        result['status'] = 'short_prefix'
        return result
    flag = struct.unpack_from('<I', payload, 46)[0]
    result['word_at_46'] = flag
    if flag == 0:
        result['status'] = 'zero_word'
        result['remaining_equals_product'] = len(payload) - 50 == expected
        return result
    if len(payload) < 54:
        result['status'] = 'short_size'
        return result
    compressed_size = struct.unpack_from('<I', payload, 50)[0]
    result['word_at_50'] = compressed_size
    if compressed_size > len(payload) - 54:
        result['status'] = 'stored_range_outside_payload'
        return result
    if expected > MAX_BYTES:
        result['status'] = 'product_cap'
        return result
    try:
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(payload[54:54 + compressed_size], MAX_BYTES + 1)
    except zlib.error:
        result['status'] = 'zlib_error'
        return result
    if len(decoded) > MAX_BYTES or decoder.unconsumed_tail:
        result['status'] = 'output_cap'
        return result
    if not decoder.eof:
        result['status'] = 'incomplete_stream'
        return result
    result['status'] = 'zlib_complete'
    result['decoded_length'] = len(decoded)
    result['decoded_equals_product'] = len(decoded) == expected
    result['declared_bytes_consumed'] = not decoder.unused_data
    trailing = payload[54 + compressed_size:]
    result['trailing_length'] = len(trailing)
    result['trailing_length_prefix_matches'] = (
        len(trailing) >= 4 and struct.unpack_from('<I', trailing)[0] == len(trailing) - 4)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error('root must be a directory')
    files = []
    summary = Counter()
    for path in sorted(args.root.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        examined = inspect(path, args.root)
        if examined is None:
            continue
        if examined['status'] != 'examined':
            summary['headers_skipped'] += 1
            continue
        summary['files'] += 1
        summary['invalid_ranges'] += examined['invalid_ranges']
        records = []
        with path.open('rb') as stream:
            for r in examined['records']:
                summary['records'] += 1
                if r['length'] > MAX_BYTES:
                    m = {'status': 'input_cap'}
                else:
                    stream.seek(r['start'])
                    payload = stream.read(r['length'])
                    if len(payload) != r['length']:
                        raise OSError(f'truncated payload: {path}')
                    m = measure(payload, r['b'] * r['c'])
                summary[m['status']] += 1
                if 'word_at_46' in m:
                    summary[f"word_at_46_{m['word_at_46']}"] += 1
                for name in ('decoded_equals_product', 'declared_bytes_consumed',
                             'remaining_equals_product', 'trailing_length_prefix_matches'):
                    summary[name] += int(bool(m.get(name)))
                if m.get('status') == 'zlib_complete' and m['trailing_length'] == 0:
                    summary['zlib_without_trailing'] += 1
                records.append({'index': r['index'], 'start': r['start'],
                                'a': r['a'], 'b': r['b'], 'c': r['c'], 'd': r['d'], **m})
        files.append({'path': examined['path'], 'sha256': examined['sha256'], 'records': records})
    output = {'root': str(args.root), 'summary': dict(sorted(summary.items())), 'files': files}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(output['summary'], indent=2))
    print('private output:', args.output)


if __name__ == '__main__':
    main()
