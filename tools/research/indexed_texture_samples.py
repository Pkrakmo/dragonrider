#!/usr/bin/env python3
"""Measure depth-8 row index statistics and same-file palette candidates, without exporting pixels."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
import zlib

from palette_measure import measure_file

LIMIT = 16 * 1024 * 1024


def measure(payload, palette_count):
    if len(payload) < 50:
        return {'status': 'short_header'}
    width, height, stride, depth = struct.unpack_from('<IIIH', payload)
    storage = struct.unpack_from('<i', payload, 46)[0]
    if depth != 8:
        return {'status': 'other_depth'}
    if stride < width:
        return {'status': 'short_stride'}
    expected = height * stride
    if expected > LIMIT:
        return {'status': 'output_cap'}
    if storage <= 0:
        if expected > len(payload) - 50:
            return {'status': 'short_rows'}
        rows = payload[50:50 + expected]
    elif storage == 1:
        if len(payload) < 54:
            return {'status': 'short_stream_length'}
        length = struct.unpack_from('<I', payload, 50)[0]
        if length > len(payload) - 54:
            return {'status': 'short_stream'}
        dec = zlib.decompressobj()
        try:
            rows = dec.decompress(payload[54:54 + length], expected + 1)
        except zlib.error:
            return {'status': 'zlib_error'}
        if len(rows) != expected or not dec.eof or dec.unused_data or dec.unconsumed_tail:
            return {'status': 'zlib_mismatch'}
    else:
        return {'status': 'unsupported_storage'}
    hist = Counter()
    if width:
        for y in range(height):
            hist.update(rows[y * stride:y * stride + width])
    result = {'status': 'measured', 'width': width, 'height': height, 'stride': stride,
              'visible_indices': width * height, 'distinct_indices': len(hist),
              'minimum_index': min(hist, default=None), 'maximum_index': max(hist, default=None),
              'zero_indices': hist[0]}
    if palette_count is not None:
        result['indices_at_or_above_candidate_count'] = sum(n for i, n in hist.items() if i >= palette_count)
    return result


def scan(root):
    results = []
    summary = Counter()
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        info = measure_file(path, root)
        if not info or info['status'] != 'examined' or not info['texture_counts'].get('depth8'):
            continue
        # One qualified candidate only; do not conflate file co-occurrence with runtime selection.
        candidates = [r for r in info['palette_candidates'] if r.get('key2') == 0]
        candidate = candidates[0] if len(candidates) == 1 and candidates[0]['status'] in ('exact', 'trailing') else None
        palette_count = candidate['count'] if candidate else None
        file_result = {'path': info['path'], 'sha256': info['sha256'],
                       'qualified_candidate_count': len(candidates),
                       'selected_candidate_count': palette_count, 'records': []}
        if candidate:
            file_result['candidate_index'] = candidate['index']
        summary['files'] += 1
        summary['files_candidate_usable'] += int(candidate is not None)
        summary['files_candidate_zero'] += int(palette_count == 0)
        with path.open('rb') as stream:
            header = stream.read(12)
            _, table, count = struct.unpack_from('<HIH', header, 4)
            stream.seek(table)
            entries = stream.read(count * 14)
            if len(entries) != count * 14:
                raise OSError(f'truncated table: {path}')
            for index, (selector, _, _, start, length) in enumerate(struct.iter_unpack('<HHHII', entries)):
                if selector != 0x40 or start < 12 or start + length > table or length < 14:
                    continue
                stream.seek(start + 12)
                depth_data = stream.read(2)
                if len(depth_data) != 2:
                    raise OSError(f'truncated depth: {path}')
                if struct.unpack('<H', depth_data)[0] != 8:
                    continue
                if length > LIMIT:
                    m = {'status': 'input_cap'}
                else:
                    stream.seek(start)
                    payload = stream.read(length)
                    if len(payload) != length:
                        raise OSError(f'truncated payload: {path}')
                    m = measure(payload, palette_count)
                m['index'] = index
                summary['records'] += 1
                summary['status_' + m['status']] += 1
                if m['status'] == 'measured':
                    summary['visible_indices'] += m['visible_indices']
                    summary['zero_indices'] += m['zero_indices']
                    if palette_count is not None:
                        n = m['indices_at_or_above_candidate_count']
                        summary['records_candidate_nonzero' if palette_count else 'records_candidate_zero'] += 1
                        summary['indices_at_or_above_nonzero_candidate_count' if palette_count else 'indices_at_or_above_zero_candidate_count'] += n
                        summary['records_exceed_nonzero_candidate_count' if palette_count else 'records_exceed_zero_candidate_count'] += int(n > 0)
                file_result['records'].append(m)
        results.append(file_result)
    return {'root': str(root), 'summary': dict(sorted(summary.items())), 'files': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error('root must be a directory')
    result = scan(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result['summary'], indent=2))
    print('private output:', args.output)


if __name__ == '__main__':
    main()
