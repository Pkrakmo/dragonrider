#!/usr/bin/env python3
"""Measure bounded SRSC selector 0x0030 records and depth-8 association.

This measures structure and counts only; it never writes palette or texture bytes.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


def measure_file(path, root):
    size = path.stat().st_size
    with path.open('rb') as stream:
        header = stream.read(12)
        if len(header) != 12 or header[:4] != b'SRSC':
            return None
        version, table, count = struct.unpack_from('<HIH', header, 4)
        if version != 0x100 or table < 12 or table + count * 14 > size:
            return {'path': path.relative_to(root).as_posix(), 'status': 'skipped_header'}
        stream.seek(table)
        entries = stream.read(count * 14)
        if len(entries) != count * 14:
            raise OSError(f'truncated table: {path}')
        records, textures, gates = [], [], []
        for index, (selector, key1, key2, start, length) in enumerate(struct.iter_unpack('<HHHII', entries)):
            if selector not in (0x30, 0x40, 0x402):
                continue
            # The selection uses the observed data-area bounds, not a universal SRSC rule.
            if start < 12 or start + length > table:
                (records if selector == 0x30 else gates if selector == 0x402 else textures).append({'index': index, 'status': 'range'})
                continue
            if selector == 0x30:
                result = {'index': index, 'key1': key1, 'key2': key2, 'start': start, 'length': length}
                if length < 2:
                    result['status'] = 'short_count'
                else:
                    stream.seek(start)
                    raw = stream.read(2)
                    if len(raw) != 2:
                        raise OSError(f'truncated count: {path}')
                    palette_count = struct.unpack('<H', raw)[0]
                    result.update(count=palette_count, expected=2 + 4 * palette_count)
                    result['status'] = ('exact' if length == result['expected'] else
                                        'short_entries' if length < result['expected'] else 'trailing')
                records.append(result)
            elif selector == 0x402:
                result = {'index': index, 'key1': key1, 'key2': key2, 'start': start, 'length': length}
                if length < 4:
                    result['status'] = 'short_value'
                else:
                    stream.seek(start)
                    raw = stream.read(4)
                    if len(raw) != 4:
                        raise OSError(f'truncated gate: {path}')
                    result['value'] = struct.unpack('<I', raw)[0]
                    result['status'] = 'read'
                gates.append(result)
            elif length >= 14:
                stream.seek(start + 12)
                raw = stream.read(2)
                if len(raw) != 2:
                    raise OSError(f'truncated texture depth: {path}')
                if struct.unpack('<H', raw)[0] == 8:
                    textures.append({'index': index, 'status': 'depth8'})
            else:
                textures.append({'index': index, 'status': 'short_header'})
        stream.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return {'path': path.relative_to(root).as_posix(), 'status': 'examined', 'sha256': digest.hexdigest(),
            'palette_candidates': records, 'gates': gates,
            'texture_counts': dict(sorted(Counter(r['status'] for r in textures).items()))}


def scan(root):
    files = []
    for path in sorted(root.rglob('*')):
        if path.is_file() and not path.is_symlink():
            result = measure_file(path, root)
            if result is not None:
                files.append(result)
    summary = Counter()
    for f in files:
        summary['headers_' + f['status']] += 1
        if f['status'] != 'examined':
            continue
        candidates = f['palette_candidates']
        gated = any(g.get('key1') == 0 and g.get('key2') == 0 and g.get('value') == 0x204
                    for g in f['gates'])
        qualified = [r for r in candidates if r.get('key2') == 0]
        depth8 = f['texture_counts'].get('depth8', 0)
        summary['depth8_records'] += depth8
        summary['depth8_files'] += bool(depth8)
        summary['depth8_files_with_candidate'] += bool(depth8 and candidates)
        summary['depth8_files_with_nonzero_count_candidate'] += bool(depth8 and any(r.get('count', 0) for r in candidates))
        summary['depth8_files_with_matching_gate'] += bool(depth8 and gated)
        summary['depth8_files_gate_and_qualified_nonzero'] += bool(depth8 and gated and any(r.get('count', 0) for r in qualified))
        summary['files_matching_gate'] += gated
        for candidate in candidates:
            summary['candidate_records'] += 1
            summary['candidate_' + candidate['status']] += 1
            if 'count' in candidate:
                summary['count_' + str(candidate['count'])] += 1
            summary['candidate_key2_zero'] += candidate.get('key2') == 0
        for key, n in f['texture_counts'].items():
            if key != 'depth8':
                summary['texture_' + key] += n
    return {'root': str(root), 'summary': dict(sorted(summary.items())), 'files': files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error('root must be a directory')
    output = scan(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(output['summary'], indent=2))
    print('private output:', args.output)


if __name__ == '__main__':
    main()
