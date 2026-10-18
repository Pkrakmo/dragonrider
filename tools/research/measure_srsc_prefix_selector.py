#!/usr/bin/env python3
"""Compare selected post-prefix words with SRSC table selector words."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

KINDS = (0x0102, 0x0302)
COUNTERS = ('records', 'short_prefix', 'prefix_outside_record', 'short_post_prefix',
            'compared', 'word_zero', 'third_zero', 'equals_second',
            'equals_third', 'differs_third')
MATCH_COUNTERS = ('matches_0101_none', 'matches_0101_unique', 'matches_0101_multiple')


def empty_counts(kind):
    names = COUNTERS + (MATCH_COUNTERS if kind == 0x0102 else ())
    return Counter({key: 0 for key in names})


def measure(data):
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('invalid SRSC header')
    version, table, count = struct.unpack_from('<HIH', data, 4)
    if version != 0x100 or count == 0 or table < 12 or table + count * 14 > len(data):
        raise ValueError('invalid SRSC table')
    result = {kind: empty_counts(kind) for kind in KINDS}
    entries = list(struct.iter_unpack('<HHHII', data[table:table + count * 14]))
    label_keys = Counter(second for kind, second, _, _, _ in entries if kind == 0x0101)
    for kind, second, third, start, length in entries:
        if kind not in result:
            continue
        if start < 12 or start + length > table:
            raise ValueError('selected payload outside pre-table region')
        counts = result[kind]
        counts['records'] += 1
        if length < 2:
            counts['short_prefix'] += 1
            continue
        prefix = struct.unpack_from('<H', data, start)[0]
        if prefix > length - 2:
            counts['prefix_outside_record'] += 1
            continue
        if prefix > length - 4:
            counts['short_post_prefix'] += 1
            continue
        word = struct.unpack_from('<H', data, start + 2 + prefix)[0]
        counts['compared'] += 1
        counts['word_zero'] += word == 0
        counts['third_zero'] += third == 0
        counts['equals_second'] += word == second
        counts['equals_third'] += word == third
        counts['differs_third'] += word != third
        if kind == 0x0102:
            matches = label_keys[word]
            counts['matches_0101_none'] += matches == 0
            counts['matches_0101_unique'] += matches == 1
            counts['matches_0101_multiple'] += matches > 1
    return result


def read_verified(root, entry):
    relative = Path(entry['path'])
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('invalid inventory path')
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError('inventory path escapes root or is not a file')
    data = path.read_bytes()
    if len(data) != entry['file_size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('inventory size or hash mismatch')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not entries:
        raise ValueError('empty inventory')
    totals = {kind: empty_counts(kind) for kind in KINDS}
    files_with_kind = Counter({kind: 0 for kind in KINDS})
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        result = measure(read_verified(root, entry))
        for kind in KINDS:
            totals[kind].update(result[kind])
            files_with_kind[kind] += result[kind]['records'] > 0
    print(json.dumps({'files_examined': len(entries),
                      'kinds': {f'{kind:04x}': dict(totals[kind], files=files_with_kind[kind])
                                for kind in KINDS}}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
