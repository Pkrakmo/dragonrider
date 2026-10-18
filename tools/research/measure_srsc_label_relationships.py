#!/usr/bin/env python3
"""Measure same-file label fanout and repeated text; never output payload contents."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_lookup import read_records

PAIRS = ((0x0102, 0x0101), (0x0200, 0x0201), (0x0302, 0x0301))


def measure(records, labels, source_kind, label_kind):
    """Count matched source fanout and equal text within each candidate parent."""
    selected = [(second, third, labels[i]) for i, (kind, second, third) in enumerate(records)
                if kind == label_kind]
    by_key = {}
    for key, parent, value in selected:
        by_key.setdefault(key, []).append((parent, value))
    fanout = Counter(third for kind, _, third in records if kind == source_kind)
    stats = Counter({'labels': len(selected), 'source_records': sum(fanout.values()),
                     'source_matched_unique': 0, 'source_unmatched': 0,
                     'source_ambiguous': 0, 'labels_unreferenced': 0,
                     'labels_referenced_once': 0, 'labels_referenced_multiple': 0,
                     'duplicate_text_occurrences': 0,
                     'duplicate_sibling_text_occurrences': 0,
                     'max_label_fanout': 0})
    texts = Counter(value for _, _, value in selected)
    siblings = Counter((parent, value) for _, parent, value in selected)
    stats['duplicate_text_occurrences'] = sum(n - 1 for n in texts.values())
    stats['duplicate_sibling_text_occurrences'] = sum(n - 1 for n in siblings.values())
    for key, count in fanout.items():
        size = len(by_key.get(key, ()))
        stats['source_matched_unique'] += count if size == 1 else 0
        stats['source_unmatched'] += count if size == 0 else 0
        stats['source_ambiguous'] += count if size > 1 else 0
    for key, _, _ in selected:
        n = fanout[key]
        stats['labels_unreferenced'] += n == 0
        stats['labels_referenced_once'] += n == 1
        stats['labels_referenced_multiple'] += n > 1
        stats['max_label_fanout'] = max(stats['max_label_fanout'], n)
    return stats


def payload_labels(path, records):
    """Read bounded selected payloads; return normalized byte strings only in memory."""
    labels = {}
    with path.open('rb') as stream:
        header = stream.read(12)
        _, table, count = struct.unpack_from('<HIH', header, 4)
        stream.seek(table)
        raw = stream.read(count * 14)
        if len(raw) != count * 14 or count != len(records):
            raise ValueError('table changed during measurement')
        for i, (kind, second, third, start, length) in enumerate(struct.iter_unpack('<HHHII', raw)):
            if (kind, second, third) != records[i]:
                raise ValueError('table changed during measurement')
            if kind not in {pair[1] for pair in PAIRS}:
                continue
            if start < 12 or length < 2 or length > 65537 or start + length > table:
                raise ValueError('invalid bounded label payload')
            stream.seek(start)
            payload = stream.read(length)
            if len(payload) != length or int.from_bytes(payload[:2], 'little') != length - 2:
                raise ValueError('invalid label framing')
            value = payload[2:]
            if not value or any(not (32 <= b <= 126 or b == 0) for b in value) or 0 in value[:-1]:
                raise ValueError('unexpected label bytes')
            labels[i] = value[:-1] if value[-1] == 0 else value
    return labels


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not entries:
        raise ValueError('empty inventory')
    totals = {f'{a:04x}_to_{b:04x}': Counter() for a, b in PAIRS}
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        try:
            records = read_records(root, entry)
            labels = payload_labels(root / entry['path'], records)
        except ValueError:
            raise ValueError('invalid inventory entry or sample') from None
        for a, b in PAIRS:
            key = f'{a:04x}_to_{b:04x}'
            result = measure(records, labels, a, b)
            maximum = max(totals[key]['max_label_fanout'], result['max_label_fanout'])
            totals[key].update(result)
            totals[key]['max_label_fanout'] = maximum
    print(json.dumps({'files_examined': len(entries), 'kind_pairs': totals}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
