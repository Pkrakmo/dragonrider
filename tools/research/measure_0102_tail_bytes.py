#!/usr/bin/env python3
"""Summarize opaque bytes following the sampled 0x0102 conditional array."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_prefix_selector import read_verified
from measure_0102_model_candidates import table


def measure(data):
    end, entries = table(data)
    counts = Counter({key: 0 for key in ('records', 'with_tail', 'empty_tail',
        'all_zero_tail', 'tail_bytes', 'zero_bytes', 'tails_with_four_bytes',
        'printable_two_byte_tag', 'declared_length_fits', 'declared_length_exceeds_tail',
        'declared_body_nul_terminated', 'remaining_after_declared_body',
        'short_prefix', 'short_fields', 'short_array_header', 'array_exceeds_record')})
    leading = Counter()
    first_bytes = Counter()
    tags = Counter()
    declared_lengths = Counter()
    prefix_tags = Counter()
    for kind, _, _, start, length in entries:
        if kind != 0x0102:
            continue
        if start < 12 or start > end or length > end - start:
            raise ValueError('selected payload outside pre-table region')
        counts['records'] += 1
        payload = memoryview(data)[start:start + length]
        if length < 2:
            counts['short_prefix'] += 1
            continue
        prefix = struct.unpack_from('<H', payload)[0]
        pos = 2 + prefix + 10
        if pos > length:
            counts['short_fields'] += 1
            continue
        if length - pos < 8:
            counts['short_array_header'] += 1
            continue
        array_count = struct.unpack_from('<I', payload, pos + 4)[0]
        pos += 8
        if array_count > (length - pos) // 4:
            counts['array_exceeds_record'] += 1
            continue
        pos += array_count * 4
        tail = payload[pos:]
        if not tail:
            counts['empty_tail'] += 1
            continue
        counts['with_tail'] += 1
        counts['tail_bytes'] += len(tail)
        zeroes = sum(byte == 0 for byte in tail)
        counts['zero_bytes'] += zeroes
        counts['all_zero_tail'] += zeroes == len(tail)
        if len(tail) >= 4:
            counts['tails_with_four_bytes'] += 1
            leading[bytes(tail[:4]).hex()] += 1
        if len(tail) >= 8:
            packed = struct.unpack_from('<I', tail, 4)[0]
            declared = packed & 0xffff
            tag = (packed >> 16).to_bytes(2, 'little')
            tag_text = tag.decode('ascii', errors='replace')
            tags[tag_text] += 1
            prefix = struct.unpack_from('<I', tail)[0]
            prefix_tags[(prefix, tag_text)] += 1
            declared_lengths[declared] += 1
            counts['printable_two_byte_tag'] += all(32 <= byte < 127 for byte in tag)
            if declared <= len(tail) - 8:
                counts['declared_length_fits'] += 1
                body = tail[8:8 + declared]
                counts['declared_body_nul_terminated'] += bool(body) and body[-1] == 0
                counts['remaining_after_declared_body'] += len(tail) - 8 - declared
            else:
                counts['declared_length_exceeds_tail'] += 1
        first_bytes[f'{tail[0]:02x}'] += 1
    return counts, leading, first_bytes, tags, declared_lengths, prefix_tags


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not entries:
        raise ValueError('empty inventory')
    totals = Counter()
    leading = Counter()
    first_bytes = Counter()
    tags = Counter()
    declared_lengths = Counter()
    prefix_tags = Counter()
    files_with_records = 0
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        counts, prefixes, initial, tag_counts, length_counts, pair_counts = measure(read_verified(root, entry))
        totals.update(counts)
        leading.update(prefixes)
        first_bytes.update(initial)
        tags.update(tag_counts)
        declared_lengths.update(length_counts)
        prefix_tags.update(pair_counts)
        files_with_records += counts['records'] > 0
    print(json.dumps({'files_examined': len(entries), 'files_with_records': files_with_records,
        'counts': dict(sorted(totals.items())),
        'most_common_first_four_bytes': leading.most_common(20),
        'most_common_two_byte_tags': tags.most_common(20),
        'most_common_prefix_tag_pairs': [
            {'first_dword': prefix, 'tag': tag, 'count': count}
            for (prefix, tag), count in prefix_tags.most_common(30)],
        'most_common_candidate_lengths': declared_lengths.most_common(20),
        'first_byte_histogram': dict(sorted(first_bytes.items()))}, indent=2))


if __name__ == '__main__':
    main()
