#!/usr/bin/env python3
"""Compare 0x0102 prefix bytes and candidate 0x0101 chains without printing names."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import struct

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified

MAX_CHAIN_STEPS_PER_FILE = 1_000_000


def framed_prefix(data, start, length, offset, exact):
    if start < 12 or start > offset or length > offset - start or length < 2:
        raise ValueError('invalid bounded payload')
    size = struct.unpack_from('<H', data, start)[0]
    if size > length - 2 or (exact and size != length - 2):
        raise ValueError('invalid prefix length')
    value = data[start + 2:start + 2 + size]
    return value[:-1] if value.endswith(b'\0') else value


def measure(data):
    offset, entries = table(data)
    labels = defaultdict(list)
    sources = []
    for kind, second, third, start, length in entries:
        if kind == 0x0101:
            labels[second].append((third, framed_prefix(data, start, length, offset, True)))
        elif kind == 0x0102:
            sources.append((third, framed_prefix(data, start, length, offset, False)))
    counts = Counter({name: 0 for name in ('sources', 'labels', 'label_missing',
        'label_multiple', 'label_unique', 'source_empty', 'source_internal_nul',
        'source_nonprintable', 'source_path_separator', 'source_slash',
        'source_backslash', 'source_colon', 'source_equals_label',
        'source_equals_label_ascii_casefold', 'source_equals_ancestor',
        'chain_zero', 'chain_zero_one_hop', 'chain_zero_two_hops', 'chain_zero_three_or_more',
        'chain_missing', 'chain_multiple', 'chain_cycle',
        'source_duplicate_in_file', 'source_duplicate_in_label',
        'source_casefold_duplicate_in_file', 'source_casefold_duplicate_in_label',
        'files_with_label_duplicates')})
    counts['sources'] = len(sources)
    counts['labels'] = sum(map(len, labels.values()))
    source_names = Counter(value for _, value in sources)
    counts['source_duplicate_in_file'] = sum(n - 1 for n in source_names.values())
    folded_source_names = Counter(value.lower() for _, value in sources)
    counts['source_casefold_duplicate_in_file'] = sum(n - 1 for n in folded_source_names.values())
    sibling_names = Counter((key, value) for key, value in sources)
    folded_names = Counter((key, value.lower()) for key, value in sources)
    counts['source_duplicate_in_label'] = sum(n - 1 for n in sibling_names.values())
    counts['source_casefold_duplicate_in_label'] = sum(n - 1 for n in folded_names.values())
    counts['files_with_label_duplicates'] = counts['source_duplicate_in_label'] > 0
    chain_steps = 0
    for key, value in sources:
        counts['source_empty'] += not value
        counts['source_internal_nul'] += b'\0' in value
        counts['source_nonprintable'] += any(b < 32 or b > 126 for b in value)
        counts['source_path_separator'] += b'/' in value or b'\\' in value
        counts['source_slash'] += b'/' in value
        counts['source_backslash'] += b'\\' in value
        counts['source_colon'] += b':' in value
        matches = labels.get(key, ())
        if not matches:
            counts['label_missing'] += 1
        elif len(matches) > 1:
            counts['label_multiple'] += 1
        else:
            counts['label_unique'] += 1
            counts['source_equals_label'] += value == matches[0][1]
            counts['source_equals_label_ascii_casefold'] += value.lower() == matches[0][1].lower()
        visited = set()
        current = key
        ancestor_match = False
        while current:
            chain_steps += 1
            if chain_steps > MAX_CHAIN_STEPS_PER_FILE:
                raise ValueError('candidate chain step limit exceeded')
            if current in visited:
                counts['chain_cycle'] += 1
                break
            visited.add(current)
            choices = labels.get(current, ())
            if not choices:
                counts['chain_missing'] += 1
                break
            if len(choices) != 1:
                counts['chain_multiple'] += 1
                break
            current, name = choices[0]
            ancestor_match |= value == name
        else:
            counts['chain_zero'] += 1
            depth = len(visited)
            if depth == 1:
                counts['chain_zero_one_hop'] += 1
            elif depth == 2:
                counts['chain_zero_two_hops'] += 1
            elif depth >= 3:
                counts['chain_zero_three_or_more'] += 1
        counts['source_equals_ancestor'] += ancestor_match
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    inventory = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not inventory:
        raise ValueError('empty inventory')
    result = Counter()
    for item in inventory:
        if item['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        result.update(measure(read_verified(root, item)))
    print(json.dumps({'files_examined': len(inventory), 'counts': dict(sorted(result.items()))},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
