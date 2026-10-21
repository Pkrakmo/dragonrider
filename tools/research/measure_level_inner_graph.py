#!/usr/bin/env python3
"""Measure candidate inner-index relationships without resolving runtime objects."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified

MAX_VALUES = 1000000


def signed(value):
    value &= 0xffffffff
    return value if value < 0x80000000 else value - 0x100000000


def measure(payload, first_word_files=None):
    pos = 0

    def take(n):
        nonlocal pos
        if n < 0 or n > len(payload) - pos:
            raise ValueError('truncated level prefix')
        part = payload[pos:pos + n]
        pos += n
        return part

    def dword():
        return struct.unpack('<I', take(4))[0]

    count = dword()
    if count > 4096:
        raise ValueError('entry limit')
    rows = []
    total = 0
    for _ in range(count):
        fields = struct.unpack('<7I', take(28))
        name_len = struct.unpack('<H', take(2))[0]
        take(name_len)
        take(24)
        size = dword()
        total += size
        if size > 4096 or total > MAX_VALUES:
            raise ValueError('inner count limit')
        values = [x[0] for x in struct.iter_unpack('<I', take(size * 4))]
        rows.append((fields, values))
    counts = Counter(entries=count, values=total)
    first_words = Counter(fields[0] for fields, _ in rows)
    if first_word_files is not None:
        first_word_files.update(first_words.keys())
    counts['first_dword_zero'] = first_words[0]
    counts['first_dword_duplicate_occurrences'] = sum(n - 1 for n in first_words.values())
    counts['first_dword_matches_entry_index'] = sum(fields[0] == i for i, (fields, _) in enumerate(rows))
    sets = [{value & 0xffff for value in values} for _, values in rows]
    for i, (fields, values) in enumerate(rows):
        low_values = [value & 0xffff for value in values]
        self_positions = [p for p, value in enumerate(values) if value == i]
        counts['entries_self_once'] += len(self_positions) == 1
        counts['entries_self_first'] += self_positions == [0]
        counts['entries_self_last'] += self_positions == [len(values) - 1]
        counts['repeated_low_occurrences'] += len(low_values) - len(sets[i])
        overlap_positions = []
        for position, value in enumerate(values):
            target = value & 0xffff
            counts['values_nonzero_high'] += bool(value >> 16)
            if target >= count:
                counts['low_outside'] += 1
                continue
            counts['values_in_range'] += 1
            reciprocal = i in sets[target]
            counts['reciprocal_occurrences'] += reciprocal
            if target == i:
                counts['self_occurrences'] += 1
            other = rows[target][0]
            x, y, width, height = signed(fields[4]), signed(fields[5]), signed(fields[1]), signed(fields[2])
            xx, yy, ww, hh = signed(other[4]), signed(other[5]), signed(other[1]), signed(other[2])
            overlap = (xx < signed(x + width) and yy < signed(y + height) and
                       signed(xx + ww) > x and signed(yy + hh) > y)
            counts['strict_rectangle_overlap'] += overlap
            counts['strict_rectangle_nonoverlap'] += not overlap
            counts['overlap_reciprocal'] += overlap and reciprocal
            counts['overlap_nonreciprocal'] += overlap and not reciprocal
            if overlap:
                overlap_positions.append(position)
        if not overlap_positions:
            counts['entries_without_overlap'] += 1
        else:
            counts['entries_with_overlap'] += 1
            span_size = overlap_positions[-1] - overlap_positions[0] + 1
            counts['entries_overlap_contiguous'] += span_size == len(overlap_positions)
            counts['nonoverlap_inside_overlap_span'] += span_size - len(overlap_positions)
            counts['entries_self_within_overlap_span'] += any(overlap_positions[0] <= p <= overlap_positions[-1] for p in self_positions)
            counts['entries_self_overlaps'] += any(p in overlap_positions for p in self_positions)
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    levels = [entry for entry in entries if Path(entry['path']).suffix.lower() == '.lvl']
    if not levels:
        raise ValueError('no levels')
    total = Counter()
    first_word_files = Counter()
    for entry in levels:
        if entry['status'] != 'examined':
            raise ValueError('unexamined level')
        data = read_verified(root, entry)
        end, records = table(data)
        matching = [(start, length) for a, b, c, start, length in records if (a, b, c) == (1, 0, 0)]
        if len(matching) != 1:
            raise ValueError('expected one level record')
        start, length = matching[0]
        if start < 12 or start > end or length > end - start:
            raise ValueError('invalid level record range')
        total.update(measure(data[start:start + length], first_word_files))
    sharing = {'distinct_values': len(first_word_files),
               'values_in_multiple_files': sum(n > 1 for n in first_word_files.values()),
               'occurrences_after_first_file': sum(n - 1 for n in first_word_files.values()),
               'maximum_files_per_value': max(first_word_files.values(), default=0)}
    print(json.dumps({'files': len(levels), 'counts': dict(sorted(total.items())),
                      'first_dword_cross_file': sharing}, indent=2))


if __name__ == '__main__':
    main()
