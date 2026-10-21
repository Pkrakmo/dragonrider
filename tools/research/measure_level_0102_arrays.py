#!/usr/bin/env python3
"""Compare raw level-object array units with indexed candidate 0x0102 units.

Inventory keys are lexical only; no embedded path is opened. Results are
aggregate observations under the explicitly chosen layout hypothesis.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path, PurePosixPath
import struct

from measure_0102_model_candidates import table
from measure_level_0102_sources import candidate_key
from measure_level_entry_caller import selected_payload
from measure_level_objects import decode
from measure_level_source_ids import records as level_records
from measure_level_texture_candidates import directory_entries, inventory_key
from measure_srsc_prefix_selector import read_verified


def positive_range(value, units):
    """Return a bounded raw candidate interval, without emulating dispatch."""
    start, length = value & 0xffff, value >> 16
    if not start or not length or length >= 0x8000:
        return None
    if start > len(units) or length > len(units) - start:
        return None
    return units[start:start + length]


def record_arrays(data):
    end, records = table(data)
    result = defaultdict(list)
    for kind, second, _, start, length in records:
        if kind != 0x102:
            continue
        if start < 12 or start > end or length > end - start or length < 2:
            raise ValueError('invalid selected record')
        payload = memoryview(data)[start:start + length]
        pos = 2 + struct.unpack_from('<H', payload)[0]
        if pos > length or length - pos < 18:
            raise ValueError('short selected record')
        declared, count = struct.unpack_from('<II', payload, pos + 10)
        pos += 18
        if count > (length - pos) // 4:
            raise ValueError('array outside record')
        units = tuple(x[0] for x in struct.iter_unpack('<I', payload[pos:pos + count * 4]))
        result[second].append((declared, units))
    return result


def compare(words, level_units, candidate, frames):
    declared, source_units = candidate
    if len(words) != len(frames):
        raise ValueError('level frame count mismatch')
    counts = Counter(objects_compared=1, words=len(words))
    counts['source_declared_exceeds_array'] += declared > len(source_units)
    counts['level_count_matches_source_count'] += len(level_units) == len(source_units)
    all_equal = True
    for pos, index in enumerate(words):
        if pos >= len(level_units):
            counts['word_without_level_unit'] += 1
            all_equal = False
            continue
        if index >= declared or index >= len(source_units):
            counts['word_outside_candidate_base'] += 1
            all_equal = False
            continue
        a, b = level_units[pos], source_units[index]
        counts['units_compared'] += 1
        counts['exact_units'] += a == b
        counts['equal_low_halves'] += (a & 0xffff) == (b & 0xffff)
        counts['equal_high_halves'] += (a >> 16) == (b >> 16)
        counts['both_zero'] += a == 0 and b == 0
        counts['exact_nonzero'] += a == b and a != 0
        group = 'flagged' if frames[pos][0] & 0x1000 else 'unflagged'
        counts[group + '_units_compared'] += 1
        counts[group + '_exact_units'] += a == b
        if group == 'flagged':
            level_range = positive_range(a, level_units)
            source_range = positive_range(b, source_units)
            counts['flagged_level_range_bounded'] += level_range is not None
            counts['flagged_source_range_bounded'] += source_range is not None
            if level_range is not None and source_range is not None:
                counts['flagged_both_ranges_bounded'] += 1
                counts['flagged_ranges_same_length'] += len(level_range) == len(source_range)
                counts['flagged_ranges_exact'] += level_range == source_range
        all_equal &= a == b
    counts['objects_all_base_units_equal'] += all_equal
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--overlay-hypothesis', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    items = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not items or any(item['status'] != 'examined' for item in items):
        raise ValueError('empty or incomplete inventory')
    indexed, levels = defaultdict(list), []
    for item in items:
        data = read_verified(root, item)
        key = inventory_key(list(PurePosixPath(item['path']).parts), args.overlay_hypothesis)
        indexed[key].append(record_arrays(data))
        if Path(item['path']).suffix.lower() == '.lvl':
            levels.append((item['path'], data))
    if not levels:
        raise ValueError('no levels')
    counts = Counter()
    for path, data in levels:
        _, directory = level_records(data)[(0, 0, 0)]
        sources = defaultdict(list)
        for ident, raw in directory_entries(directory):
            sources[ident].append(candidate_key(path, raw, args.overlay_hypothesis))
        objects, _ = decode(selected_payload(data))
        for row in objects:
            if row[4] <= 0 or row[5] <= 0:
                continue
            counts['objects_with_arrays'] += 1
            key = row[7][1]
            choices = sources.get(key >> 16, ())
            if len(choices) != 1 or choices[0] is None:
                counts['source_missing_or_ambiguous'] += 1
                continue
            files = indexed.get(choices[0], ())
            if len(files) != 1:
                counts['file_missing_or_ambiguous'] += 1
                continue
            matches = files[0].get(key & 0xffff, ())
            if len(matches) != 1:
                counts['record_missing_or_ambiguous'] += 1
                continue
            counts.update(compare(row[12], row[13], matches[0], row[14]))
    print(json.dumps({'files': len(items), 'levels': len(levels),
                      'overlay_hypothesis': args.overlay_hypothesis,
                      'counts': dict(sorted(counts.items()))}, indent=2))


if __name__ == '__main__':
    main()
