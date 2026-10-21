#!/usr/bin/env python3
"""Compare candidate type-12 array values with level first dwords, in aggregate."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from measure_0102_array_types import resource_types
from measure_0102_model_candidates import table
from measure_0102_resource_table import RFL_SHA256, RESOURCE_OFFSET, RESOURCE_SIZE
from measure_srsc_prefix_selector import read_verified
from verify_level_entry import selected


def classify(units, flags, level_files, level_sets=None, distinct_range_values=None):
    if len(units) < len(flags):
        raise ValueError('array shorter than metadata count')
    result = Counter()

    def add(value, category):
        result[category + '_values'] += 1
        result[category + '_zero'] += value == 0
        count = level_files[value]
        result[category + '_no_level_match'] += count == 0
        result[category + '_one_level_match'] += count == 1
        result[category + '_multiple_level_matches'] += count > 1

    for index, flag in enumerate(flags):
        if (flag & 0xfff) != 12:
            continue
        if not flag & 0x1000:
            add(units[index], 'scalar')
            continue
        result['range_descriptors'] += 1
        value = units[index]
        first, high = value & 0xffff, value >> 16
        length = high if high < 0x8000 else high - 0x10000
        if first == 0 or high == 0:
            result['range_empty'] += 1
        elif length < 0:
            result['range_negative'] += 1
        elif first + length > len(units):
            result['range_outside'] += 1
        else:
            result['range_in_bounds'] += 1
            values = units[first:first + length]
            if distinct_range_values is not None:
                distinct_range_values.update(values)
            if level_sets is not None:
                common = set(level_sets.get(values[0], ()))
                for item in values[1:]:
                    common.intersection_update(level_sets.get(item, ()))
                result['range_no_common_level'] += len(common) == 0
                result['range_one_common_level'] += len(common) == 1
                result['range_multiple_common_levels'] += len(common) > 1
            for item in values:
                add(item, 'range')
    return result


def measure(data, metadata, level_files, level_sets=None, distinct_range_values=None):
    end, records = table(data)
    result = Counter()
    for kind, _, _, start, length in records:
        if kind != 0x102:
            continue
        result['records'] += 1
        if start < 12 or start > end or length > end - start:
            raise ValueError('selected record outside payload')
        payload = memoryview(data)[start:start + length]
        if len(payload) < 2:
            raise ValueError('short prefix')
        prefix = struct.unpack_from('<H', payload)[0]
        pos = 2 + prefix
        if pos > length or length - pos < 18:
            raise ValueError('short array header')
        key = struct.unpack_from('<H', payload, pos + 6)[0]
        declared, count = struct.unpack_from('<II', payload, pos + 10)
        pos += 18
        if count > (length - pos) // 4:
            raise ValueError('array outside payload')
        flags = metadata.get(key, ())
        if len(flags) != 1 or declared != len(flags[0]) or count < declared:
            raise ValueError('resource selection or array count mismatch')
        units = [x[0] for x in struct.iter_unpack('<I', payload[pos:pos + count * 4])]
        result.update(classify(units, flags[0], level_files, level_sets, distinct_range_values))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('rfl', type=Path)
    args = parser.parse_args()
    binary = args.rfl.read_bytes()
    if hashlib.sha256(binary).hexdigest() != RFL_SHA256:
        raise ValueError('RFL SHA-256 mismatch')
    if RESOURCE_OFFSET > len(binary) or RESOURCE_SIZE > len(binary) - RESOURCE_OFFSET:
        raise ValueError('resource outside RFL')
    metadata, _ = resource_types(binary[RESOURCE_OFFSET:RESOURCE_OFFSET + RESOURCE_SIZE])
    root = args.root.resolve(strict=True)
    items = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not items or any(item['status'] != 'examined' for item in items):
        raise ValueError('empty or incomplete inventory')
    level_files = Counter()
    level_sets = {}
    levels = 0
    # Each pass checks the inventory hash; no full-inventory snapshot is retained.
    for item in items:
        if Path(item['path']).suffix.lower() == '.lvl':
            _, entries = selected(read_verified(root, item))
            values = {int(entry['Prefix dwords'].split()[0], 16) for entry in entries}
            level_files.update(values)
            for value in values:
                level_sets.setdefault(value, set()).add(levels)
            levels += 1
    if not levels:
        raise ValueError('no level files')
    counts = Counter()
    distinct_range_values = set()
    for item in items:
        counts.update(measure(read_verified(root, item), metadata, level_files, level_sets, distinct_range_values))
    print(json.dumps({'files': len(items), 'levels': levels, 'distinct_level_values': len(level_files),
                      'distinct_range_values': len(distinct_range_values),
                      'counts': dict(sorted(counts.items()))}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
