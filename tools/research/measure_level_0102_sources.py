#!/usr/bin/env python3
"""Compare type-12 numeric level matches with lexical level-directory sources.

Uses inventory keys only; embedded paths are never opened. The overlay convention
is an explicit hypothesis, not a runtime path resolver.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import struct

from measure_0102_array_types import resource_types
from measure_0102_model_candidates import table
from measure_0102_resource_table import RFL_SHA256, RESOURCE_OFFSET, RESOURCE_SIZE
from measure_level_source_ids import records as level_records
from measure_level_texture_candidates import directory_entries, inventory_key
from measure_srsc_prefix_selector import read_verified
from verify_level_entry import selected


def candidate_key(level_path, raw, overlay):
    if raw.endswith(b'\0') and b'\0' not in raw[:-1]:
        raw = raw[:-1]
    try:
        name = raw.decode('ascii')
    except UnicodeDecodeError:
        return None
    if not name or name.endswith(('\\', '/')) or len(name) >= 256 or any(ord(c) < 32 or ord(c) >= 127 for c in name):
        return None
    target = PureWindowsPath(name)
    if target.drive or target.root or ':' in name or target.name in ('', '..'):
        return None
    level = PurePosixPath(level_path)
    if level.is_absolute() or '..' in level.parts or '\\' in level_path:
        return None
    parts = list(level.parent.parts)
    for component in target.parts:
        if component == '..':
            if not parts:
                return None
            parts.pop()
        elif component != '.':
            parts.append(component)
    if not parts:
        return None
    if '.' not in parts[-1]:
        parts[-1] += '.odb'
    return inventory_key(parts, overlay)


def ranges(data, metadata):
    end, records = table(data)
    for kind, _, _, start, length in records:
        if kind != 0x102:
            continue
        if start < 12 or start > end or length > end - start:
            raise ValueError('selected record outside payload')
        payload = memoryview(data)[start:start + length]
        if len(payload) < 2:
            raise ValueError('short prefix')
        size = struct.unpack_from('<H', payload)[0]
        pos = 2 + size
        if pos > length or length - pos < 18:
            raise ValueError('short array header')
        key = struct.unpack_from('<H', payload, pos + 6)[0]
        declared, count = struct.unpack_from('<II', payload, pos + 10)
        pos += 18
        if count > (length - pos) // 4:
            raise ValueError('array exceeds record')
        flags = metadata.get(key, ())
        if len(flags) != 1 or declared != len(flags[0]) or count < declared:
            raise ValueError('metadata selection or count mismatch')
        units = [unit[0] for unit in struct.iter_unpack('<I', payload[pos:pos + count * 4])]
        for index, flag in enumerate(flags[0]):
            if flag & 0x1fff != 0x100c:
                continue
            encoded = units[index]
            first, high = encoded & 0xffff, encoded >> 16
            length = high if high < 0x8000 else high - 0x10000
            if not first or not high or length < 0 or first + length > count:
                continue
            yield units[first:first + length]


def classify(values, value_levels, source_levels):
    if not values:
        raise ValueError('empty range')
    common = set(value_levels.get(values[0], ()))
    for value in values[1:]:
        common.intersection_update(value_levels.get(value, ()))
    jointly = common & source_levels
    best = max((sum(level in value_levels.get(value, ()) for value in values)
                for level in source_levels), default=0)
    return len(common), len(source_levels), len(jointly), best


def bucket(value):
    return 'none' if value == 0 else 'one' if value == 1 else 'multiple'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('rfl', type=Path)
    parser.add_argument('--overlay-hypothesis', action='store_true')
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
    inventory = Counter(inventory_key(list(PurePosixPath(item['path']).parts), args.overlay_hypothesis)
                        for item in items)
    value_levels, source_levels = {}, {}
    stats = Counter()
    level_index = 0
    for item in items:
        if Path(item['path']).suffix.lower() != '.lvl':
            continue
        data = read_verified(root, item)
        _, entries = selected(data)
        for value in {int(entry['Prefix dwords'].split()[0], 16) for entry in entries}:
            value_levels.setdefault(value, set()).add(level_index)
        _, directory = level_records(data)[(0, 0, 0)]
        for _, raw in directory_entries(directory):
            key = candidate_key(item['path'], raw, args.overlay_hypothesis)
            stats['directory_entries'] += 1
            if key is None:
                stats['directory_unusable'] += 1
            else:
                stats['directory_' + bucket(inventory[key]) + '_inventory_match'] += 1
                source_levels.setdefault(key, set()).add(level_index)
        level_index += 1
    if not level_index:
        raise ValueError('no levels')
    sources_with_ranges = set()
    sources_nonjoint = set()
    for item in items:
        data = read_verified(root, item)
        path_key = inventory_key(list(PurePosixPath(item['path']).parts), args.overlay_hypothesis)
        for values in ranges(data, metadata):
            common, directory, joined, best = classify(values, value_levels, source_levels.get(path_key, set()))
            stats['ranges'] += 1
            sources_with_ranges.add(path_key)
            stats['numeric_' + bucket(common)] += 1
            stats['source_' + bucket(directory)] += 1
            stats['joint_' + bucket(joined)] += 1
            if directory and not joined:
                sources_nonjoint.add(path_key)
                stats['nonjoint_partial'] += 0 < best < len(values)
                stats['nonjoint_no_value_match'] += best == 0
            stats['range_values'] += len(values)
            stats['source_inventory_' + bucket(inventory[path_key])] += 1
    stats['sources_with_ranges'] = len(sources_with_ranges)
    stats['sources_nonjoint'] = len(sources_nonjoint)
    print(json.dumps({'files': len(items), 'levels': level_index, 'overlay_hypothesis': args.overlay_hypothesis,
                      'counts': dict(sorted(stats.items()))}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
