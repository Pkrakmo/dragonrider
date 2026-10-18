#!/usr/bin/env python3
"""Compare raw 0x0102 units with candidate RFL scalar metadata."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import struct

from measure_0102_resource_table import RFL_SHA256, RESOURCE_OFFSET, RESOURCE_SIZE
from measure_srsc_prefix_selector import read_verified
from measure_0102_descriptor_keys import verified
from verify_database_descriptors import decode


def read_u32(data, pos):
    if pos < 0 or pos > len(data) or len(data) - pos < 4:
        raise ValueError('resource offset outside bounds')
    return struct.unpack_from('<I', data, pos)[0]


def resource_types(resource):
    count = read_u32(resource, 0)
    if count > (len(resource) - 4) // 32:
        raise ValueError('truncated resource entries')
    by_key = defaultdict(list)
    stats = Counter(entries=count)
    for i in range(count):
        base = 4 + i * 32
        key, expected = read_u32(resource, base), read_u32(resource, base + 20)
        groups, list_offset = read_u32(resource, base + 24), read_u32(resource, base + 28)
        start = base + list_offset
        if start > len(resource) or groups > (len(resource) - start) // 4:
            raise ValueError('group offset table outside resource')
        flags = []
        for j in range(groups):
            group = base + read_u32(resource, start + j * 4)
            amount, offset = read_u32(resource, group + 4), read_u32(resource, group + 8)
            params = group + offset
            if params > len(resource) or amount > (len(resource) - params) // 16:
                raise ValueError('group entries outside resource')
            flags.extend(read_u32(resource, params + k * 16 + 4) for k in range(amount))
        if len(flags) != expected:
            raise ValueError('group total differs from declared count')
        by_key[key].append(flags)
        stats['groups'] += groups
        stats['entries_in_groups'] += len(flags)
    return by_key, stats


def measure(data, by_key, dependency_ids=None):
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('invalid SRSC header')
    version, table, nrecords = struct.unpack_from('<HIH', data, 4)
    if version != 0x100 or not nrecords or table < 12 or nrecords * 14 > len(data) - table:
        raise ValueError('invalid SRSC table')
    result = Counter({key: 0 for key in ('records', 'missing_or_ambiguous_resource',
        'mismatched_count', 'array_shorter_than_declared', 'array_at_least_declared',
        'scalar_5', 'scalar_9', 'scalar_5_zero', 'scalar_9_zero',
        'scalar_5_high_zero', 'scalar_9_high_zero', 'scalar_5_high_nonzero',
        'scalar_9_high_nonzero', 'scalar_5_dependency_missing', 'scalar_5_dependency_unique',
        'scalar_5_dependency_multiple', 'flagged_entries', 'other_scalar_entries')})
    for kind, _, _, start, length in struct.iter_unpack('<HHHII', data[table:table + nrecords * 14]):
        if kind != 0x102:
            continue
        if start < 12 or start > table or length > table - start:
            raise ValueError('selected payload outside pre-table region')
        result['records'] += 1
        payload = memoryview(data)[start:start + length]
        if len(payload) < 2:
            raise ValueError('short prefix length')
        prefix = struct.unpack_from('<H', payload)[0]
        pos = 2 + prefix
        if pos > length or length - pos < 18:
            raise ValueError('short prefix or array header')
        key = struct.unpack_from('<H', payload, pos + 6)[0]
        declared, count = struct.unpack_from('<II', payload, pos + 10)
        pos += 18
        if count > (length - pos) // 4:
            raise ValueError('array outside payload')
        choices = by_key.get(key, ())
        if len(choices) != 1:
            result['missing_or_ambiguous_resource'] += 1
            continue
        flags = choices[0]
        if declared != len(flags):
            result['mismatched_count'] += 1
            continue
        if count < declared:
            result['array_shorter_than_declared'] += 1
            continue
        result['array_at_least_declared'] += 1
        for i, flag in enumerate(flags):
            if flag & 0x1000:
                result['flagged_entries'] += 1
                continue
            kind = flag & 0xfff
            if kind not in (5, 9):
                result['other_scalar_entries'] += 1
                continue
            value = struct.unpack_from('<I', payload, pos + i * 4)[0]
            name = f'scalar_{kind}'
            result[name] += 1
            result[name + '_zero'] += value == 0
            result[name + '_high_zero'] += value >> 16 == 0
            result[name + '_high_nonzero'] += value >> 16 != 0
            if kind == 5 and value >> 16 and dependency_ids is not None:
                matches = dependency_ids.count(value >> 16)
                result['scalar_5_dependency_missing'] += matches == 0
                result['scalar_5_dependency_unique'] += matches == 1
                result['scalar_5_dependency_multiple'] += matches > 1
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('rfl', type=Path)
    parser.add_argument('--descriptors', type=Path, help='private asset inventory for same-path DB comparison')
    args = parser.parse_args()
    binary = args.rfl.read_bytes()
    if hashlib.sha256(binary).hexdigest() != RFL_SHA256:
        raise ValueError('RFL SHA-256 does not match the pinned US retail image')
    if RESOURCE_OFFSET > len(binary) or RESOURCE_SIZE > len(binary) - RESOURCE_OFFSET:
        raise ValueError('resource range outside RFL image')
    by_key, stats = resource_types(binary[RESOURCE_OFFSET:RESOURCE_OFFSET + RESOURCE_SIZE])
    root = args.root.resolve(strict=True)
    inventory = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not inventory:
        raise ValueError('empty inventory')
    descriptors = {}
    if args.descriptors:
        descriptor_items = json.loads(args.descriptors.read_text(encoding='utf-8'))['files']
        descriptors = {entry['path'].lower(): entry for entry in descriptor_items}
        if len(descriptors) != len(descriptor_items):
            raise ValueError('case-insensitive descriptor inventory path collision')
    result = Counter()
    pairs = 0
    for item in inventory:
        if item['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        ids = None
        if args.descriptors and item['path'].lower().endswith('.odb'):
            descriptor = descriptors.get((item['path'][:-4] + '.db').lower())
            if descriptor is None:
                raise ValueError('missing same-path descriptor in inventory')
            ids = [ident for ident, _ in decode(verified(root, descriptor))]
            pairs += 1
        measured = measure(read_verified(root, item), by_key, ids)
        if args.descriptors and measured['records'] and ids is None:
            raise ValueError('selected SRSC records lack a same-path descriptor comparison')
        result.update(measured)
    print(json.dumps({'files_examined': len(inventory), 'resource': dict(sorted(stats.items())),
                      'descriptor_pairs': pairs, 'counts': dict(sorted(result.items()))}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
