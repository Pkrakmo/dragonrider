#!/usr/bin/env python3
"""Compare 0x0102 payload keys with IDs in same-path retail descriptors."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from verify_database_descriptors import decode
from measure_level_source_ids import records as level_records
from verify_level_directory import decode as decode_level_directory


def measure(data, ids, level_ids=None):
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('invalid SRSC header')
    version, table, count = struct.unpack_from('<HIH', data, 4)
    if version != 0x100 or not count or table < 12 or table + count * 14 > len(data):
        raise ValueError('invalid SRSC table')
    result = Counter({'missing_with_level': 0, 'missing_in_level': 0,
                      'zero_key_nonzero_low': 0, 'missing_key_nonzero_low': 0})
    missing_keys = set()
    gate_values = []
    for kind, second, third, start, length in struct.iter_unpack('<HHHII', data[table:table + count * 14]):
        if (kind, second, third) == (0x0402, 0, 0):
            if start < 12 or start + length > table:
                raise ValueError('invalid 0x0402 payload')
            gate_values.append(struct.unpack_from('<I', data, start)[0] if length >= 4 else None)
        if kind != 0x0102:
            continue
        if start < 12 or start + length > table or length < 2:
            raise ValueError('invalid 0x0102 payload')
        prefix = struct.unpack_from('<H', data, start)[0]
        if prefix + 12 > length:
            raise ValueError('short 0x0102 payload')
        key = struct.unpack_from('<H', data, start + prefix + 6)[0]
        low = struct.unpack_from('<H', data, start + prefix + 4)[0]
        result['records'] += 1
        if key == 0:
            result['zero_keys'] += 1
            result['zero_key_nonzero_low'] += low != 0
        else:
            result['nonzero_keys'] += 1
            matches = ids.count(key)
            result['nonzero_unique_matches'] += matches == 1
            result['nonzero_multiple_matches'] += matches > 1
            result['nonzero_missing'] += matches == 0
            if not matches:
                missing_keys.add(key)
                result['missing_key_nonzero_low'] += low != 0
                if level_ids is not None:
                    result['missing_with_level'] += 1
                    result['missing_in_level'] += key in level_ids
    result['distinct_missing_keys_per_file'] = len(missing_keys)
    result['files_with_missing_keys'] = bool(missing_keys)
    result['gate_tuple_count'] = len(gate_values)
    result['gate_missing'] = not gate_values
    result['gate_duplicate'] = len(gate_values) > 1
    if len(gate_values) == 1:
        result['gate_short'] = gate_values[0] is None
        result['gate_equals_0102'] = gate_values[0] == 0x0102
        result['gate_other'] = gate_values[0] is not None and gate_values[0] != 0x0102
    return result


def verified(root, entry):
    path = (root / entry['path']).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError('inventory path escapes root or is not a file')
    data = path.read_bytes()
    if len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('inventory length or hash mismatch')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    by_path = {entry['path'].lower(): entry for entry in entries}
    if len(by_path) != len(entries):
        raise ValueError('case-insensitive inventory path collision')
    totals = Counter()
    for item in entries:
        if not item['path'].lower().endswith('.odb'):
            continue
        descriptor = by_path.get((item['path'][:-4] + '.db').lower())
        if descriptor is None:
            totals['odb_without_descriptor'] += 1
            continue
        ids = [key for key, _ in decode(verified(root, descriptor))]
        level = by_path.get((item['path'][:-4] + '.lvl').lower())
        level_ids = None
        if level is not None:
            directory = level_records(verified(root, level))[(0, 0, 0)][1]
            level_ids = [key for key, _, _ in decode_level_directory(directory)[4]]
            totals['pairs_with_level'] += 1
        counts = measure(verified(root, item), ids, level_ids)
        totals['pairs'] += 1
        totals['pairs_with_0102'] += counts['records'] > 0
        totals.update(counts)
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
