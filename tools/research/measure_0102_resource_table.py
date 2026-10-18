#!/usr/bin/env python3
"""Compare 0x0102 fields with a resource in the pinned US retail RFL."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import struct

from measure_srsc_prefix_selector import read_verified

# These offsets identify the ROC/OBJECTS language-0x0409 leaf in exactly this
# PE image, as independently listed by objdump. They are not a PE parser.
RFL_SHA256 = '9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3'
RESOURCE_OFFSET = 0x180fd8
RESOURCE_SIZE = 0x1198b


def resource_entries(resource):
    if len(resource) < 4:
        raise ValueError('truncated resource count')
    count = struct.unpack_from('<I', resource)[0]
    if count > (len(resource) - 4) // 32:
        raise ValueError('truncated resource table')
    result = defaultdict(list)
    for i in range(count):
        pos = 4 + i * 32
        ident = struct.unpack_from('<I', resource, pos)[0]
        value = struct.unpack_from('<I', resource, pos + 20)[0]
        result[ident].append(value)
    return result, count


def measure(data, entries):
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('invalid SRSC header')
    version, table, count = struct.unpack_from('<HIH', data, 4)
    if version != 0x100 or not count or table < 12 or count * 14 > len(data) - table:
        raise ValueError('invalid SRSC table')
    names = ('records', 'short_prefix', 'short_fields', 'missing_key', 'unique_key',
             'multiple_key', 'first_match_equal', 'first_match_different')
    result = Counter({key: 0 for key in names})
    for kind, _, _, start, length in struct.iter_unpack('<HHHII', data[table:table + count * 14]):
        if kind != 0x0102:
            continue
        if start < 12 or start > table or length > table - start:
            raise ValueError('selected payload outside pre-table region')
        result['records'] += 1
        if length < 2:
            result['short_prefix'] += 1
            continue
        prefix = struct.unpack_from('<H', data, start)[0]
        pos = start + 2 + prefix
        if prefix > length - 2 or length - 2 - prefix < 14:
            result['short_fields'] += 1
            continue
        key = struct.unpack_from('<H', data, pos + 6)[0]
        value = struct.unpack_from('<I', data, pos + 10)[0]
        matches = entries.get(key, ())
        if not matches:
            result['missing_key'] += 1
            continue
        result['unique_key'] += len(matches) == 1
        result['multiple_key'] += len(matches) > 1
        result['first_match_equal'] += value == matches[0]
        result['first_match_different'] += value != matches[0]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('rfl', type=Path)
    args = parser.parse_args()
    binary = args.rfl.read_bytes()
    if hashlib.sha256(binary).hexdigest() != RFL_SHA256:
        raise ValueError('RFL SHA-256 does not match the pinned US retail image')
    if RESOURCE_OFFSET > len(binary) or RESOURCE_SIZE > len(binary) - RESOURCE_OFFSET:
        raise ValueError('resource range outside RFL image')
    entries, resource_count = resource_entries(binary[RESOURCE_OFFSET:RESOURCE_OFFSET + RESOURCE_SIZE])
    root = args.root.resolve(strict=True)
    inventory = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not inventory:
        raise ValueError('empty inventory')
    totals = Counter()
    with_records = 0
    for item in inventory:
        if item['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        counts = measure(read_verified(root, item), entries)
        totals.update(counts)
        with_records += counts['records'] > 0
    print(json.dumps({'files_examined': len(inventory), 'files_with_records': with_records,
                      'resource_entries': resource_count, 'resource_unique_keys': len(entries),
                      'counts': dict(sorted(totals.items()))}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
