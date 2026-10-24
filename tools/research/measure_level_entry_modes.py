#!/usr/bin/env python3
"""Measure level-entry discriminator and post-name flag on hashed US levels."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from measure_0102_model_candidates import table
from measure_level_0001 import load_inventory, safe_inventory_path


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def level_inventory_entries(entries):
    """Select only well-formed level inventory entries before opening files."""
    selected = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('invalid inventory entry')
        path = entry.get('path')
        if not isinstance(path, str):
            raise ValueError('invalid inventory path')
        if Path(path).suffix.lower() != '.lvl':
            continue
        expected_hash = entry.get('sha256')
        if not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash):
            raise ValueError('invalid inventory hash')
        selected.append(entry)
    if not selected:
        raise ValueError('inventory contains no SRSC level candidates')
    return selected


def decode(payload):
    cursor = 0

    def take(size):
        nonlocal cursor
        if size < 0 or size > len(payload) - cursor:
            raise ValueError('truncated level prefix')
        result = payload[cursor:cursor + size]
        cursor += size
        return result

    def dword():
        return struct.unpack('<I', take(4))[0]

    count = dword()
    if count > 4096:
        raise ValueError('outer entry count exceeds measurement limit')
    entries = []
    for _ in range(count):
        first_seven = struct.unpack('<7I', take(28))
        name_length = struct.unpack('<H', take(2))[0]
        take(name_length)
        following_six = struct.unpack('<6I', take(24))
        inner_count = dword()
        if inner_count > 4096:
            raise ValueError('inner entry count exceeds measurement limit')
        take(inner_count * 4)
        entries.append((first_seven[0], first_seven[1], first_seven[2],
                        first_seven[3], following_six[0]))
    return entries, len(payload) - cursor


def measure(data):
    table_offset, records = table(data)
    matches = [record for record in records if record[:3] == (1, 0, 0)]
    if len(matches) != 1:
        raise ValueError('expected exactly one (1,0,0) record')
    _, _, _, start, length = matches[0]
    if start < 12 or start > len(data) or length > len(data) - start:
        raise ValueError('level payload outside file')
    table_end = table_offset + len(records) * 14
    if start < table_end and table_offset < start + length:
        raise ValueError('level payload overlaps SRSC table')
    return decode(memoryview(data)[start:start + length])


def read_verified_level(root, entry):
    """Read one inventory-selected level only after path, size, and hash checks."""
    if not isinstance(entry, dict) or entry.get('status') != 'examined':
        raise ValueError('inventory contains unexamined files')
    expected_size = entry.get('file_size')
    expected_hash = entry.get('sha256')
    if type(expected_size) is not int or expected_size < 0:
        raise ValueError('invalid inventory file size')
    if not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash):
        raise ValueError('invalid inventory hash')
    path = safe_inventory_path(root, entry.get('path'))
    data = path.read_bytes()
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError('inventory size or hash mismatch')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('root is not a directory')
    files = level_inventory_entries(load_inventory(args.inventory))
    discriminators = Counter()
    flag_bits = Counter()
    cross = Counter()
    entries_total = trailing_total = 0
    for item in files:
        entries, trailing = measure(read_verified_level(root, item))
        entries_total += len(entries)
        trailing_total += trailing
        for _, _, _, discriminator, flags in entries:
            discriminators[discriminator] += 1
            flag_bits[flags & 0xffff] += 1
            cross[(discriminator == 2, bool(flags & 2))] += 1
    print(json.dumps({
        'files_examined': len(files), 'entries': entries_total,
        'unparsed_trailing_bytes': trailing_total,
        'discriminator_distinct_values': len(discriminators),
        'discriminator_most_common': discriminators.most_common(20),
        'post_name_flags_distinct_values': len(flag_bits),
        'post_name_flags_most_common': flag_bits.most_common(20),
        'cross_discriminator_eq_2_and_flag_bit_1': {
            f'discriminator_eq_2={is_two},flag_bit_1={flag}': count
            for (is_two, flag), count in sorted(cross.items())}}, indent=2))


if __name__ == '__main__':
    main()
