#!/usr/bin/env python3
"""Compare selected raw level prefixes against an independent bounded decoder."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import zlib

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified


def decode(payload):
    position = 0

    def take(size):
        nonlocal position
        if size < 0 or size > len(payload) - position:
            raise ValueError('truncated level prefix')
        data = payload[position:position + size]
        position += size
        return data

    def word():
        return struct.unpack('<I', take(4))[0]

    count = word()
    if count > 4096:
        raise ValueError('entry limit')
    result = []
    for index in range(count):
        before = struct.unpack('<7I', take(28))
        size = struct.unpack('<H', take(2))[0]
        byte_sequence = take(size)
        after = struct.unpack('<6I', take(24))
        inner = word()
        if inner > 4096:
            raise ValueError('inner count limit')
        take(inner * 4)
        result.append({'Level entry': str(index),
                       'Prefix dwords': ' '.join(f'{value:08x}' for value in before),
                       'Byte sequence length': str(size),
                       'Byte sequence CRC32': f'{zlib.crc32(byte_sequence):08x}',
                       'Following dwords': ' '.join(f'{value:08x}' for value in after),
                       'Inner count': str(inner)})
    return result


def selected(data):
    end, records = table(data)
    matches = [(index, start, length) for index, (a, b, c, start, length) in enumerate(records)
               if (a, b, c) == (1, 0, 0)]
    if len(matches) != 1:
        raise ValueError('expected one level block record')
    index, start, length = matches[0]
    if start < 12 or start > end or length > end - start:
        raise ValueError('invalid level record range')
    return index, decode(data[start:start + length])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('inspector', type=Path)
    parser.add_argument('--probe', type=Path, help='test-only callback probe')
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    inspector = args.inspector.resolve(strict=True)
    probe = args.probe.resolve(strict=True) if args.probe else None
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    files = [entry for entry in entries if Path(entry['path']).suffix.lower() == '.lvl']
    if not files:
        raise ValueError('no level files')
    entry_total = comparisons = lookup_comparisons = probe_comparisons = 0
    for entry in files:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined level')
        data = read_verified(root, entry)
        record, expected = selected(data)
        entry_total += len(expected)
        if probe:
            _, records = table(data)
            _, _, _, start, length = records[record]
            payload = data[start:start + length]
            if len(payload) > 32 * 1024 * 1024:
                raise ValueError('probe payload exceeds limit')
            actual = subprocess.run([str(probe)], input=struct.pack('<I', len(payload)) + payload,
                                    capture_output=True, check=True).stdout.decode('ascii').splitlines()
            lines = [f"{row['Level entry']}: {row['Prefix dwords']}:{row['Byte sequence length']}:"
                     f"{row['Byte sequence CRC32']}: {row['Following dwords']}:{row['Inner count']}"
                     for row in expected]
            if actual != lines:
                raise ValueError('probe does not match independent entry-prefix decoding')
            probe_comparisons += len(expected)
        selections = sorted({0, len(expected) // 2, len(expected) - 1} if expected else set())
        first_words = [int(row['Prefix dwords'].split()[0], 16) for row in expected]
        for index in selections:
            # The inspector reopens the verified path; concurrent changes are not excluded.
            result = subprocess.run([str(inspector), '--level-entry', str(record), str(index),
                                     str(root / entry['path'])], capture_output=True, text=True, check=True)
            actual = dict(line.split(': ', 1) for line in result.stdout.splitlines() if ': ' in line)
            if any(actual.get(key) != value for key, value in expected[index].items()):
                raise ValueError('inspector does not match independent entry-prefix decoding')
            comparisons += 1
        keys = {first_words[index] for index in selections}
        missing = 0
        while missing in keys or missing in first_words:
            missing += 1
        keys.add(missing)
        for value in sorted(keys):
            indices = [index for index, first in enumerate(first_words) if first == value]
            expected_lookup = {'Matching entries': str(len(indices)),
                               'First matching entry': str(indices[0]) if indices else 'none'}
            result = subprocess.run([str(inspector), '--level-entry-find', str(record), str(value),
                                     str(root / entry['path'])], capture_output=True, text=True, check=True)
            actual = dict(line.split(': ', 1) for line in result.stdout.splitlines() if ': ' in line)
            if any(actual.get(key) != result for key, result in expected_lookup.items()):
                raise ValueError('inspector does not match independent first-word lookup')
            lookup_comparisons += 1
    print(json.dumps({'files': len(files), 'entries_decoded': entry_total,
                      'selected_entries_compared': comparisons,
                      'lookup_comparisons': lookup_comparisons,
                      'probe_entries_compared': probe_comparisons}, indent=2))


if __name__ == '__main__':
    main()
