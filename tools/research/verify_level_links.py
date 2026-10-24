#!/usr/bin/env python3
"""Compare level inner-value diagnostics against independent bounded decoding."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified


def decode(payload):
    pos = 0

    def take(size):
        nonlocal pos
        if size < 0 or size > len(payload) - pos:
            raise ValueError('truncated level prefix')
        part = payload[pos:pos + size]
        pos += size
        return part

    def dword():
        return struct.unpack('<I', take(4))[0]

    entries = dword()
    if entries > 4096:
        raise ValueError('level entry limit')
    totals = {'Entries': entries, 'Inner values': 0, 'Nonzero high halves': 0,
              'Raw values outside entry count': 0, 'Low halves outside entry count': 0,
              'Low halves equal entry index': 0}
    for entry in range(entries):
        take(28)
        name_length = struct.unpack('<H', take(2))[0]
        take(name_length)
        take(24)
        count = dword()
        if count > 4096:
            raise ValueError('level inner limit')
        values = struct.iter_unpack('<I', take(count * 4))
        for (value,) in values:
            low = value & 0xffff
            totals['Inner values'] += 1
            totals['Nonzero high halves'] += bool(value >> 16)
            totals['Raw values outside entry count'] += value >= entries
            totals['Low halves outside entry count'] += low >= entries
            totals['Low halves equal entry index'] += low == entry
    return totals


def selected(data):
    end, entries = table(data)
    matches = [(i, start, length) for i, (a, b, c, start, length) in enumerate(entries)
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
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    inspector = args.inspector.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    files = [entry for entry in entries if Path(entry['path']).suffix.lower() == '.lvl']
    if not files:
        raise ValueError('no level files')
    totals = {}
    with tempfile.TemporaryDirectory(prefix='dragonrider-level-links-') as directory:
        snapshot = Path(directory) / 'verified-level.lvl'
        for entry in files:
            if entry['status'] != 'examined':
                raise ValueError('inventory contains unexamined level')
            data = read_verified(root, entry)
            index, expected = selected(data)
            snapshot.write_bytes(data)
            result = subprocess.run([str(inspector), '--level-links', str(index), str(snapshot)],
                                    capture_output=True, text=True, check=True)
            parsed = dict(line.split(': ', 1) for line in result.stdout.splitlines() if ': ' in line)
            if any(parsed.get(key) != str(value) for key, value in expected.items()):
                raise ValueError('inspector does not match independent level-prefix decoding')
            for key, value in expected.items():
                totals[key] = totals.get(key, 0) + value
    print(json.dumps({'files': len(files), 'totals': totals}, indent=2))


if __name__ == '__main__':
    main()
