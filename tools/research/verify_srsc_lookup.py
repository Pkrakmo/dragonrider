#!/usr/bin/env python3
"""Independently compare a C++ lookup probe with hash-checked SRSC tables."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from measure_srsc_prefix_selector import read_verified
from measure_0102_model_candidates import table


def expected_lines(entries):
    ordered = sorted(range(len(entries)), key=lambda i: entries[i][1])
    pairs = {}
    triples = {}
    sorted_pairs = {}
    sorted_triples = {}
    for i, entry in enumerate(entries):
        key = entry[:3]
        pairs.setdefault(key[:2], i)
        triples.setdefault(key, i)
    for i, source in enumerate(ordered):
        key = entries[source][:3]
        sorted_pairs.setdefault(key[:2], (i, source))
        sorted_triples.setdefault(key, (i, source))
    for source in ordered:
        key = entries[source][:3]
        pair = pairs[key[:2]]
        triple = triples[key]
        yield (source, pair, pair, triple, triple,
               *sorted_pairs[key[:2]], *sorted_triples[key])


def verify(probe, data):
    offset, entries = table(data)
    count = len(entries)
    result = subprocess.run([str(probe)], input=struct.pack('<H', count) + data[offset:offset + count * 14],
                            capture_output=True, check=True)
    lines = result.stdout.splitlines()
    if len(lines) != count:
        raise ValueError('lookup probe returned an unexpected line count')
    for actual, expected in zip(lines, expected_lines(entries)):
        if tuple(map(int, actual.split())) != expected:
            raise ValueError('lookup probe disagrees with independent ordering or first-match model')
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('probe', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    probe = args.probe.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not entries:
        raise ValueError('empty inventory')
    records = 0
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        records += verify(probe, read_verified(root, entry))
    print(f'files={len(entries)} records={records} pair_comparisons={2 * records} triple_comparisons={2 * records}')


if __name__ == '__main__':
    main()
