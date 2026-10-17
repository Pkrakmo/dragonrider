#!/usr/bin/env python3
"""Measure traced grid metadata and compare selected entry summaries with the inspector."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import zlib

from measure_level_blocks import measure
from measure_level_source_ids import records


def signed32(value):
    return value if value < 0x80000000 else value - 0x100000000


def scan(payload):
    entries = {}
    def add(entry, prefix, index, first, second):
        if entry not in entries:
            entries[entry] = {'width': prefix[1], 'height': prefix[2],
                              'origin_first': signed32(prefix[4]), 'origin_second': signed32(prefix[5]),
                              'base': prefix[6], 'count': 0, 'bit8': 0, 'min': None, 'max': None}
        result = entries[entry]
        value = 2 * second - 65536
        result['count'] += 1
        result['bit8'] += bool(first & 0x100)
        result['min'] = value if result['min'] is None else min(result['min'], value)
        result['max'] = value if result['max'] is None else max(result['max'], value)
    summary = measure(payload, on_grid=add)
    if len(entries) != summary[1]:
        raise ValueError('missing grid entry')
    return entries


def output(entry, result):
    first = result['origin_first'] * 2048
    second = result['origin_second'] * 2048
    return (f'Grid entry: {entry}\nDimensions: {result["width"]}x{result["height"]}\n'
            f'Origin indices: {result["origin_first"]},{result["origin_second"]}\n'
            f'Base value bits: 0x{result["base"]:08x}\n'
            f'Nominal first coordinate: {first}..{first + result["width"] * 2048}\n'
            f'Nominal second coordinate: {second}..{second + result["height"] * 2048}\n'
            f'Grid points: {result["count"]}\nFirst word bit 8: {result["bit8"]}\n'
            f'Transformed word range: {result["min"]}..{result["max"]}\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--inspector', type=Path)
    args = parser.parse_args()
    files = [item for item in json.loads(args.inventory.read_text())['files']
             if Path(item['path']).suffix.lower() == '.lvl' and 'candidate_table' in item]
    if not files:
        parser.error('inventory contains no level candidates')
    totals = Counter()
    ranges = [None, None, None, None]
    failures = []
    for item in files:
        try:
            path = args.root / item['path']
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('inventory hash mismatch')
            index, payload = records(data)[(1, 0, 0)]
            entries = scan(payload)
            if args.inspector and entries:
                selected = sorted({0, len(entries) // 2, len(entries) - 1})
                for entry in selected:
                    process = subprocess.run([str(args.inspector), '--level-grid', str(index), str(entry), str(path)],
                                             capture_output=True, text=True)
                    if process.returncode != 0 or output(entry, entries[entry]) not in process.stdout:
                        raise ValueError('inspector grid mismatch: ' + process.stderr.strip())
                    totals['inspector_entries'] += 1
            for result in entries.values():
                totals['entries'] += 1
                totals['points'] += result['count']
                totals['bit8'] += result['bit8']
                totals['nonfinite_base_bits'] += (result['base'] & 0x7f800000) == 0x7f800000
                extents = (result['origin_first'] * 2048,
                           (result['origin_first'] + result['width']) * 2048,
                           result['origin_second'] * 2048,
                           (result['origin_second'] + result['height']) * 2048)
                for i, value in enumerate(extents):
                    if ranges[i] is None:
                        ranges[i] = value
                    else:
                        ranges[i] = min(ranges[i], value) if i % 2 == 0 else max(ranges[i], value)
            totals['files'] += 1
        except (OSError, ValueError, struct.error, zlib.error) as error:
            failures.append(f"{item['path']}: {error}")
    print(f'Levels: {totals["files"]}/{len(files)}; entries={totals["entries"]}; grid points={totals["points"]}; '
          f'bit8={totals["bit8"]}; nonfinite base bit patterns={totals["nonfinite_base_bits"]}; '
          f'inspector comparisons={totals["inspector_entries"]}')
    print(f'Nominal coordinate extents: first={ranges[0]}..{ranges[1]}, second={ranges[2]}..{ranges[3]}')
    if failures:
        print(*failures, sep='\n')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
