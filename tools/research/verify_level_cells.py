#!/usr/bin/env python3
"""Independently compare selected raw cells and candidate indices in hashed levels."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib

from measure_level_blocks import measure
from measure_level_source_ids import records


def expected(entry, prefix, index, cell, mode):
    width, height = prefix[1:3]
    row, column = divmod(index, width)
    a = row * (width + 1) + column
    b, d = a + 1, a + width + 1
    c = d + 1
    bit = cell[0] & 1
    if mode == 'normal':
        corners = (a, b, c, d)
        triangles = ((d, a, b), (b, c, d)) if not bit else ((c, d, a), (a, b, c))
    else:
        corners = (b, a, d, c)
        triangles = ((b, a, d), (d, c, b)) if not bit else ((a, d, c), (c, b, a))
    numbers = lambda values: ' '.join(map(str, values))
    summary = (f'Cell: entry={entry} column={column} row={row}\nDimensions: {width}x{height}\n'
            f'Flags: {cell[0]}\nRaw dwords: {cell[1] & 0xffffffff},{cell[2] & 0xffffffff}\n'
            f'Raw words: {numbers(cell[3:])}\nCandidate corners: {numbers(corners)}\n'
            f'Candidate first triangle: {numbers(triangles[0])}\nCandidate second triangle: {numbers(triangles[1])}\n')
    for i, grid in enumerate(corners):
        summary += f'Candidate corner {i}: grid={grid} word1={cell[3 + i]} transformed-word2={65535 - cell[7 + i]}\n'
    return summary


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
    failures = []
    for item in files:
        try:
            path = args.root / item['path']
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('inventory hash mismatch')
            record, payload = records(data)[(1, 0, 0)]
            selected = {}
            def add(entry, prefix, index, cell):
                totals[f'flags_{cell[0] & 3}'] += 1
                selected.setdefault(cell[0] & 3, (entry, prefix, index, cell))
            summary = measure(payload, on_cell_detail=add)
            totals['cells'] += summary[10]
            if args.inspector:
                for entry, prefix, index, cell in selected.values():
                    row, column = divmod(index, prefix[1])
                    for mode in ('normal', 'mode1'):
                        result = subprocess.run([str(args.inspector), '--level-cell', str(record), str(entry),
                                                 str(column), str(row), mode, str(path)], capture_output=True, text=True)
                        if result.returncode or result.stdout != expected(entry, prefix, index, cell, mode):
                            raise ValueError('inspector cell mismatch: ' + result.stderr.strip())
                        totals['comparisons'] += 1
            totals['files'] += 1
        except (OSError, ValueError, KeyError, struct.error, zlib.error) as error:
            failures.append(f"{item['path']}: {error}")
    print(f'Levels: {totals["files"]}/{len(files)}; cells={totals["cells"]}; '
          f'flags bits 1:0 counts={[totals[f"flags_{i}"] for i in range(4)]}; '
          f'inspector comparisons={totals["comparisons"]}')
    if failures:
        print(*failures, sep='\n')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
