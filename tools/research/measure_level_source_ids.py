#!/usr/bin/env python3
"""Compare cell dword high halves with explicit directory values, not runtime resolution."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib

from measure_level_blocks import measure
from verify_level_directory import decode


def counter_for(entries):
    """Return a streaming counter; counts are file occurrences, not runtime calls."""
    ids = Counter(value for value, _, _ in entries if 0 < value <= 0xffff)
    counts = Counter()
    def add(first, second):
        for value in (first, second):
            if value < 0:
                counts['negative'] += 1
            else:
                source = value >> 16
                if source == 0:
                    counts['zero_high'] += 1
                elif ids[source] == 1:
                    counts['unique_explicit'] += 1
                elif ids[source] > 1:
                    counts['duplicate_explicit'] += 1
                else:
                    counts['unmatched'] += 1
    return counts, add


def records(data):
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('bad header')
    version, offset, count = struct.unpack_from('<HIH', data, 4)
    if version != 0x100 or offset > len(data) or count * 14 > len(data) - offset:
        raise ValueError('bad table')
    found = {}
    for index, record in enumerate(struct.iter_unpack('<HHHII', data[offset:offset + count * 14])):
        selector = record[:3]
        if selector in ((0, 0, 0), (1, 0, 0)):
            if selector in found:
                raise ValueError('duplicate selected record')
            start, length = record[3:]
            if start > len(data) or length > len(data) - start:
                raise ValueError('bad selected record range')
            found[selector] = (index, data[start:start + length])
    if len(found) != 2:
        raise ValueError('missing selected record')
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--inspector', type=Path, help='compare the C++ inspector')
    args = parser.parse_args()
    files = [item for item in json.loads(args.inventory.read_text())['files']
             if Path(item['path']).suffix.lower() == '.lvl' and 'candidate_table' in item]
    if not files:
        parser.error('inventory contains no SRSC level candidates')
    total, entry_counts, file_counts = Counter(), Counter(), Counter()
    failures = []
    for item in files:
        try:
            data = (args.root / item['path']).read_bytes()
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('inventory hash mismatch')
            selected = records(data)
            directory_index, directory_payload = selected[(0, 0, 0)]
            blocks_index, blocks_payload = selected[(1, 0, 0)]
            entries = decode(directory_payload)[4]
            values = Counter(value for value, _, _ in entries)
            result, add = counter_for(entries)
            measure(blocks_payload, add)
            if args.inspector:
                process = subprocess.run([str(args.inspector), '--level-source-ids', str(directory_index),
                                          str(blocks_index), str(args.root / item['path'])],
                                         capture_output=True, text=True)
                expected = (f'Directory record: {directory_index}\nBlocks record: {blocks_index}\n'
                            f'Negative dword occurrences: {result["negative"]}\n'
                            f'Zero high-half occurrences: {result["zero_high"]}\n'
                            f'Unique explicit value matches: {result["unique_explicit"]}\n'
                            f'Duplicate explicit value matches: {result["duplicate_explicit"]}\n'
                            f'Unmatched high-half occurrences: {result["unmatched"]}\n')
                if process.returncode != 0 or expected not in process.stdout:
                    raise ValueError('inspector comparison failed: ' + process.stderr.strip())
            entry_counts['entries'] += len(entries)
            entry_counts['zero'] += values[0]
            entry_counts['over_16_bits'] += sum(n for v, n in values.items() if v > 0xffff)
            entry_counts['duplicate_nonzero_ids'] += sum(n for v, n in values.items() if v and n > 1)
            total.update(result)
            file_counts['matched'] += 1
            for kind in ('zero_high', 'unique_explicit', 'duplicate_explicit', 'unmatched'):
                file_counts[kind] += bool(result[kind])
        except (OSError, ValueError, struct.error, zlib.error) as error:
            failures.append(f"{item['path']}: {error}")
    print(f'Files: {file_counts["matched"]}/{len(files)}; entries: {dict(sorted(entry_counts.items()))}')
    print(f'Cell dword occurrences: {dict(sorted(total.items()))}')
    print('Files with occurrences: ' + str({k: file_counts[k] for k in
          ('zero_high', 'unique_explicit', 'duplicate_explicit', 'unmatched')}))
    if failures:
        print(*failures, sep='\n')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
