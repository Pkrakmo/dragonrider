#!/usr/bin/env python3
"""Compare inspector record output with a private installed-tree manifest."""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inspector', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    items = [item for item in json.loads(args.manifest.read_text())['files'] if 'candidate_table' in item]
    if not items:
        parser.error('manifest contains no candidate tables')
    failures = []
    for item in items:
        path = args.root / item['path']
        table = item['candidate_table']
        with path.open('rb') as stream:
            stream.seek(table['offset'])
            data = stream.read(table['count'] * 14)
        if len(data) != table['count'] * 14:
            failures.append(item['path'])
            continue
        expected = list(struct.iter_unpack('<HHHII', data))
        result = subprocess.run([str(args.inspector), '--records', str(path)], capture_output=True, text=True)
        matches = re.findall(r'^Record \d+: selectors=(\d+),(\d+),(\d+) offset=(\d+) length=(\d+)$', result.stdout, re.M)
        observed = [tuple(map(int, row)) for row in matches]
        if result.returncode != 0 or observed != expected[:50]:
            failures.append(item['path'])
    print(f'Private SRSC record inspections: {len(items) - len(failures)}/{len(items)} matched')
    if failures:
        print(*failures, sep='\n')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
