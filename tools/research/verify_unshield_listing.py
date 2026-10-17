#!/usr/bin/env python3
"""Compare SRSC inventory paths and sizes with an unshield cabinet listing."""

import argparse
from collections import defaultdict
import json
from pathlib import Path, PureWindowsPath
import re
import subprocess


def listing_index(text):
    result = defaultdict(list)
    for line in text.splitlines():
        match = re.fullmatch(r'\s*(\d+)\s+(.+)', line)
        if not match:
            continue
        parts = PureWindowsPath(match.group(2)).parts
        if not parts:
            raise ValueError('empty listing path')
        key = '/'.join([part.replace(' ', '_') for part in parts[:-1]] + [parts[-1]]).lower()
        result[key].append(int(match.group(1)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cabinet', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    output = subprocess.run(['unshield', 'l', str(args.cabinet)], capture_output=True, text=True, check=True)
    listing = listing_index(output.stdout)
    entries = [item for item in json.loads(args.inventory.read_text())['files'] if 'candidate_table' in item]
    if not entries:
        parser.error('inventory contains no SRSC candidates')
    failures = [item['path'] for item in entries
                if listing[item['path'].lower()] != [item['size']]]
    print(f'SRSC inventory paths with a unique listing path and matching size: {len(entries) - len(failures)}/{len(entries)}')
    if failures:
        print(*failures, sep='\n')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
