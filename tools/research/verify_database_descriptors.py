#!/usr/bin/env python3
"""Independently compare bounded descriptor summaries with a private inventory."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zlib

from measure_level_source_ids import records
from measure_level_0001 import safe_inventory_path
from verify_level_directory import decode as decode_level_directory


def decode(data):
    lines = data.split(b'\r\n')
    if not lines or lines.pop() != b'' or len(lines) < 2 or lines[0] != b'version 1':
        raise ValueError('unrecognized descriptor header or line ending')
    count_match = re.fullmatch(rb'dependencies ([0-9]+)', lines[1])
    if not count_match or int(count_match[1]) != len(lines) - 2:
        raise ValueError('invalid dependency count')
    entries = []
    for line in lines[2:]:
        match = re.fullmatch(rb'([0-9]+) (.+)', line)
        if not match or int(match[1]) > 2147483647:
            raise ValueError('invalid dependency entry')
        entries.append((int(match[1]), match[2]))
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--inspector', required=True, type=Path)
    parser.add_argument('--compare-level-ids', action='store_true',
                        help='compare IDs with same-path level directories, without resolving names')
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    manifest = json.loads(args.inventory.read_text(encoding='utf-8'))
    candidates = [f for f in manifest['files'] if f['path'].lower().endswith('.db')]
    total = 0
    with tempfile.TemporaryDirectory(prefix='dragonrider-database-descriptor-') as directory:
        snapshot = Path(directory) / 'verified-descriptor.db'
        for item in candidates:
            path = safe_inventory_path(root, item['path'])
            data = path.read_bytes()
            if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('inventory length or hash mismatch')
            entries = decode(data)
            expected = f'Database descriptor version: 1\nDependencies: {len(entries)}\n'
            for index, (ident, name) in enumerate(entries):
                expected += f'Dependency {index}: id={ident} bytes={len(name)} crc32={zlib.crc32(name):08x}\n'
            snapshot.write_bytes(data)
            run = subprocess.run([str(args.inspector), '--database', str(snapshot)],
                                 capture_output=True, text=True, check=True)
            if run.stdout != expected:
                raise ValueError('inspector output differs from independently decoded data')
            total += len(entries)
    if not candidates:
        raise ValueError('no descriptors in inventory')
    print(f'matched {len(candidates)} hash-verified descriptors and {total} dependencies')
    if args.compare_level_ids:
        by_path = {f['path'].lower(): f for f in manifest['files']}
        if len(by_path) != len(manifest['files']):
            raise ValueError('case-insensitive inventory path collision')
        pairs = missing = db_total = level_total = db_in_level = level_in_db = equal_sets = 0
        for item in manifest['files']:
            if not item['path'].lower().endswith('.lvl'):
                continue
            descriptor = by_path.get((item['path'][:-4] + '.db').lower())
            if descriptor is None:
                missing += 1
                continue
            def verified(entry):
                path = (root / entry['path']).resolve(strict=True)
                if not path.is_relative_to(root) or not path.is_file():
                    raise ValueError('inventory path escapes root or is not a file')
                data = path.read_bytes()
                if len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
                    raise ValueError('inventory length or hash mismatch')
                return data
            db_ids = [ident for ident, _ in decode(verified(descriptor))]
            level_entries = decode_level_directory(records(verified(item))[(0, 0, 0)][1])[4]
            level_ids = [ident for ident, _, _ in level_entries]
            pairs += 1
            db_total += len(db_ids)
            level_total += len(level_ids)
            db_in_level += sum(ident in level_ids for ident in db_ids)
            level_in_db += sum(ident in db_ids for ident in level_ids)
            equal_sets += set(db_ids) == set(level_ids)
        print(f'level pairs={pairs}, no colocated descriptor={missing}, '
              f'descriptor IDs={db_total}, level IDs={level_total}, '
              f'descriptor IDs present in level={db_in_level}, '
              f'level IDs present in descriptor={level_in_db}, equal ID sets={equal_sets}')


if __name__ == '__main__':
    main()
