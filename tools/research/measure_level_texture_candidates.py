#!/usr/bin/env python3
"""Compare level cell selectors with candidate inventory files; do not follow embedded paths."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import struct
import subprocess
import zlib

from measure_level_blocks import measure
from measure_level_source_ids import records


def inventory_key(parts, overlay=False):
    if overlay:
        # Hypothesis: installer groups share a destination, and extraction
        # converted spaces in directory names to underscores. Never open keys.
        if len(parts) < 2:
            return None
        parts = [part.replace('_', ' ') for part in parts[1:-1]] + [parts[-1]]
    return '/'.join(parts).lower()


def candidate_key(level_path, name, overlay=False):
    """Conservative lexical inventory key, not Windows path resolution."""
    if name.endswith(b'\0') and b'\0' not in name[:-1]:
        name = name[:-1]
    try:
        name = name.decode('ascii')
    except UnicodeDecodeError:
        return None
    if not name or len(name) >= 256 or any(ord(c) < 32 or ord(c) >= 127 for c in name):
        return None
    path = PureWindowsPath(name)
    if path.drive or path.root or ':' in name:
        return None
    level = PurePosixPath(level_path)
    if level.is_absolute() or '..' in level.parts or '\\' in level_path:
        return None
    parts = list(level.parent.parts)
    for part in path.parts:
        if part == '..':
            if not parts:
                return None
            parts.pop()
        elif part != '.':
            parts.append(part)
    if not parts or parts[-1] in ('.', '..'):
        return None
    if '.' not in parts[-1]:
        parts[-1] += '.txd'
    return inventory_key(parts, overlay)


def directory_entries(payload):
    pos = 0
    def take(size):
        nonlocal pos
        if size > len(payload) - pos:
            raise ValueError('truncated directory')
        result = payload[pos:pos + size]
        pos += size
        return result
    def u16():
        return struct.unpack('<H', take(2))[0]
    def u32():
        return struct.unpack('<I', take(4))[0]
    take(u16())
    u32(); u32()
    count = u32()
    if count > 4096:
        raise ValueError('directory count exceeds limit')
    return [(u32(), take(u16())) for _ in range(count)]


def texture_selectors(data):
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('candidate is not SRSC')
    version, table, count = struct.unpack_from('<HIH', data, 4)
    if version != 0x100 or not count or table > len(data) or count * 14 > len(data) - table:
        raise ValueError('bad candidate table')
    selectors = Counter()
    for first, second, _third, offset, length in struct.iter_unpack('<HHHII', data[table:table + count * 14]):
        if offset > len(data) or length > len(data) - offset:
            raise ValueError('bad candidate record range')
        if first == 0x40:
            selectors[second] += 1
    return selectors


def verified(root, item):
    relative = PurePosixPath(item['path'])
    if relative.is_absolute() or '..' in relative.parts or '\\' in item['path']:
        raise ValueError('unsafe inventory path')
    path = (root / Path(*relative.parts)).resolve(strict=True)
    if not path.is_relative_to(root):
        raise ValueError('inventory path escapes root')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('inventory hash mismatch')
    return path, data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--inspector', type=Path)
    parser.add_argument('--overlay-hypothesis', action='store_true',
                        help='compare group-stripped, space/underscore-normalized directory keys')
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    items = json.loads(args.inventory.read_text())['files']
    inventory = defaultdict(list)
    for item in items:
        item_path = PurePosixPath(item['path'])
        if item_path.is_absolute() or '..' in item_path.parts or '\\' in item['path']:
            raise ValueError('unsafe inventory path')
        key = inventory_key(list(item_path.parts), args.overlay_hypothesis)
        if key is not None:
            inventory[key].append(item)
    levels = [item for item in items if Path(item['path']).suffix.lower() == '.lvl'
              and 'candidate_table' in item]
    if not levels:
        parser.error('inventory contains no level candidates')
    totals, entries, pairs, files = Counter(), Counter(), Counter(), Counter()
    candidate_cache = {}
    failures = []
    for item in levels:
        try:
            level_path, data = verified(root, item)
            selected = records(data)
            block_index, blocks = selected[(1, 0, 0)]
            names = defaultdict(list)
            for source, name in directory_entries(selected[(0, 0, 0)][1]):
                names[source].append(name)
                key = candidate_key(item['path'], name, args.overlay_hypothesis)
                entries['total'] += 1
                entries['unsafe_name' if key is None else ('unique_file' if len(inventory[key]) == 1
                        else 'missing_file' if not inventory[key] else 'ambiguous_file')] += 1
            refs = Counter()
            negative = [0]
            def add(first, second):
                for value in (first, second):
                    if value < 0:
                        negative[0] += 1
                    else:
                        refs[value] += 1
            measure(blocks, add)
            per_source = defaultdict(Counter)
            for value, count in refs.items():
                per_source[value >> 16][value & 0xffff] += count
            for source, low_values in per_source.items():
                occurrences = sum(low_values.values())
                source_names = names[source]
                if source == 0 or len(source_names) != 1:
                    kind = 'unmapped_source'
                else:
                    key = candidate_key(item['path'], source_names[0], args.overlay_hypothesis)
                    if key is None:
                        kind = 'unsafe_name'
                    elif not inventory[key]:
                        kind = 'missing_file'
                    elif len(inventory[key]) != 1:
                        kind = 'ambiguous_file'
                    else:
                        kind = 'candidate_file'
                pairs[kind] += 1
                if kind != 'candidate_file':
                    totals[kind] += occurrences
                    continue
                target = inventory[key][0]
                if key not in candidate_cache:
                    texture_path, texture_data = verified(root, target)
                    candidate_cache[key] = (texture_path, texture_selectors(texture_data))
                texture_path, selectors = candidate_cache[key]
                result = Counter()
                for low, count in low_values.items():
                    result['unique' if selectors[low] == 1 else 'multiple' if selectors[low] > 1 else 'missing_selector'] += count
                if args.inspector:
                    process = subprocess.run([str(args.inspector), '--level-texture-ids', str(block_index),
                                              str(source), str(level_path), str(texture_path)],
                                             capture_output=True, text=True)
                    expected = (f'Blocks record: {block_index}\nSelected source ID: {source}\n'
                                f'Negative dword occurrences: {negative[0]}\n'
                                f'Other source occurrences: {sum(refs.values()) - occurrences}\n'
                                f'Unique selector matches: {result["unique"]}\n'
                                f'Multiple selector matches: {result["multiple"]}\n'
                                f'Missing selector matches: {result["missing_selector"]}\n')
                    if process.returncode != 0 or expected not in process.stdout:
                        raise ValueError('inspector comparison failed: ' + process.stderr.strip())
                totals.update(result)
                pairs['with_missing_selector'] += bool(result['missing_selector'])
                pairs['with_multiple_selector'] += bool(result['multiple'])
            totals['negative'] += negative[0]
            files['levels'] += 1
        except (OSError, ValueError, struct.error, zlib.error) as error:
            failures.append(f"{item['path']}: {error}")
    print('Key policy: ' + ('hypothetical overlay' if args.overlay_hypothesis else 'exact extracted layout'))
    print(f'Levels: {files["levels"]}/{len(levels)}; directory entries: {dict(sorted(entries.items()))}')
    print('Referenced level/source pairs: ' + str(dict(sorted(pairs.items()))))
    print('Cell dword occurrences: ' + str(dict(sorted(totals.items()))))
    print(f'Unique candidate files hash-verified: {len(candidate_cache)}')
    if failures:
        print(*failures, sep='\n')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
