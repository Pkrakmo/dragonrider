#!/usr/bin/env python3
"""Compare level frames directly with hypothetical same-source 0x0102 frames."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path, PurePosixPath
import struct

from measure_0102_model_candidates import table
from measure_level_0102_sources import candidate_key
from measure_level_entry_caller import selected_payload
from measure_level_objects import decode
from measure_level_source_ids import records as level_records
from measure_level_texture_candidates import directory_entries, inventory_key
from measure_srsc_prefix_selector import read_verified


def record_frames(data):
    end, records = table(data)
    result = defaultdict(list)
    for kind, second, _, start, length in records:
        if kind != 0x102:
            continue
        if start < 12 or start > end or length > end - start or length < 2:
            raise ValueError('invalid selected record')
        payload = memoryview(data)[start:start + length]
        pos = 2 + struct.unpack_from('<H', payload)[0]
        if pos > length or length - pos < 18:
            raise ValueError('short selected record')
        declared, count = struct.unpack_from('<II', payload, pos + 10)
        pos += 18
        if count > (length - pos) // 4:
            raise ValueError('array outside record')
        pos += 4 * count
        if declared > (length - pos) // 6:
            raise ValueError('frame headers outside record')
        frames = []
        for _ in range(declared):
            if length - pos < 6:
                raise ValueError('short frame header')
            tag, size = struct.unpack_from('<IH', payload, pos)
            pos += 6
            if size > length - pos:
                raise ValueError('short frame body')
            frames.append((tag, bytes(payload[pos:pos + size])))
            pos += size
        if pos != length:
            raise ValueError('trailing record bytes')
        result[second].append(frames)
    return result


def compare(words, frames, source):
    if len(words) != len(frames):
        raise ValueError('level frame count mismatch')
    result = Counter(objects_compared=1)
    for word, (tag, body) in zip(words, frames):
        result['frames'] += 1
        if word >= len(source):
            result['index_outside_source'] += 1
            continue
        expected_tag, expected_body = source[word]
        body = bytes(body)
        result['tags_equal'] += tag == expected_tag
        result['body_exact'] += body == expected_body
        result['body_equal_allow_terminal_nul'] += body.removesuffix(b'\0') == expected_body.removesuffix(b'\0')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--overlay-hypothesis', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    items = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not items or any(item['status'] != 'examined' for item in items):
        raise ValueError('empty or incomplete inventory')
    indexed, levels = defaultdict(list), []
    for item in items:
        data = read_verified(root, item)
        key = inventory_key(list(PurePosixPath(item['path']).parts), args.overlay_hypothesis)
        indexed[key].append(record_frames(data))
        if Path(item['path']).suffix.lower() == '.lvl':
            levels.append((item['path'], data))
    if not levels:
        raise ValueError('no levels')
    result = Counter()
    for path, data in levels:
        _, directory = level_records(data)[(0, 0, 0)]
        sources = defaultdict(list)
        for ident, raw in directory_entries(directory):
            sources[ident].append(candidate_key(path, raw, args.overlay_hypothesis))
        objects, _ = decode(selected_payload(data))
        for row in objects:
            if row[4] <= 0 or row[5] <= 0:
                continue
            result['objects_with_arrays'] += 1
            key = row[7][1]
            choices = sources.get(key >> 16, ())
            if len(choices) != 1 or choices[0] is None:
                result['source_missing_or_ambiguous'] += 1
                continue
            files = indexed.get(choices[0], ())
            if len(files) != 1:
                result['file_missing_or_ambiguous'] += 1
                continue
            matches = files[0].get(key & 0xffff, ())
            if len(matches) != 1:
                result['record_missing_or_ambiguous'] += 1
                continue
            result.update(compare(row[12], row[14], matches[0]))
    print(json.dumps({'files': len(items), 'levels': len(levels),
                      'overlay_hypothesis': args.overlay_hypothesis,
                      'counts': dict(sorted(result.items()))}, indent=2))


if __name__ == '__main__':
    main()
