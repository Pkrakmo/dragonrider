#!/usr/bin/env python3
"""Measure aggregate raw tag/context equalities in selector-0x20 frames.

The comparisons are strictly numeric equalities against fields which the
bounded object-framing reader already exposes.  They neither decode bodies nor
assign meanings to tags, fields, counts, or their possible runtime use.  The
CLI opens only hash-verified inventory entries and emits no paths, tag values,
payload bytes, or hashes.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

from measure_level_entry_caller import selected_payload
from measure_level_objects import decode
from measure_srsc_prefix_selector import read_verified


def measure(payload):
    """Return aggregate equality counts for one already-selected payload."""
    objects, trailing = decode(payload)
    result = Counter(objects=len(objects), trailing_bytes=trailing)
    for row in objects:
        fields = row[7]
        first_word = row[8]
        following = row[9]
        references = row[2]
        first_count, second_count = row[4:6]
        frames = row[14]
        result['objects_with_frames'] += bool(frames)
        result['objects_without_frames'] += not frames
        result['frames'] += len(frames)
        if not frames:
            continue

        # These are numeric observations only.  In particular, the u16 values
        # are compared as their raw, zero-extended integer values; no type or
        # identifier interpretation is implied.
        context = {
            **{f'field_{index}': value for index, value in enumerate(fields)},
            'first_word': first_word,
            **{f'following_{index}': value for index, value in enumerate(following)},
            'reference_count': len(references),
            'first_count': first_count,
            'second_count': second_count,
            'frame_count': len(frames),
        }
        object_matches = Counter()
        for position, (tag, _body) in enumerate(frames):
            matched = 0
            for name, value in context.items():
                equal = tag == value
                result[f'tag_equals_{name}'] += equal
                matched += equal
            result['tag_equals_frame_position'] += tag == position
            matched += tag == position
            result['tags_matching_any_context_value'] += bool(matched)
            result['tags_matching_multiple_context_values'] += matched > 1
            object_matches['any'] += bool(matched)
            object_matches['multiple'] += matched > 1
        result['objects_with_any_tag_context_match'] += bool(object_matches['any'])
        result['objects_with_multiple_tag_context_matches'] += bool(object_matches['multiple'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    levels = [entry for entry in entries if Path(entry['path']).suffix.lower() == '.lvl']
    if not levels or any(entry.get('status') != 'examined' for entry in levels):
        raise ValueError('empty or incomplete level inventory')
    totals = Counter()
    for entry in levels:
        totals.update(measure(selected_payload(read_verified(root, entry))))
    print(json.dumps({'level_files': len(levels), 'counts': dict(sorted(totals.items()))},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
