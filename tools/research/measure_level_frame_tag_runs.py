#!/usr/bin/env python3
"""Measure aggregate selector-0x20 frame tag order without releasing values.

This is a bounded byte-structure measurement.  It reports only counts of
within-object tag sequence shapes and adjacent relationships; it assigns no
meaning to tags, bodies, object fields, producers, or runtime behavior.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

from measure_level_entry_caller import selected_payload
from measure_level_objects import decode
from measure_srsc_prefix_selector import read_verified


def measure(payload):
    """Return aggregate tag-run counts for one already-selected payload."""
    objects, trailing = decode(payload)
    result = Counter(objects=len(objects), trailing_bytes=trailing)
    for row in objects:
        frames = row[14]
        frame_count = len(frames)
        if frame_count == 0:
            result['objects_with_empty_frame_sequence'] += 1
            continue
        if frame_count == 1:
            result['objects_with_single_frame_sequence'] += 1
        else:
            result['objects_with_multiple_frame_sequence'] += 1

        tags = [tag for tag, _body in frames]
        duplicate_count = frame_count - len(set(tags))
        result['objects_with_duplicate_tags'] += duplicate_count > 0
        result['duplicate_tag_occurrences_within_object'] += duplicate_count
        result['frames'] += frame_count

        exact_adjacent_repeats = 0
        for (left_tag, left_body), (right_tag, right_body) in zip(frames, frames[1:]):
            if right_tag > left_tag:
                result['adjacent_tag_increase'] += 1
            elif right_tag == left_tag:
                result['adjacent_tag_equal'] += 1
            else:
                result['adjacent_tag_decrease'] += 1
            if left_tag == right_tag and left_body == right_body:
                exact_adjacent_repeats += 1
        result['exact_adjacent_tag_body_repeats'] += exact_adjacent_repeats
        result['objects_with_exact_adjacent_tag_body_repeat'] += exact_adjacent_repeats > 0
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
