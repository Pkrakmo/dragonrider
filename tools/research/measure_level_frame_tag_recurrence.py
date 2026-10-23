#!/usr/bin/env python3
"""Measure aggregate within-object selector-0x20 frame-tag recurrence.

This bounded byte-structure measurement emits counts only.  A repeated tag is
compared with its nearest preceding occurrence in the same object; this is an
ordering convention, not an assertion about tag identity, frame bodies,
producers, or runtime behavior.  The output never includes tag values, frame
bodies, file paths, or hashes.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

from measure_level_entry_caller import selected_payload
from measure_level_objects import decode
from measure_srsc_prefix_selector import read_verified


def distance_bucket(distance):
    """Classify a positive index distance without retaining a tag value."""
    if distance == 1:
        return 'repeat_distance_adjacent'
    if distance <= 3:
        return 'repeat_distance_2_3'
    return 'repeat_distance_4_plus'


def measure(payload):
    """Return recurrence aggregates for one already-selected payload."""
    objects, trailing = decode(payload)
    result = Counter(objects=len(objects), trailing_bytes=trailing,
                     frames=0, first_tag_occurrences=0,
                     repeated_tag_occurrences=0, objects_with_repeated_tags=0,
                     repeat_distance_adjacent=0, repeat_distance_2_3=0,
                     repeat_distance_4_plus=0,
                     repeated_tag_same_body_length=0,
                     repeated_tag_different_body_length=0,
                     repeated_tag_exact_body_equal=0,
                     repeated_tag_exact_body_different=0)
    for row in objects:
        frames = row[14]
        result['frames'] += len(frames)
        previous = {}
        repeated_in_object = 0
        for index, (tag, body) in enumerate(frames):
            old = previous.get(tag)
            if old is None:
                result['first_tag_occurrences'] += 1
            else:
                previous_index, previous_body = old
                repeated_in_object += 1
                result['repeated_tag_occurrences'] += 1
                result[distance_bucket(index - previous_index)] += 1
                if len(body) == len(previous_body):
                    result['repeated_tag_same_body_length'] += 1
                else:
                    result['repeated_tag_different_body_length'] += 1
                if body == previous_body:
                    result['repeated_tag_exact_body_equal'] += 1
                else:
                    result['repeated_tag_exact_body_different'] += 1
            previous[tag] = (index, body)
        result['objects_with_repeated_tags'] += repeated_in_object > 0
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
