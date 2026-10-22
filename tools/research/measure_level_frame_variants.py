#!/usr/bin/env python3
"""Summarize bounded selector-0x20 frame shapes without emitting payloads.

This reads only hash-verified level snapshots.  The classifications describe
byte structure (not text encoding, field names, or runtime meaning); frame
bodies and their fingerprints never appear in the output.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from measure_level_entry_caller import selected_payload
from measure_level_objects import decode
from measure_srsc_prefix_selector import read_verified


def body_category(body):
    """Return a deliberately byte-level category for one already-bounded body."""
    if not body:
        return 'empty'
    printable_or_nul = all(byte == 0 or 0x20 <= byte <= 0x7e for byte in body)
    if not printable_or_nul:
        return 'other_bytes'
    nul_count = body.count(0)
    if nul_count == 0:
        return 'printable_no_nul'
    if nul_count == 1 and body[-1] == 0:
        return 'printable_terminal_nul'
    return 'printable_other_nul'


def length_bucket(length):
    if length == 0:
        return 'length_0'
    if length == 1:
        return 'length_1'
    if length <= 7:
        return 'length_2_7'
    if length <= 31:
        return 'length_8_31'
    if length <= 127:
        return 'length_32_127'
    return 'length_128_plus'


def measure(payload):
    """Measure structural frame variants in a single selector-0x20 payload."""
    objects, trailing = decode(payload)
    counts = Counter(objects=len(objects), trailing_bytes=trailing)
    body_occurrences = Counter()
    frame_occurrences = Counter()
    body_tags = defaultdict(set)
    tag_bodies = defaultdict(set)

    for row in objects:
        frames = row[14]
        counts['objects_with_frames'] += bool(frames)
        counts['objects_without_frames'] += not frames
        counts['declared_frame_count'] += len(frames)
        object_frames = Counter()
        for tag, body in frames:
            # Copying here is intentional: it permits exact aggregate reuse
            # counts without releasing a payload or a digest of one.
            body = bytes(body)
            signature = (tag, body)
            object_frames[signature] += 1
            body_occurrences[body] += 1
            frame_occurrences[signature] += 1
            body_tags[body].add(tag)
            tag_bodies[tag].add(body)
            counts['frames'] += 1
            counts['frame_header_bytes'] += 6
            counts['frame_body_bytes'] += len(body)
            counts[length_bucket(len(body))] += 1
            counts['tag_zero'] += tag == 0
            counts['tag_bit_1000_set'] += bool(tag & 0x1000)
            counts['tag_bits_outside_low_12_set'] += bool(tag & ~0xfff)
            counts['body_' + body_category(body)] += 1
        counts['objects_with_duplicate_exact_frames'] += any(n > 1 for n in object_frames.values())
        counts['duplicate_exact_frame_occurrences_within_object'] += sum(
            n - 1 for n in object_frames.values())

    counts['distinct_body_values'] = len(body_occurrences)
    counts['repeated_body_occurrences'] = counts['frames'] - len(body_occurrences)
    counts['distinct_tag_body_pairs'] = len(frame_occurrences)
    counts['repeated_tag_body_pair_occurrences'] = counts['frames'] - len(frame_occurrences)
    counts['body_values_with_multiple_tags'] = sum(len(tags) > 1 for tags in body_tags.values())
    counts['tag_values_with_multiple_bodies'] = sum(len(bodies) > 1 for bodies in tag_bodies.values())
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    items = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    levels = [item for item in items if Path(item['path']).suffix.lower() == '.lvl']
    if not levels or any(item.get('status') != 'examined' for item in levels):
        raise ValueError('empty or incomplete level inventory')
    total = Counter()
    for item in levels:
        total.update(measure(selected_payload(read_verified(root, item))))
    print(json.dumps({'level_files': len(levels), 'counts': dict(sorted(total.items()))},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
