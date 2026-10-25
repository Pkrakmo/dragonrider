#!/usr/bin/env python3
"""Find exact serialized level-frame tokens in verified SRSC record payloads.

The output is aggregate only. A byte match is not a producer, format, or
runtime association claim.
"""
import argparse
from collections import Counter, defaultdict, deque
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct

from measure_0102_model_candidates import table
from measure_level_entry_caller import selected_payload
from measure_level_objects import decode

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_INPUT_SIZE = 256 * 1024 * 1024


def safe_read(root, item):
    if not isinstance(item, dict) or item.get('status') != 'examined':
        raise ValueError('unexamined or malformed inventory entry')
    rel = item.get('path')
    if not isinstance(rel, str):
        raise ValueError('invalid inventory path')
    path = PurePosixPath(rel)
    if path.is_absolute() or not path.parts or any(x in ('', '.', '..') for x in path.parts):
        raise ValueError('unsafe inventory path')
    candidate = root
    for part in path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError('symlink in inventory path')
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError('inventory path escapes root or is not a regular file')
    if resolved.stat().st_nlink != 1:
        raise ValueError('multiply linked inventory input')
    size, digest = item.get('file_size'), item.get('sha256')
    if type(size) is not int or size < 0:
        raise ValueError('invalid inventory size')
    if size > MAX_INPUT_SIZE:
        raise ValueError('inventory input exceeds read limit')
    if resolved.stat().st_size != size:
        raise ValueError('inventory size mismatch')
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError('invalid inventory SHA-256')
    with resolved.open('rb') as source:
        data = source.read(size + 1)
    if len(data) != size:
        raise ValueError('inventory size mismatch')
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('inventory hash mismatch')
    return data


def level_frames(data):
    objects, _ = decode(selected_payload(data))
    result = Counter()
    for row in objects:
        if row[4] > 0 and row[5] > 0:
            result.update((tag, bytes(body)) for tag, body in row[14])
    return result


def automaton(patterns):
    """Build a byte Aho-Corasick matcher; outputs terminal pattern indexes."""
    transitions = [{}]
    outputs = [set()]
    failures = [0]
    for ident, pattern in enumerate(sorted(patterns)):
        state = 0
        for byte in pattern:
            state = transitions[state].setdefault(byte, len(transitions))
            if state == len(transitions):
                transitions.append({})
                outputs.append(set())
                failures.append(0)
        outputs[state].add(ident)
    queue = deque()
    for child in transitions[0].values():
        queue.append(child)
    while queue:
        state = queue.popleft()
        for byte, child in transitions[state].items():
            queue.append(child)
            failure = failures[state]
            while failure and byte not in transitions[failure]:
                failure = failures[failure]
            failures[child] = transitions[failure].get(byte, 0)
            outputs[child].update(outputs[failures[child]])
    return transitions, failures, outputs


def find_patterns(data, matcher):
    transitions, failures, outputs = matcher
    found = set()
    state = 0
    for byte in data:
        while state and byte not in transitions[state]:
            state = failures[state]
        state = transitions[state].get(byte, 0)
        if outputs[state]:
            found.update(outputs[state])
    return found


def measure(levels, containers):
    occurrence_counts = Counter()
    for frames in levels:
        occurrence_counts.update(frames)
    patterns = {struct.pack('<IH', tag, len(body)) + body
                for tag, body in occurrence_counts if len(body) <= 0xffff}
    pattern_ids = {pattern: i for i, pattern in enumerate(sorted(patterns))}
    matcher = automaton(patterns)
    found_by_kind = defaultdict(set)
    record_hits = Counter()
    record_counts = Counter()
    for data in containers:
        _, entries = table(data)
        for kind, _, _, start, length in entries:
            if start < 12 or start > len(data) or length > len(data) - start:
                raise ValueError('SRSC payload outside file')
            payload = data[start:start + length]
            found = find_patterns(payload, matcher)
            record_counts[kind] += 1
            if found:
                record_hits[kind] += 1
                found_by_kind[kind].update(found)
    encoded = {}
    for kind in sorted(record_counts):
        if record_hits[kind]:
            encoded[f'0x{kind:04x}'] = {
                'records_examined': record_counts[kind],
                'records_containing_any_exact_frame_token': record_hits[kind],
                'distinct_level_frame_tokens_found': len(found_by_kind[kind]),
            }
    return {
        'counts': {
            'level_files': len(levels),
            'level_frame_occurrences': sum(occurrence_counts.values()),
            'distinct_level_frame_tokens': len(patterns),
            'srsc_containers': len(containers),
            'srsc_records_examined': sum(record_counts.values()),
        },
        'record_kinds_with_matches': encoded,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('root is not a directory')
    items = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not isinstance(items, list) or not items:
        raise ValueError('empty or malformed inventory')
    seen = set()
    levels, containers = [], []
    for item in items:
        rel = item.get('path') if isinstance(item, dict) else None
        if not isinstance(rel, str):
            raise ValueError('invalid inventory path')
        canonical = PurePosixPath(rel).as_posix()
        if canonical in seen:
            raise ValueError('duplicate inventory path')
        seen.add(canonical)
        data = safe_read(root, item)
        if data[:4] != b'SRSC':
            raise ValueError('inventory contains a non-SRSC file')
        containers.append(data)
        if PurePosixPath(rel).suffix.lower() == '.lvl':
            levels.append(level_frames(data))
    if not levels:
        raise ValueError('no level files')
    print(json.dumps(measure(levels, containers), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
