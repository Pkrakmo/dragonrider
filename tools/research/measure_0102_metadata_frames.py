#!/usr/bin/env python3
"""Test whether post-array 0x0102 tails match candidate metadata frames."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from measure_0102_array_types import resource_types
from measure_0102_model_candidates import table
from measure_0102_resource_table import RFL_SHA256, RESOURCE_OFFSET, RESOURCE_SIZE
from measure_level_object_metadata import descriptor_string_candidates
from measure_srsc_prefix_selector import read_verified


def compare_tail(tail, flags, descriptors, bodies=None, resource_key=None):
    """Test one tag/u16-length/body frame per descriptor, without partial claims."""
    result = Counter(tails=1)
    if len(flags) != len(descriptors):
        raise ValueError('metadata lengths differ')
    if len(flags) > len(tail) // 6:
        result['too_short_for_frame_headers'] += 1
        return result
    position = 0
    flag_matches = name_matches = terminal = no_nul = embedded = even = writer_rule = 0
    pending = []
    for index, (flag, candidate) in enumerate(zip(flags, descriptors)):
        if len(tail) - position < 6:
            result['truncated_frame_header'] += 1
            return result
        tag, length = struct.unpack_from('<IH', tail, position)
        position += 6
        if length > len(tail) - position:
            result['truncated_frame_body'] += 1
            return result
        raw = bytes(tail[position:position + length])
        body = raw.removesuffix(b'\0')
        position += length
        flag_matches += tag == flag
        name_matches += body == candidate.get('0_descriptor')
        terminal += raw.endswith(b'\0') and b'\0' not in raw[:-1]
        no_nul += b'\0' not in raw
        embedded += b'\0' in raw[:-1]
        even += len(raw) % 2 == 0
        writer_rule += (b'\0' not in body and
                        raw == body + (b'\0' if len(body) % 2 else b''))
        if bodies is not None:
            pending.append(((resource_key, index), raw))
    if bodies is not None:
        for key, raw in pending:
            bodies.setdefault(key, set()).add(raw)
    result['parsed_tails'] += 1
    result['exact_tails'] += position == len(tail)
    result['trailing_bytes'] += len(tail) - position
    result['frames'] += len(flags)
    result['flags_equal'] += flag_matches
    result['names_equal'] += name_matches
    result['body_one_terminal_nul'] += terminal
    result['body_no_nul'] += no_nul
    result['body_embedded_nul'] += embedded
    result['body_even_length'] += even
    result['body_matches_even_writer_rule'] += writer_rule
    result['all_flags_equal'] += flag_matches == len(flags)
    result['all_names_equal'] += name_matches == len(flags)
    return result


def measure(data, metadata, candidates, bodies=None):
    end, records = table(data)
    result = Counter()
    for kind, _, _, start, length in records:
        if kind != 0x0102:
            continue
        result['records'] += 1
        if start < 12 or start > end or length > end - start or length < 2:
            raise ValueError('invalid record range')
        payload = memoryview(data)[start:start + length]
        prefix = struct.unpack_from('<H', payload)[0]
        pos = 2 + prefix
        if pos > length or length - pos < 18:
            raise ValueError('short record header')
        key = struct.unpack_from('<H', payload, pos + 6)[0]
        declared, count = struct.unpack_from('<II', payload, pos + 10)
        pos += 18
        if count > (length - pos) // 4:
            raise ValueError('array outside record')
        flags = metadata.get(key, ())
        names = candidates.get(key, ())
        if len(flags) != 1 or len(names) != 1 or len(flags[0]) != declared:
            raise ValueError('metadata selection or declared count mismatch')
        result.update(compare_tail(payload[pos + count * 4:], flags[0], names[0], bodies, key))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('rfl', type=Path)
    args = parser.parse_args()
    binary = args.rfl.read_bytes()
    if hashlib.sha256(binary).hexdigest() != RFL_SHA256:
        raise ValueError('RFL SHA-256 mismatch')
    if RESOURCE_OFFSET > len(binary) or RESOURCE_SIZE > len(binary) - RESOURCE_OFFSET:
        raise ValueError('resource outside RFL')
    resource = binary[RESOURCE_OFFSET:RESOURCE_OFFSET + RESOURCE_SIZE]
    metadata, _ = resource_types(resource)
    candidates = descriptor_string_candidates(resource)
    items = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not items or any(item['status'] != 'examined' for item in items):
        raise ValueError('empty or incomplete inventory')
    root = args.root.resolve(strict=True)
    counts = Counter()
    bodies = {}
    for item in items:
        counts.update(measure(read_verified(root, item), metadata, candidates, bodies))
    counts['distinct_candidate_descriptors'] = len(bodies)
    counts['candidate_descriptors_with_multiple_raw_bodies'] = sum(len(values) > 1 for values in bodies.values())
    print(json.dumps({'files': len(items), 'counts': dict(sorted(counts.items()))}, indent=2))


if __name__ == '__main__':
    main()
