#!/usr/bin/env python3
"""Compare level object helper words to candidate 0x0102 metadata, aggregates only.

Paths derived from level data are lexical keys, never opened. A match does not
establish runtime loading, manager selection, or helper dispatch.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import struct

from measure_0102_array_types import read_u32, resource_types
from measure_0102_descriptor_keys import verified
from measure_0102_model_candidates import table
from measure_0102_resource_table import RFL_SHA256, RESOURCE_OFFSET, RESOURCE_SIZE
from measure_level_0102_sources import candidate_key
from measure_level_entry_caller import selected_payload
from measure_level_objects import decode
from measure_level_source_ids import records as level_records
from measure_level_texture_candidates import directory_entries, inventory_key
from measure_srsc_prefix_selector import read_verified
from verify_database_descriptors import decode as decode_descriptor


def measure_frame_body(body, value):
    """Compare raw textual candidates without emitting original bytes."""
    body = bytes(body)
    counts = Counter(frame_bodies=1)
    counts['body_one_terminal_nul'] += body.endswith(b'\0') and b'\0' not in body[:-1]
    counts['body_no_nul'] += b'\0' not in body
    counts['body_embedded_nul'] += b'\0' in body[:-1]
    text = body[:-1] if body.endswith(b'\0') else body
    counts['body_even_length'] += len(body) % 2 == 0
    if b'\0' not in text:
        expected = text + (b'\0' if len(text) % 2 else b'')
        counts['body_matches_even_writer_rule'] += body == expected
    if re.fullmatch(rb'[+-]?[0-9]+', text):
        counts['body_decimal_integer'] += 1
        # Cap conversion independently of input length and Python's digit limit.
        if len(text) <= 16:
            number = int(text)
            signed = value if value < 0x80000000 else value - 0x100000000
            counts['body_decimal_equals_dword_unsigned'] += number == value
            counts['body_decimal_equals_dword_signed'] += number == signed
            counts['body_decimal_equals_low_word'] += number == (value & 0xffff)
    if re.fullmatch(rb'[+-]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?', text):
        counts['body_decimal_float'] += 1
        if len(text) <= 64:
            number = float(text)
            raw_float = struct.unpack('<f', struct.pack('<I', value))[0]
            counts['body_float_equals_dword'] += math.isfinite(number) and number == raw_float
    if re.fullmatch(rb'0[xX][0-9a-fA-F]+', text):
        counts['body_hex_integer'] += 1
        if len(text) <= 10:
            counts['body_hex_equals_dword'] += int(text, 16) == value
    return counts


def descriptor_string_candidates(resource):
    """Try bounded C strings at four hypothetical bases for descriptor offsets."""
    # Validate the shared group structure before independently walking it.
    resource_types(resource)
    result = defaultdict(list)
    for i in range(read_u32(resource, 0)):
        base = 4 + i * 32
        key = read_u32(resource, base)
        start = base + read_u32(resource, base + 28)
        descriptors = []
        for j in range(read_u32(resource, base + 24)):
            group = base + read_u32(resource, start + j * 4)
            params = group + read_u32(resource, group + 8)
            for k in range(read_u32(resource, group + 4)):
                pos = params + k * 16
                candidates = {}
                for field in (0, 8, 12):
                    offset = read_u32(resource, pos + field)
                    for name, origin in (('resource', 0), ('entry', base),
                                         ('group', group), ('descriptor', pos)):
                        target = origin + offset
                        if target >= len(resource):
                            continue
                        end = resource.find(b'\0', target, min(len(resource), target + 512))
                        if end >= 0:
                            candidates[f'{field}_{name}'] = resource[target:end]
                descriptors.append(candidates)
        result[key].append(descriptors)
    return result


def compare_frame_candidates(words, frames, descriptors, flags=None):
    result = Counter()
    if len(words) != len(frames):
        raise ValueError('frame count differs from word count')
    if flags is not None and len(flags) != len(descriptors):
        raise ValueError('descriptor and flag counts differ')
    if flags is not None:
        result['descriptor_candidates_missing'] += sum('0_descriptor' not in item for item in descriptors)
    pairs = Counter((flag, candidate['0_descriptor']) for flag, candidate in zip(flags or (), descriptors)
                    if '0_descriptor' in candidate)
    for word, (tag, body) in zip(words, frames):
        if word >= len(descriptors):
            continue
        text = bytes(body).removesuffix(b'\0')
        if flags is not None:
            matches = pairs[(tag, text)]
            category = 'none' if not matches else 'one' if matches == 1 else 'multiple'
            result[f'descriptor_pair_{category}'] += 1
        for candidate, value in descriptors[word].items():
            result[f'candidate_{candidate}_bounded'] += 1
            result[f'candidate_{candidate}_equal'] += text == value
    return result


def candidate_records(data):
    end, records = table(data)
    result = defaultdict(list)
    for kind, second, _, start, length in records:
        if kind != 0x102:
            continue
        if start < 12 or start > end or length > end - start or length < 2:
            raise ValueError('invalid selected record range')
        prefix = struct.unpack_from('<H', data, start)[0]
        pos = start + 2 + prefix
        if pos > start + length or start + length - pos < 18:
            raise ValueError('short selected record header')
        metadata_key = struct.unpack_from('<H', data, pos + 6)[0]
        declared, count = struct.unpack_from('<II', data, pos + 10)
        if count > (start + length - pos - 18) // 4:
            raise ValueError('selected record array outside payload')
        result[second].append((metadata_key, declared))
    return result


def measure_words(words, units, flags, frames=(), dependency_ids=None):
    result = Counter(objects_measured=1)
    if frames and len(frames) != len(words):
        raise ValueError('frame count differs from word count')
    first_positions = {}
    for position, word in enumerate(words):
        first_positions.setdefault(word, position)
        result['words'] += 1
        if frames:
            tag, body = frames[position]
            result['frames'] += 1
            result['frame_tag_equals_word'] += tag == word
            result['frame_tag_zero'] += tag == 0
            result['frame_empty'] += not body
            result['frame_ends_nul'] += bool(body) and body[-1] == 0
            result['frame_printable_or_nul'] += all(32 <= c < 127 or c == 0 for c in body)
            if position < len(units):
                result.update(measure_frame_body(body, units[position]))
        if word >= len(flags):
            result['word_outside_metadata'] += 1
            continue
        flag = flags[word]
        result['word_inside_metadata'] += 1
        result[f'type_{flag & 0xfff}'] += 1
        if frames:
            result['frame_tag_equals_descriptor_flags'] += frames[position][0] == flag
        if flag & 0xfff == 10 and position < len(units):
            value = units[position]
            start, length = value & 0xffff, value >> 16
            result['type_10_spans'] += 1
            if not length:
                result['type_10_empty_spans'] += 1
            elif start + length > len(units):
                result['type_10_spans_outside_units'] += 1
            else:
                raw = struct.pack(f'<{length}I', *units[start:start + length])
                result['type_10_spans_inside_units'] += 1
                nul = raw.find(b'\0')
                result['type_10_spans_nul_terminated'] += nul >= 0
                result['type_10_spans_printable_prefix'] += nul >= 0 and all(32 <= c < 127 for c in raw[:nul])
        if flag & 0x1000:
            result['flagged'] += 1
            selected = first_positions[word]
            if selected >= len(units):
                result['flagged_position_outside_units'] += 1
                continue
            value = units[selected]
            start, high = value & 0xffff, value >> 16
            signed_high = high if high < 0x8000 else high - 0x10000
            if start == 0 or high == 0:
                result['flagged_zero_start_or_length'] += 1
            elif signed_high < 0:
                result['flagged_negative_length'] += 1
            elif start + signed_high > len(units):
                result['flagged_end_outside_units'] += 1
            else:
                result['flagged_range_inside_units'] += 1
        else:
            result['scalar'] += 1
            result['scalar_position_outside_units'] += position >= len(units)
            if position < len(units) and (flag & 0xfff) in (5, 9):
                kind, value = flag & 0xfff, units[position]
                prefix = f'scalar_{kind}'
                result[prefix + '_units'] += 1
                result[prefix + '_zero'] += value == 0
                result[prefix + '_high_zero'] += value >> 16 == 0
                if kind == 5 and value >> 16 and dependency_ids is not None:
                    count = dependency_ids[value >> 16]
                    category = 'missing' if not count else 'unique' if count == 1 else 'multiple'
                    result[prefix + '_dependency_' + category] += 1
    return result


def measure_coverage(words, units, flags):
    """Count raw candidate coverage, without modeling dispatch or mutations."""
    count = len(units)
    if len(words) > count or any(word >= len(flags) for word in words):
        return Counter(coverage_objects_skipped=1)
    flagged_delta = [0] * (count + 1)
    type10_delta = [0] * (count + 1)
    first_positions = {}
    for pos, word in enumerate(words):
        first_positions.setdefault(word, pos)
        flag = flags[word]
        if flag & 0x1000:
            value = units[first_positions[word]]
            start, high = value & 0xffff, value >> 16
            if start and 0 < high < 0x8000 and start + high <= count:
                flagged_delta[start] += 1
                flagged_delta[start + high] -= 1
        if flag & 0xfff == 10:
            value = units[pos]
            start, length = value & 0xffff, value >> 16
            if length and start + length <= count:
                type10_delta[start] += 1
                type10_delta[start + length] -= 1
    result = Counter(coverage_objects=1)
    flagged = type10 = 0
    for i in range(count):
        flagged += flagged_delta[i]
        type10 += type10_delta[i]
        if i < len(words):
            result['base_units'] += 1
            result['base_units_in_flagged_range'] += flagged > 0
            result['base_units_in_type10_span'] += type10 > 0
        else:
            result['extra_units'] += 1
            result['extra_units_uncovered'] += flagged == 0 and type10 == 0
            result['extra_units_flagged_only'] += flagged > 0 and type10 == 0
            result['extra_units_type10_only'] += flagged == 0 and type10 > 0
            result['extra_units_both'] += flagged > 0 and type10 > 0
            result['extra_units_repeated_flagged'] += flagged > 1
            result['extra_units_repeated_type10'] += type10 > 1
    return result


def join_candidate(key, sources, indexed, metadata):
    """Require unique matches at every lexical and numeric join."""
    choices = sources.get(key >> 16, ())
    if len(choices) != 1:
        return ('source_id_missing' if not choices else 'source_id_multiple', None, None)
    if choices[0] is None:
        return ('source_path_unusable', None, None)
    files = indexed.get(choices[0], ())
    if len(files) != 1:
        return ('source_file_missing' if not files else 'source_file_multiple', None, None)
    records, ids = files[0]
    matches = records.get(key & 0xffff, ())
    if len(matches) != 1:
        return ('record_missing' if not matches else 'record_multiple', None, None)
    meta_key, declared = matches[0]
    choices = metadata.get(meta_key, ())
    if len(choices) != 1 or declared != len(choices[0]):
        return ('metadata_missing_ambiguous_or_count_mismatch', None, None)
    return (None, choices[0], ids)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('rfl', type=Path)
    parser.add_argument('--overlay-hypothesis', action='store_true')
    parser.add_argument('--descriptors', type=Path, help='private full inventory for same-path DB comparisons')
    args = parser.parse_args()
    binary = args.rfl.read_bytes()
    if hashlib.sha256(binary).hexdigest() != RFL_SHA256:
        raise ValueError('RFL SHA-256 mismatch')
    if RESOURCE_OFFSET > len(binary) or RESOURCE_SIZE > len(binary) - RESOURCE_OFFSET:
        raise ValueError('resource outside RFL')
    resource = binary[RESOURCE_OFFSET:RESOURCE_OFFSET + RESOURCE_SIZE]
    metadata, _ = resource_types(resource)
    descriptor_candidates = descriptor_string_candidates(resource)
    root = args.root.resolve(strict=True)
    items = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not items or any(item['status'] != 'examined' for item in items):
        raise ValueError('empty or incomplete inventory')
    descriptors = {}
    if args.descriptors:
        entries = json.loads(args.descriptors.read_text(encoding='utf-8'))['files']
        descriptors = {entry['path'].lower(): entry for entry in entries}
        if len(entries) != len(descriptors):
            raise ValueError('case-insensitive descriptor inventory collision')
    indexed = defaultdict(list)
    levels = []
    pairs = 0
    for item in items:
        data = read_verified(root, item)
        key = inventory_key(list(PurePosixPath(item['path']).parts), args.overlay_hypothesis)
        ids = None
        if args.descriptors and item['path'].lower().endswith('.odb'):
            descriptor = descriptors.get((item['path'][:-4] + '.db').lower())
            if descriptor is None:
                raise ValueError('missing same-path descriptor')
            ids = Counter(ident for ident, _ in decode_descriptor(verified(root, descriptor)))
            pairs += 1
        indexed[key].append((candidate_records(data), ids))
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
            reason, flags, ids = join_candidate(row[7][1], sources, indexed, metadata)
            if reason is not None:
                result[reason] += 1
                continue
            if args.descriptors and ids is None:
                result['objects_without_descriptor_pair'] += 1
            result.update(measure_words(row[12], row[13], flags, row[14], ids))
            result.update(measure_coverage(row[12], row[13], flags))
            reason, candidates, _ = join_candidate(row[7][1], sources, indexed, descriptor_candidates)
            if reason is not None:
                raise ValueError('candidate descriptor selection disagrees with metadata')
            result.update(compare_frame_candidates(row[12], row[14], candidates, flags))
    print(json.dumps({'files': len(items), 'levels': len(levels), 'descriptor_pairs': pairs,
                      'overlay_hypothesis': args.overlay_hypothesis,
                      'counts': dict(sorted(result.items()))}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
