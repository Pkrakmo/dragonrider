#!/usr/bin/env python3
"""Measure raw flagged array units against a pinned candidate resource.

This is a byte comparison, not a simulation of the mutating retail routine.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from measure_0102_array_types import resource_types
from measure_0102_resource_table import RFL_SHA256, RESOURCE_OFFSET, RESOURCE_SIZE
from measure_srsc_prefix_selector import read_verified
from measure_0102_model_candidates import table
from measure_0102_descriptor_keys import verified
from verify_database_descriptors import decode


def measure_units(units, flags, dependency_ids=None, tag_index=None):
    """Classify flagged dwords and their raw proposed index intervals."""
    if len(units) < len(flags):
        raise ValueError('array shorter than base count')
    counts = Counter({name: 0 for name in (
        'flagged', 'clear_low_zero', 'clear_high_zero', 'clear_both_zero',
        'negative_high', 'end_outside', 'in_bounds', 'in_bounds_base_overlap',
        'in_bounds_prior_range_overlap', 'in_bounds_extra_only',
        'in_bounds_elements', 'in_bounds_unique_extra_elements',
        'extra_elements', 'extra_elements_not_covered', 'type10_entries',
        'type10_zero_low', 'type10_zero_high', 'type10_both_zero', 'type10_nonempty_in_bounds',
        'type10_nonempty_outside', 'type10_extra_elements',
        'type10_elements', 'type10_base_overlap', 'type10_prior_range_overlap',
        'type10_overlaps_flagged_extra', 'extra_not_covered_by_either',
        'type10_nul_in_span', 'type10_printable_before_nul', 'type10_hex_tag_prefix')})
    covered = set()
    extra = set()
    for i, flag in enumerate(flags):
        if not flag & 0x1000:
            continue
        value = units[i]
        low = value & 0xffff
        high_bits = value >> 16
        high = high_bits if high_bits < 0x8000 else high_bits - 0x10000
        counts['flagged'] += 1
        counts[f'type_{flag & 0xfff}'] += 1
        if low == 0 or high_bits == 0:
            counts['clear_low_zero'] += low == 0
            counts['clear_high_zero'] += high_bits == 0
            counts['clear_both_zero'] += low == 0 and high_bits == 0
            continue
        # The original comparison is signed; negative lengths can pass its
        # end check but do not enter its signed increasing-index loop.
        end = low + high - 1
        if end >= len(units):
            counts['end_outside'] += 1
        elif high < 0:
            counts['negative_high'] += 1
        else:
            indices = set(range(low, end + 1))
            counts['in_bounds'] += 1
            counts['in_bounds_elements'] += high
            counts['in_bounds_base_overlap'] += low < len(flags)
            counts['in_bounds_extra_only'] += low >= len(flags)
            counts['in_bounds_prior_range_overlap'] += bool(indices & covered)
            covered.update(indices)
            extra.update(index for index in indices if index >= len(flags))
            kind = flag & 0xfff
            if kind in (5, 9):
                for index in range(low, end + 1):
                    unit = units[index]
                    high_word = unit >> 16
                    name = f'indirect_{kind}'
                    counts[name + '_units'] += 1
                    counts[name + '_zero'] += unit == 0
                    counts[name + '_high_zero'] += high_word == 0
                    counts[name + '_high_nonzero'] += high_word != 0
                    if kind == 5 and high_word and dependency_ids is not None:
                        matches = dependency_ids[high_word]
                        outcome = 'missing' if matches == 0 else 'unique' if matches == 1 else 'multiple'
                        counts[name + '_dependency_' + outcome] += 1
    counts['extra_elements'] = len(units) - len(flags)
    counts['in_bounds_unique_extra_elements'] = len(extra)
    counts['extra_elements_not_covered'] = counts['extra_elements'] - len(extra)
    type10_extra = set()
    type10_covered = set()
    for i, flag in enumerate(flags):
        if (flag & 0xfff) != 10:
            continue
        value = units[i]
        low, high = value & 0xffff, value >> 16
        counts['type10_entries'] += 1
        counts['type10_zero_low'] += low == 0
        counts['type10_zero_high'] += high == 0
        counts['type10_both_zero'] += low == 0 and high == 0
        if high == 0:
            continue
        if low + high > len(units):
            counts['type10_nonempty_outside'] += 1
            continue
        counts['type10_nonempty_in_bounds'] += 1
        counts['type10_elements'] += high
        counts['type10_base_overlap'] += low < len(flags)
        indices = set(range(low, low + high))
        counts['type10_prior_range_overlap'] += bool(indices & type10_covered)
        type10_covered.update(indices)
        type10_extra.update(range(max(low, len(flags)), low + high))
        span = b''.join(struct.pack('<I', units[index]) for index in range(low, low + high))
        nul = span.find(b'\0')
        if nul >= 0:
            counts['type10_nul_in_span'] += 1
            counts['type10_printable_before_nul'] += all(32 <= byte <= 126 for byte in span[:nul])
        match = re.match(rb'<0x([0-9a-fA-F]+)>', span)
        counts['type10_hex_tag_prefix'] += match is not None
        if match is not None and tag_index is not None:
            digits = match.group(1).lstrip(b'0')
            if len(digits) > 8:
                counts['type10_tag_over_u32'] += 1
            else:
                value = int(digits or b'0', 16)
                matches = tag_index[value & 0xffff]
                outcome = 'missing' if matches == 0 else 'unique' if matches == 1 else 'multiple'
                counts['type10_tag_0400_' + outcome] += 1
                counts['type10_tag_high_nonzero'] += value > 0xffff
    counts['type10_extra_elements'] = len(type10_extra)
    counts['type10_overlaps_flagged_extra'] = len(type10_extra & extra)
    counts['extra_not_covered_by_either'] = counts['extra_elements'] - len(extra | type10_extra)
    return counts


def measure(data, by_key, dependency_ids=None, tag_index=None):
    offset, entries = table(data)
    total = Counter(records=0, missing_or_ambiguous_resource=0,
                    mismatched_count=0, array_shorter_than_declared=0)
    for kind, _, _, start, length in entries:
        if kind != 0x0102:
            continue
        total['records'] += 1
        if start < 12 or start > offset or length > offset - start:
            raise ValueError('selected payload outside pre-table region')
        payload = memoryview(data)[start:start + length]
        if len(payload) < 2:
            raise ValueError('short prefix length')
        prefix = struct.unpack_from('<H', payload)[0]
        pos = 2 + prefix
        if pos > length or length - pos < 18:
            raise ValueError('short prefix or array header')
        key = struct.unpack_from('<H', payload, pos + 6)[0]
        declared, count = struct.unpack_from('<II', payload, pos + 10)
        pos += 18
        if count > (length - pos) // 4:
            raise ValueError('array outside payload')
        choices = by_key.get(key, ())
        if len(choices) != 1:
            total['missing_or_ambiguous_resource'] += 1
            continue
        flags = choices[0]
        if declared != len(flags):
            total['mismatched_count'] += 1
            continue
        if count < declared:
            total['array_shorter_than_declared'] += 1
            continue
        units = [item[0] for item in struct.iter_unpack('<I', payload[pos:pos + count * 4])]
        total.update(measure_units(units, flags, dependency_ids, tag_index))
    return total


def zero_third_0400(data):
    """Return selector keys and bounded payload digests, without contents."""
    offset, entries = table(data)
    result = []
    for kind, second, third, start, length in entries:
        if kind != 0x400 or third != 0:
            continue
        if start < 12 or start > offset or length > offset - start:
            raise ValueError('selected 0x0400 payload outside pre-table region')
        result.append((second, length, hashlib.sha256(data[start:start + length]).digest()))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('rfl', type=Path)
    parser.add_argument('--descriptors', type=Path, help='private asset inventory for same-path DB comparison')
    parser.add_argument('--compare-0400', action='store_true', help='compare strict tags to all inventoried 0x0400 zero-third selectors')
    args = parser.parse_args()
    binary = args.rfl.read_bytes()
    if hashlib.sha256(binary).hexdigest() != RFL_SHA256:
        raise ValueError('RFL SHA-256 does not match the pinned US retail image')
    if RESOURCE_OFFSET > len(binary) or RESOURCE_SIZE > len(binary) - RESOURCE_OFFSET:
        raise ValueError('resource range outside RFL image')
    by_key, stats = resource_types(binary[RESOURCE_OFFSET:RESOURCE_OFFSET + RESOURCE_SIZE])
    root = args.root.resolve(strict=True)
    inventory = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not inventory:
        raise ValueError('empty inventory')
    tag_index = None
    tag_files = 0
    tag_payloads = {}
    if args.compare_0400:
        tag_index = Counter()
        for item in inventory:
            if item['status'] != 'examined':
                raise ValueError('inventory contains unexamined files')
            matches = zero_third_0400(read_verified(root, item))
            tag_index.update(second for second, _, _ in matches)
            for second, length, digest in matches:
                tag_payloads.setdefault(second, set()).add((length, digest))
            tag_files += bool(matches)
    descriptors = {}
    if args.descriptors:
        items = json.loads(args.descriptors.read_text(encoding='utf-8'))['files']
        descriptors = {entry['path'].lower(): entry for entry in items}
        if len(descriptors) != len(items):
            raise ValueError('case-insensitive descriptor inventory path collision')
    result = Counter()
    pairs = 0
    for item in inventory:
        if item['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        ids = None
        if args.descriptors and item['path'].lower().endswith('.odb'):
            descriptor = descriptors.get((item['path'][:-4] + '.db').lower())
            if descriptor is None:
                raise ValueError('missing same-path descriptor in inventory')
            ids = Counter(ident for ident, _ in decode(verified(root, descriptor)))
            pairs += 1
        measured = measure(read_verified(root, item), by_key, ids, tag_index)
        if args.descriptors and measured['records'] and ids is None:
            raise ValueError('selected SRSC records lack a same-path descriptor comparison')
        result.update(measured)
    print(json.dumps({'files_examined': len(inventory), 'resource': dict(sorted(stats.items())),
                      'descriptor_pairs': pairs, 'tag_comparison_files': tag_files,
                      'tag_comparison_records': sum(tag_index.values()) if tag_index is not None else 0,
                      'tag_comparison_duplicate_keys': sum(count > 1 for count in tag_index.values()) if tag_index is not None else 0,
                      'tag_comparison_duplicate_identical_keys': sum(tag_index[key] > 1 and len(values) == 1 for key, values in tag_payloads.items()),
                      'counts': dict(sorted(result.items()))}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
