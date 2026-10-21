#!/usr/bin/env python3
"""Measure a conditional selector-0x20 object framing; emit aggregates only."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
import subprocess
import zlib

from measure_level_entry_caller import selected_payload
from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified
from verify_level_entry import selected


def decode(payload):
    pos = 0

    def take(n):
        nonlocal pos
        if n < 0 or n > len(payload) - pos:
            raise ValueError('truncated object framing')
        result = payload[pos:pos + n]
        pos += n
        return result

    def word():
        return struct.unpack('<H', take(2))[0]

    def signed():
        return struct.unpack('<i', take(4))[0]

    count = word()
    objects = []
    for _ in range(count):
        fields = struct.unpack('<7I', take(28))
        first_word = word()
        refs = word()
        references = struct.unpack(f'<{refs}H', take(refs * 2))
        following = struct.unpack('<3H', take(6))
        optional = b''
        if fields[6] & 0x100:
            optional = take(12)
        n = signed()
        m = signed()
        strings = 0
        array_words = ()
        array_dwords = ()
        frames = []
        if n > 0 and m > 0:
            array_dwords = struct.unpack(f'<{n}I', take(n * 4))
            array_words = struct.unpack(f'<{m}H', take(m * 2))
            for _ in range(m):
                tag = struct.unpack('<I', take(4))[0]
                length = word()
                frames.append((tag, take(length)))
                strings += 1
        objects.append((fields[2], refs, references, fields[6], n, m, strings,
                        fields, first_word, following, zlib.crc32(optional), pos, array_words, array_dwords,
                        frames))
    return objects, len(payload) - pos


def relation_counts(objects):
    edges = {(index, target) for index, row in enumerate(objects) for target in row[2]}
    return Counter(distinct_edges_reciprocated=sum((target, index) in edges
                                                   for index, target in edges),
                   distinct_edges_unreciprocated=sum((target, index) not in edges
                                                     for index, target in edges))


def conditional_counts(first_count, words):
    return Counter(conditional_array_words=len(words),
                   conditional_array_words_below_first_count=sum(v < first_count for v in words),
                   conditional_array_words_at_or_above_first_count=sum(v >= first_count for v in words),
                   objects_with_outside_conditional_words=int(any(v >= first_count for v in words)),
                   objects_repeated_conditional_words=int(len(set(words)) != len(words)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--probe', type=Path, help='test-only C++ callback probe')
    parser.add_argument('--inspector', type=Path, help='compare inspector aggregate summary')
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    levels = [entry for entry in entries if Path(entry['path']).suffix.lower() == '.lvl']
    if not levels or any(entry['status'] != 'examined' for entry in levels):
        raise ValueError('empty or incomplete level inventory')
    totals = Counter()
    snapshots = []
    for entry in levels:
        data = read_verified(root, entry)
        payload = selected_payload(data)
        objects, trailing = decode(payload)
        if args.probe:
            if len(payload) > 32 * 1024 * 1024:
                raise ValueError('probe input exceeds limit')
            result = subprocess.run([str(args.probe.resolve(strict=True))],
                                    input=struct.pack('<I', len(payload)) + bytes(payload),
                                    capture_output=True, check=True).stdout.decode('ascii').splitlines()
            expected = []
            for row in objects:
                _, _, indices, _, n, m, _, fields, first_word, following, optional_crc, end = row[:12]
                reference_data = struct.pack(f'<{len(indices)}H', *indices)
                array_words, array_dwords, frames = row[12:15]
                dword_bytes = struct.pack(f'<{len(array_dwords)}I', *array_dwords)
                word_bytes = struct.pack(f'<{len(array_words)}H', *array_words)
                frame_bytes = b''.join(struct.pack('<IH', tag, len(body)) + body for tag, body in frames)
                numbers = (*fields, first_word, len(indices), zlib.crc32(reference_data),
                           *following, optional_crc, n & 0xffffffff, m & 0xffffffff, end,
                           zlib.crc32(dword_bytes), zlib.crc32(word_bytes), zlib.crc32(frame_bytes))
                expected.append(':'.join(str(number) for number in numbers))
            expected.append(f'end:{len(objects)}:{len(payload) - trailing}')
            if result != expected:
                raise ValueError('C++ probe disagrees with independent decoding')
            totals['probe_objects_compared'] += len(objects)
        if args.inspector:
            _, records = table(data)
            index = next(i for i, record in enumerate(records) if record[:3] == (0x20, 0, 0))
            result = subprocess.run([str(args.inspector.resolve(strict=True)), '--level-objects',
                                     str(index), str(root / entry['path'])],
                                    capture_output=True, text=True, check=True)
            actual = dict(line.split(': ', 1) for line in result.stdout.splitlines() if ': ' in line)
            expected = {'Record': str(index), 'Objects': str(len(objects)),
                        'Index words': str(sum(row[1] for row in objects)),
                        'Flag 0x100 objects': str(sum(bool(row[3] & 0x100) for row in objects)),
                        'Objects with conditional arrays': str(sum(bool(row[13]) for row in objects)),
                        'Conditional dwords': str(sum(len(row[13]) for row in objects)),
                        'Conditional words': str(sum(len(row[12]) for row in objects)),
                        'Conditional frame bytes': str(sum(6 + len(body) for row in objects
                                                           for _, body in row[14])),
                        'Trailing bytes (unvalidated)': str(trailing)}
            if any(actual.get(key) != value for key, value in expected.items()):
                raise ValueError('inspector disagrees with independent decoding')
            totals['inspector_files_compared'] += 1
        _, level_entries = selected(data)
        keys = Counter(int(row['Prefix dwords'].split()[0], 16) for row in level_entries)
        snapshots.append((objects, keys))
        totals['files'] += 1
        totals['objects'] += len(objects)
        totals['files_with_trailing_bytes'] += trailing != 0
        totals['trailing_bytes'] += trailing
        totals.update(relation_counts(objects))
        for index, row in enumerate(objects):
            key, refs, indices, flags, n, m, strings = row[:7]
            array_words = row[12]
            totals['zero_keys'] += key == 0
            totals['all_ones_keys'] += key == 0xffffffff
            totals['keys_no_match'] += keys[key] == 0
            totals['nonzero_keys_no_match'] += key != 0 and keys[key] == 0
            totals['keys_one_match'] += keys[key] == 1
            totals['keys_multiple_matches'] += keys[key] > 1
            totals['reference_words'] += refs
            totals['reference_words_out_of_range'] += sum(i >= len(objects) for i in indices)
            totals['reference_words_self'] += sum(i == index for i in indices)
            totals['reference_words_before'] += sum(i < index for i in indices)
            totals['reference_words_after'] += sum(i > index for i in indices)
            totals['objects_with_repeated_references'] += len(set(indices)) != len(indices)
            totals['flag_0100_objects'] += bool(flags & 0x100)
            totals['both_counts_positive'] += n > 0 and m > 0
            if n > 0 and m > 0:
                totals['objects_second_count_le_first'] += m <= n
                totals['objects_second_count_gt_first'] += m > n
                totals['objects_second_count_eq_first'] += m == n
                totals.update(conditional_counts(n, array_words))
                for value in row[13][:m]:
                    low, high = value & 0xffff, value >> 16
                    totals['conditional_selected_dwords'] += 1
                    totals['conditional_low_below_first_count'] += low < n
                    totals['conditional_high_zero'] += high == 0
            totals['strings'] += strings
    unmatched = set()
    for index, (objects, keys) in enumerate(snapshots):
        file_has_unmatched = False
        for key, *_ in objects:
            if key and not keys[key]:
                unmatched.add(key)
                file_has_unmatched = True
                other_matches = sum(key in other for j, (_, other) in enumerate(snapshots)
                                    if j != index)
                totals['nonzero_unmatched_found_in_other_levels'] += other_matches > 0
                totals['nonzero_unmatched_one_other_level'] += other_matches == 1
                totals['nonzero_unmatched_multiple_other_levels'] += other_matches > 1
                totals['nonzero_unmatched_no_other_level'] += other_matches == 0
        totals['files_with_nonzero_unmatched'] += file_has_unmatched
    totals['distinct_nonzero_unmatched_keys'] = len(unmatched)
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
