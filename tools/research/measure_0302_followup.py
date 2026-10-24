#!/usr/bin/env python3
"""Measure bounded 0x0302 post-prefix fields without exporting payload data."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from measure_srsc_lookup import read_snapshot


def classify(payload, record_length=None):
    if record_length is None:
        record_length = len(payload)
    out = Counter({'records': 1})
    if len(payload) < 2:
        out['short_prefix'] += 1
        return out
    prefix = int.from_bytes(payload[:2], 'little')
    offset = 2 + prefix
    if offset > record_length:
        out['prefix_exceeds_record'] += 1
        return out
    remaining = record_length - offset
    if remaining < 32:
        out['less_than_32_after_prefix'] += 1
        return out
    if len(payload) < offset + min(remaining, 36):
        raise ValueError('short bounded payload read')
    flags, width, bits, count, field12, field16, field20, size, mode = \
        struct.unpack_from('<IHHIIIIII', payload, offset)
    del flags, field12, field16, field20
    product16 = (width * (bits >> 3)) & 0xffff
    product32 = (product16 * count) & 0xffffffff
    out['fixed_fields_present'] += 1
    out['product_equals_size'] += product32 == size
    out['size_multiple_of_product'] += product32 != 0 and size % product32 == 0
    out['size_equals_twice_product'] += size == product32 * 2
    out['size_equals_four_times_product'] += size == product32 * 4
    out['size_less_than_product'] += size < product32
    out['product_is_zero'] += product32 == 0
    out['size_is_zero'] += size == 0
    # On the cached-object path these same words become mode and, when
    # nonzero, input length. The decoded size comes from prior object state.
    out['cached_mode_zero'] += size == 0
    out['cached_mode_nonzero'] += size != 0
    if size != 0:
        out['cached_stored_zero'] += mode == 0
        out['cached_stored_one'] += mode == 1
        out['cached_stored_fits'] += mode <= remaining - 32
        out['cached_stored_exact'] += mode == remaining - 32
    out['size_at_24_fits_tail_at_32'] += size <= remaining - 32
    out['size_at_24_equals_tail_at_32'] += size == remaining - 32
    out['mode_at_28_zero'] += mode == 0
    out['mode_at_28_one'] += mode == 1
    out['mode_at_28_other'] += mode not in (0, 1)
    if mode == 0:
        out['zero_mode_size_fits'] += size <= remaining - 32
        out['zero_mode_size_exact'] += size == remaining - 32
    elif remaining >= 36:
        compressed = int.from_bytes(payload[offset + 32:offset + 36], 'little')
        out['nonzero_mode_length_present'] += 1
        out['nonzero_mode_length_fits'] += compressed <= remaining - 36
        out['nonzero_mode_length_exact'] += compressed == remaining - 36
    else:
        out['nonzero_mode_length_missing'] += 1
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    totals = Counter()
    for entry in entries:
        if entry['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        data, records = read_snapshot(root, entry)
        totals['files_examined'] += 1
        totals['files_with_0302'] += any(kind == 0x0302 for kind, _, _ in records)
        _, table, count = struct.unpack_from('<HIH', data, 4)
        raw = data[table:table + count * 14]
        if count != len(records):
            raise ValueError('table changed during measurement')
        for i, (kind, second, third, start, length) in enumerate(struct.iter_unpack('<HHHII', raw)):
            if (kind, second, third) != records[i]:
                raise ValueError('table changed during measurement')
            if kind != 0x0302:
                continue
            if start < 12 or start + length > table:
                raise ValueError('selected payload outside pre-table range')
            amount = min(length, 65573)
            payload = data[start:start + amount]
            if len(payload) != amount:
                raise ValueError('short payload read')
            totals.update(classify(payload, length))
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
