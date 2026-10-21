#!/usr/bin/env python3
"""Compare bounded 0x0302 hypothetical new-object bodies by digest."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import struct
import zlib

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified

LIMIT = 32 * 1024 * 1024


def decode_body(payload, limit=LIMIT):
    if len(payload) < 2:
        raise ValueError('short prefix')
    pos = 2 + struct.unpack_from('<H', payload)[0]
    if pos > len(payload) or len(payload) - pos < 32:
        raise ValueError('short fixed fields')
    _, channels, bits, rate, _, _, _, size, mode = struct.unpack_from('<IHHIIIIII', payload, pos)
    if size > limit:
        raise ValueError('decoded size exceeds limit')
    pos += 32
    if mode:
        if len(payload) - pos < 4:
            raise ValueError('short stored length')
        stored = struct.unpack_from('<I', payload, pos)[0]
        pos += 4
    else:
        stored = size
    if stored > limit or stored > len(payload) - pos:
        raise ValueError('stored body exceeds bounds or limit')
    body = payload[pos:pos + stored]
    if mode:
        stream = zlib.decompressobj()
        try:
            body = stream.decompress(body, size + 1)
        except zlib.error as error:
            raise ValueError('invalid zlib stream') from error
        if len(body) != size or not stream.eof or stream.unused_data or stream.unconsumed_tail:
            raise ValueError('incomplete or unexpected zlib output')
    return (channels, bits, rate), mode, body, len(payload) - (pos + stored)


def summarize(items):
    by_format = Counter()
    by_digest = defaultdict(set)
    modes = defaultdict(set)
    files = defaultdict(set)
    counts = Counter()
    for file_index, (fmt, mode, body, trailing) in items:
        digest = hashlib.sha256(body).digest()
        key = (len(body), digest)
        by_format[(fmt, key)] += 1
        by_digest[key].add(fmt)
        modes[(fmt, key)].add(mode)
        files[(fmt, key)].add(file_index)
        counts['records'] += 1
        counts['trailing_records'] += trailing != 0
    counts['distinct_format_body_groups'] = len(by_format)
    counts['repeated_format_body_occurrences'] = sum(n - 1 for n in by_format.values())
    counts['format_body_groups_with_repetitions'] = sum(n > 1 for n in by_format.values())
    counts['body_digests_with_multiple_formats'] = sum(len(values) > 1 for values in by_digest.values())
    counts['format_body_groups_with_multiple_modes'] = sum(len(values) > 1 for values in modes.values())
    counts['format_body_groups_in_multiple_files'] = sum(len(values) > 1 for values in files.values())
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not entries or any(e['status'] != 'examined' for e in entries):
        raise ValueError('empty or incomplete inventory')

    def rows():
        for file_index, entry in enumerate(entries):
            data = read_verified(root, entry)
            end, records = table(data)
            for kind, _, _, offset, length in records:
                if kind != 0x0302:
                    continue
                if offset < 12 or offset > end or length > end - offset:
                    raise ValueError('selected record outside payload')
                yield file_index, decode_body(data[offset:offset + length])

    print(json.dumps({'files': len(entries), 'counts': dict(sorted(summarize(rows()).items()))}, indent=2))


if __name__ == '__main__':
    main()
