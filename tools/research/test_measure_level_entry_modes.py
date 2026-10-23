#!/usr/bin/env python3
"""Synthetic parsing and inventory checks for level-entry mode measurement."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from measure_level_entry_modes import decode, level_inventory_entries, measure, read_verified_level


def payload(*, discriminator=2, flag=0, tail=b''):
    return (struct.pack('<I', 1) + struct.pack('<7I', 9, 2, 3, discriminator, 5, 6, 7)
            + struct.pack('<H', 1) + b'x' + struct.pack('<6I', flag, 0, 0, 0, 0, 0)
            + struct.pack('<I', 1) + struct.pack('<I', 0) + tail)


def srsc(records):
    body = b''.join(data for _, data in records)
    offset = 12
    entries = []
    for selectors, data in records:
        entries.append(struct.pack('<HHHII', *selectors, offset, len(data)))
        offset += len(data)
    return b'SRSC' + struct.pack('<HIH', 0x100, offset, len(entries)) + body + b''.join(entries)


class LevelEntryModesTests(unittest.TestCase):
    def test_decode_and_measure_preserve_raw_discriminator_and_flag(self):
        data = srsc([((1, 0, 0), payload(discriminator=2, flag=2, tail=b'opaque'))])
        entries, trailing = measure(data)
        self.assertEqual(entries, [(9, 2, 3, 2, 2)])
        self.assertEqual(trailing, 6)

    def test_decode_rejects_every_truncated_structural_prefix(self):
        data = payload()
        for size in range(len(data) - 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode(data[:size])
        with self.assertRaises(ValueError):
            decode(struct.pack('<I', 4097))

    def test_measure_requires_one_bounded_level_record(self):
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            measure(srsc([((2, 0, 0), b'')]))
        outside = b'SRSC' + struct.pack('<HIH', 0x100, 12, 1) + struct.pack('<HHHII', 1, 0, 0, 12, 1)
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            measure(outside)

    def test_verified_read_rejects_bad_metadata_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            data = b'data'
            sample = root / 'sample.lvl'
            sample.write_bytes(data)
            entry = {'path': 'sample.lvl', 'status': 'examined', 'file_size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest(), 'candidate_table': {}}
            self.assertEqual(read_verified_level(root, entry), data)
            with self.assertRaisesRegex(ValueError, 'size'):
                read_verified_level(root, dict(entry, file_size=-1))
            with self.assertRaisesRegex(ValueError, 'hash'):
                read_verified_level(root, dict(entry, sha256='x' * 64))
            outside = Path(outside_directory) / 'outside.lvl'
            outside.write_bytes(data)
            (root / 'linked.lvl').symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                read_verified_level(root, dict(entry, path='linked.lvl'))

    def test_level_inventory_selection_validates_candidate_metadata(self):
        entry = {'path': 'sample.lvl', 'status': 'examined', 'file_size': 1,
                 'sha256': 'a' * 64}
        self.assertEqual(level_inventory_entries([entry, dict(entry, path='other.mod')]), [entry])
        with self.assertRaisesRegex(ValueError, 'hash'):
            level_inventory_entries([dict(entry, sha256='g' * 64)])
        with self.assertRaisesRegex(ValueError, 'entry'):
            level_inventory_entries(['bad'])


if __name__ == '__main__':
    unittest.main()
