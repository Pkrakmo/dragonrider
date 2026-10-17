#!/usr/bin/env python3
"""Synthetic bounds checks for the level prefix measurement."""

import struct
import unittest

from measure_level_0001 import decode_prefix


class LevelPrefixTest(unittest.TestCase):
    def test_variable_entry_and_opaque_tail(self):
        payload = (struct.pack("<I", 1) + bytes(28) + struct.pack("<H", 3) + b"abc"
                   + bytes(24) + struct.pack("<III", 2, 0, 7) + b"tail")
        self.assertEqual(decode_prefix(payload), (1, [2], [3], [0, 7], 4))
        for size in range(len(payload) - 4):
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode_prefix(payload[:size])

    def test_empty_and_excessive_counts(self):
        self.assertEqual(decode_prefix(struct.pack("<I", 0)), (0, [], [], [], 0))
        with self.assertRaises(ValueError):
            decode_prefix(struct.pack("<I", 4097))
        with self.assertRaises(ValueError):
            decode_prefix(struct.pack("<I", 1) + bytes(28) + bytes(2) + bytes(24)
                          + struct.pack("<I", 4097))


if __name__ == "__main__":
    unittest.main()
