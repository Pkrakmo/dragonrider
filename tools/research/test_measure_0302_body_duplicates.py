import struct
import unittest
import zlib

from measure_0302_body_duplicates import decode_body, summarize


def payload(body, mode=0):
    stored = zlib.compress(body) if mode else body
    fixed = struct.pack('<IHHIIIIII', 0, 1, 16, 22050, 0, 0, 0, len(body), mode)
    return b'\0\0' + fixed + (struct.pack('<I', len(stored)) if mode else b'') + stored


class BodyTests(unittest.TestCase):
    def test_modes_duplicates_and_format(self):
        a = decode_body(payload(b'abcd'))
        b = decode_body(payload(b'abcd', 1))
        counts = summarize([(0, a), (1, b), (0, ((2, 16, 22050), 0, b'abcd', 0))])
        self.assertEqual(counts['repeated_format_body_occurrences'], 1)
        self.assertEqual(counts['format_body_groups_with_multiple_modes'], 1)
        self.assertEqual(counts['body_digests_with_multiple_formats'], 1)
        self.assertEqual(counts['format_body_groups_in_multiple_files'], 1)

    def test_limits_truncation_and_trailing(self):
        good = payload(b'abcd', 1)
        for size in range(len(good)):
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode_body(good[:size])
        with self.assertRaises(ValueError):
            decode_body(good, limit=3)
        self.assertEqual(decode_body(good + b'x')[-1], 1)
        damaged = bytearray(good)
        damaged[-1] ^= 1
        with self.assertRaises(ValueError):
            decode_body(damaged)

    def test_zlib_unused_input_rejected(self):
        good = bytearray(payload(b'abcd', 1))
        stored = struct.unpack_from('<I', good, 34)[0]
        struct.pack_into('<I', good, 34, stored + 1)
        with self.assertRaises(ValueError):
            decode_body(good + b'x')

    def test_decoded_size_mismatch_rejected(self):
        for size in (1, 5):
            good = bytearray(payload(b'abcd', 1))
            struct.pack_into('<I', good, 26, size)
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode_body(good)


if __name__ == '__main__':
    unittest.main()
