import struct
import unittest

from measure_0302_audio_fields import classify


class AudioFieldTests(unittest.TestCase):
    def test_values_and_alignment(self):
        payload = b'\x00\x00' + struct.pack('<IHHIIIIII', 0, 2, 16, 44100, 0, 0, 0, 44, 1)
        counts = classify(payload)
        self.assertEqual(counts['channels_2'], 1)
        self.assertEqual(counts['bits_16'], 1)
        self.assertEqual(counts['rate_44100'], 1)
        self.assertEqual(counts['size_multiple_of_block'], 1)
        self.assertEqual(counts['mode_1'], 1)

    def test_odd_bits_zero_block_and_overflow(self):
        payload = b'\x00\x00' + struct.pack('<IHHIIIIII', 0, 65535, 15, 0xffffffff, 0, 0, 0, 1, 0)
        counts = classify(payload)
        self.assertEqual(counts['bits_multiple_of_8'], 0)
        self.assertEqual(counts['average_product_fits_u32'], 0)
        zero = b'\x00\x00' + struct.pack('<IHHIIIIII', 0, 0, 16, 0, 0, 0, 0, 0, 0)
        counts = classify(zero)
        self.assertEqual(counts['block_nonzero'], 0)
        self.assertEqual(counts['size_multiple_of_block'], 0)

    def test_truncation(self):
        good = b'\x00\x00' + bytes(32)
        for size in range(len(good)):
            with self.subTest(size=size), self.assertRaises(ValueError):
                classify(good[:size])
        with self.assertRaises(ValueError):
            classify(b'\xff\xff' + bytes(32))


if __name__ == '__main__':
    unittest.main()
