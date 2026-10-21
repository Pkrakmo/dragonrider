import struct
import unittest

from measure_0302_pcm_candidates import measure


class CandidatePcmTests(unittest.TestCase):
    def test_unsigned_eight_bit_midpoint_and_endpoints(self):
        counts = measure((1, 8, 22050), bytes([128, 128, 0, 255]))
        self.assertEqual(counts['samples'], 4)
        self.assertEqual(counts['zero_samples'], 2)
        self.assertEqual(counts['endpoint_samples'], 2)
        self.assertEqual(counts['records_with_changes'], 1)

    def test_signed_sixteen_and_silence(self):
        counts = measure((1, 16, 22050), struct.pack('<hhhh', 0, 0, -32768, 32767))
        self.assertEqual(counts['zero_samples'], 2)
        self.assertEqual(counts['endpoint_samples'], 2)
        self.assertEqual(measure((1, 16, 0), bytes(4))['records_all_zero'], 1)
        with self.assertRaises(ValueError):
            measure((1, 16, 0), b'\0')

    def test_other_formats_and_empty(self):
        self.assertEqual(measure((2, 16, 0), b'')['unsupported_format'], 1)
        self.assertEqual(measure((1, 8, 0), b'')['records_all_zero'], 0)


if __name__ == '__main__':
    unittest.main()
