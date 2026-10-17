import struct
import unittest
import zlib

from measure_texture_layout import LIMIT, measure


def header(width=2, height=2, row=4, depth=16, flag=1, extra_flag=0):
    return struct.pack('<IIIH9I', width, height, row, depth,
                       0, 0, 0, 0, 0, extra_flag, 0, 0, flag)


class MeasurementTests(unittest.TestCase):
    def test_compressed_and_trailing(self):
        encoded = zlib.compress(b'abcdefgh')
        body = header(extra_flag=0x100) + struct.pack('<I', len(encoded)) + encoded
        result = measure(body + struct.pack('<I', 3) + b'xyz')
        self.assertEqual(result['status'], 'zlib')
        self.assertTrue(result['row_relation'])
        self.assertTrue(result['tail_length_matches'])
        self.assertFalse(result['tail_is_complete_zlib'])
        self.assertFalse(result['tail_is_complete_raw_deflate'])

    def test_raw(self):
        self.assertTrue(measure(header(flag=0) + b'12345678')['available_exact'])
        self.assertFalse(measure(header(flag=0))['available_exact'])

    def test_hostile(self):
        self.assertEqual(measure(b'')['status'], 'short_header')
        self.assertEqual(measure(header(height=LIMIT, row=2))['status'], 'output_cap')
        self.assertEqual(measure(header() + struct.pack('<I', 100))['status'], 'stream_range')
        self.assertEqual(measure(header() + struct.pack('<I', 2) + b'xx')['status'], 'zlib_error')
        encoded = zlib.compress(b'longer than expected')
        self.assertEqual(measure(header() + struct.pack('<I', len(encoded)) + encoded)['status'], 'zlib_mismatch')


if __name__ == '__main__':
    unittest.main()
