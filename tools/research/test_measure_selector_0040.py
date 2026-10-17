import struct
import unittest
import zlib

from measure_selector_0040 import MAX_BYTES, measure


class SelectorMeasureTest(unittest.TestCase):
    def test_compressed_with_and_without_trailing(self):
        data = bytes(range(128))
        compressed = zlib.compress(data)
        header = bytes(46) + struct.pack('<II', 1, len(compressed))
        plain = measure(header + compressed, len(data))
        self.assertEqual(plain['status'], 'zlib_complete')
        self.assertTrue(plain['decoded_equals_product'])
        self.assertTrue(plain['declared_bytes_consumed'])
        self.assertEqual(plain['trailing_length'], 0)
        tail = struct.pack('<I', 3) + b'abc'
        self.assertTrue(measure(header + compressed + tail, len(data))['trailing_length_prefix_matches'])

    def test_raw_and_malformed_and_bounded(self):
        self.assertEqual(measure(bytes(49), 0)['status'], 'short_prefix')
        self.assertTrue(measure(bytes(50) + b'abc', 3)['remaining_equals_product'])
        self.assertEqual(measure(bytes(46) + struct.pack('<I', 1), 0)['status'], 'short_size')
        self.assertEqual(measure(bytes(46) + struct.pack('<II', 1, 20), 0)['status'], 'stored_range_outside_payload')
        self.assertEqual(measure(bytes(46) + struct.pack('<II', 1, 0), MAX_BYTES + 1)['status'], 'product_cap')
        self.assertEqual(measure(bytes(46) + struct.pack('<II', 1, 3) + b'bad', 3)['status'], 'zlib_error')
        compressed = zlib.compress(b'1234')[:-1]
        truncated = bytes(46) + struct.pack('<II', 1, len(compressed)) + compressed
        self.assertEqual(measure(truncated, 4)['status'], 'incomplete_stream')
        bomb = zlib.compress(bytes(MAX_BYTES + 1))
        capped = bytes(46) + struct.pack('<II', 1, len(bomb)) + bomb
        self.assertEqual(measure(capped, 1)['status'], 'output_cap')
        extra = zlib.compress(b'1234') + b'garbage'
        result = measure(bytes(46) + struct.pack('<II', 1, len(extra)) + extra, 4)
        self.assertEqual(result['status'], 'zlib_complete')
        self.assertFalse(result['declared_bytes_consumed'])


if __name__ == '__main__':
    unittest.main()
