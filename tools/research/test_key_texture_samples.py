import struct
import unittest
import zlib

from key_texture_samples import LIMIT, inspect_payload


def payload(key, rows, *, compressed=False, depth=8, stride=3, width=2, height=2):
    header = bytearray(50)
    struct.pack_into('<IIIH', header, 0, width, height, stride, depth)
    struct.pack_into('<I', header, 18, key)
    if compressed:
        struct.pack_into('<i', header, 46, 1)
        data = zlib.compress(rows)
        return bytes(header) + struct.pack('<I', len(data)) + data
    return bytes(header) + rows


class KeySamplesTest(unittest.TestCase):
    def test_key_and_padding(self):
        for compressed in (False, True):
            result = inspect_payload(payload(4, bytes([4, 1, 4, 4, 2, 4]), compressed=compressed))
            self.assertEqual(result['matches'], 2)
            self.assertEqual(result['visible_indices'], 4)

    def test_full_dword_and_sentinel(self):
        for key in (0x104, 0xffffffff):
            result = inspect_payload(payload(key, bytes([4] * 6)))
            self.assertEqual(result['matches'], 0)
            self.assertEqual(result['key'], key)

    def test_malformed_and_limits(self):
        self.assertEqual(inspect_payload(b'')['status'], 'short_header')
        self.assertEqual(inspect_payload(payload(1, b'', stride=1))['status'], 'short_stride')
        self.assertEqual(inspect_payload(payload(1, b'', width=0, stride=1, height=LIMIT+1))['status'], 'output_cap')
        self.assertEqual(inspect_payload(payload(1, b''))['status'], 'short_rows')
        truncated = payload(1, bytes(6), compressed=True)[:-1]
        self.assertEqual(inspect_payload(truncated)['status'], 'short_stream')
        bad = bytearray(payload(1, bytes(6), compressed=True)); bad[54] ^= 0xff
        self.assertEqual(inspect_payload(bad)['status'], 'zlib_error')

    def test_depth_and_empty(self):
        self.assertEqual(inspect_payload(payload(2, b'', depth=16))['status'], 'header')
        result = inspect_payload(payload(2, b'', width=0, stride=0, height=0))
        self.assertEqual((result['matches'], result['visible_indices']), (0, 0))

if __name__ == '__main__':
    unittest.main()
