import struct
import unittest
import zlib

from verify_level_grid import output, scan, signed32


class GridTest(unittest.TestCase):
    def test_grid_metadata_and_flags(self):
        prefix = struct.pack('<7I', 0, 1, 1, 0, 0xfffffffe, 3, 0x7fc00000)
        prefix += bytes(2 + 24) + struct.pack('<I', 0)
        grid = struct.pack('<8H', 0x100, 0, 0, 0x8000, 0, 0xffff, 0x100, 0x7fff)
        decoded = grid + bytes(26)
        compressed = zlib.compress(decoded)
        payload = struct.pack('<I', 1) + prefix + struct.pack('<II', 1, len(compressed)) + compressed
        result = scan(payload)[0]
        self.assertEqual((result['origin_first'], result['origin_second'], result['base']), (-2, 3, 0x7fc00000))
        self.assertEqual((result['count'], result['bit8'], result['min'], result['max']), (4, 2, -65536, 65534))
        self.assertIn('Nominal first coordinate: -4096..-2048\n', output(0, result))
        self.assertIn('Nominal second coordinate: 6144..8192\n', output(0, result))
        with self.assertRaises((ValueError, zlib.error)):
            scan(payload[:-1])

    def test_empty_and_signed_limits(self):
        self.assertEqual(scan(bytes(8)), {})
        self.assertEqual(signed32(0x80000000), -2147483648)
        self.assertEqual(signed32(0x7fffffff), 2147483647)


if __name__ == '__main__':
    unittest.main()
