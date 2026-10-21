import struct
import unittest

from verify_srsc_0302_new import expected


class Verify0302Tests(unittest.TestCase):
    def test_raw_and_nonzero(self):
        header = b'\x02\x00xy' + struct.pack('<IHHIIIII', 0x12345678, 1, 2, 3, 4, 5, 6, 3)
        raw = header + struct.pack('<I', 0) + b'\1\2\3\xff'
        self.assertIn('Body CRC32: 55bc801d\nTrailing bytes (unvalidated): 1', expected(raw, 0))
        stored = header + struct.pack('<II', 42, 2) + b'\7\10'
        self.assertIn('Mode: 42\nBody bytes: 2', expected(stored, 1))
        for i in range(len(raw) - 1):
            with self.assertRaises(ValueError):
                expected(raw[:i], 0)
        with self.assertRaises(ValueError):
            expected(header + struct.pack('<I', 42), 0)


if __name__ == '__main__':
    unittest.main()
