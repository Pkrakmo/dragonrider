import struct
import unittest
import zlib

from measure_level_blocks import measure


def fixture(storage, content):
    entry = bytes(28) + bytes(2) + bytes(24) + struct.pack("<I", 0)
    return struct.pack("<I", 1) + entry + struct.pack("<II", storage, len(content)) + content


class BlockTest(unittest.TestCase):
    def test_raw_and_compressed(self):
        data = b"abcd"
        for storage, content in ((0, data), (1, zlib.compress(data))):
            payload = fixture(storage, content)
            self.assertEqual(measure(payload), (storage, 1, storage, 0, 4, zlib.crc32(data), 0,
                                                1, 2 * 0x6463 - 65536, 2 * 0x6463 - 65536,
                                                0, 0, 0, 0, 0))
            for length in range(len(payload)):
                with self.subTest(storage=storage, length=length), self.assertRaises((ValueError, zlib.error)):
                    measure(payload[:length])

    def test_extra_compressed_bytes(self):
        with self.assertRaises(ValueError):
            measure(fixture(1, zlib.compress(b"abcd") + b"x"))

    def test_cell_flags_and_signed_dwords(self):
        prefix = struct.pack("<7I", 0, 1, 1, 0, 0, 0, 0) + bytes(2 + 24 + 4)
        cell = struct.pack("<Hii8H", 3, -2, 17, *([0] * 8))
        decoded = bytes(16) + cell
        stream = zlib.compress(decoded)
        payload = struct.pack("<I", 1) + prefix + struct.pack("<II", 1, len(stream)) + stream
        result = measure(payload)
        self.assertEqual(result[7:], (4, -65536, -65536, 1, 1, 1, 1, 0))


if __name__ == "__main__":
    unittest.main()
