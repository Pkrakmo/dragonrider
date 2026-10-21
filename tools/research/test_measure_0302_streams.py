import struct
import unittest
import zlib

from measure_0302_streams import LIMIT, classify


def frame(expected, data, mode=1):
    return b'\0\0' + bytes(24) + struct.pack('<II', expected, mode) + (struct.pack('<I', len(data)) if mode else b'') + data


class StreamTests(unittest.TestCase):
    def test_valid_and_extra(self):
        compressed = zlib.compress(b'hello')
        result = classify(frame(5, compressed))
        self.assertEqual(result['complete_exact_size'], 1)
        self.assertEqual(result['unused_input'], 0)
        self.assertEqual(classify(frame(5, compressed + b'x'))['unused_input'], 1)
        self.assertEqual(classify(frame(4, compressed))['decoded_over_size'], 1)
        self.assertEqual(classify(frame(5, compressed[:-1]))['stream_eof'], 0)

    def test_errors_and_limits(self):
        self.assertEqual(classify(frame(5, b'not zlib'))['zlib_error'], 1)
        self.assertEqual(classify(frame(LIMIT + 1, b''))['limit_skipped'], 1)
        self.assertEqual(classify(frame(0, b'', mode=0))['zero_mode'], 1)
        for data in (b'', b'\xff\xff', frame(5, b'abc')[:-1]):
            with self.assertRaises(ValueError):
                classify(data)


if __name__ == '__main__':
    unittest.main()
