import struct
import unittest

from measure_0102_tail_bytes import measure
from test_measure_srsc_prefix_selector import fixture


def payload(tail):
    return b'\x00\x00' + b'\x00' * 10 + struct.pack('<II', 1, 0) + tail


class TailBytesTests(unittest.TestCase):
    def test_tail_aggregation(self):
        tagged = b'ABCD' + struct.pack('<HH', 3, 0x6e49) + b'xz\x00'
        data = fixture([(0x102, 0, 0, payload(tagged)),
                        (0x102, 0, 0, payload(tagged)),
                        (0x102, 0, 0, payload(b'\x00\x00')),
                        (0x102, 0, 0, payload(b''))])
        counts, leading, first_bytes, tags, lengths, prefix_tags = measure(data)
        self.assertEqual(counts['records'], 4)
        self.assertEqual(counts['with_tail'], 3)
        self.assertEqual(counts['all_zero_tail'], 1)
        self.assertEqual(counts['tail_bytes'], 24)
        self.assertEqual(counts['zero_bytes'], 6)
        self.assertEqual(counts['printable_two_byte_tag'], 2)
        self.assertEqual(counts['declared_length_fits'], 2)
        self.assertEqual(counts['declared_body_nul_terminated'], 2)
        self.assertEqual(leading, {'41424344': 2})
        self.assertEqual(first_bytes, {'41': 2, '00': 1})
        self.assertEqual(tags, {'In': 2})
        self.assertEqual(lengths, {3: 2})
        self.assertEqual(prefix_tags, {(0x44434241, 'In'): 2})

    def test_rejects_invalid_payload_range(self):
        data = bytearray(fixture([(0x102, 0, 0, payload(b'X'))]))
        table = struct.unpack_from('<I', data, 6)[0]
        struct.pack_into('<I', data, table + 6, 11)
        with self.assertRaises(ValueError):
            measure(data)


if __name__ == '__main__':
    unittest.main()
