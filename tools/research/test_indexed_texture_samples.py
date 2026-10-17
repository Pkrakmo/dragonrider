import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from indexed_texture_samples import LIMIT, measure, scan


def texture(width, height, stride, rows, compressed=False):
    header = bytearray(50)
    struct.pack_into('<IIIH', header, 0, width, height, stride, 8)
    if compressed:
        struct.pack_into('<i', header, 46, 1)
        stream = zlib.compress(rows)
        return bytes(header) + struct.pack('<I', len(stream)) + stream
    return bytes(header) + rows


def container(records):
    data = bytearray()
    table = bytearray()
    for selector, payload in records:
        table.extend(struct.pack('<HHHII', selector, 0, 0, 12 + len(data), len(payload)))
        data.extend(payload)
    return b'SRSC' + struct.pack('<HIH', 0x100, 12 + len(data), len(records)) + data + table


class IndexedTextureTests(unittest.TestCase):
    def test_padding_excluded_for_raw_and_compressed(self):
        for compressed in (False, True):
            result = measure(texture(2, 2, 3, b'\x00\x01\xff\x02\x03\xff', compressed), 3)
            self.assertEqual(result['status'], 'measured')
            self.assertEqual(result['visible_indices'], 4)
            self.assertEqual(result['maximum_index'], 3)
            self.assertEqual(result['distinct_indices'], 4)
            self.assertEqual(result['indices_at_or_above_candidate_count'], 1)

    def test_truncated_and_output_cap(self):
        self.assertEqual(measure(b'\0' * 49, 0)['status'], 'short_header')
        self.assertEqual(measure(texture(2, 1, 1, b'\0'), 0)['status'], 'short_stride')
        self.assertEqual(measure(texture(1, LIMIT + 1, 1, b''), 0)['status'], 'output_cap')
        self.assertEqual(measure(texture(1, 2, 1, b'\0'), 0)['status'], 'short_rows')
        compressed = texture(1, 1, 1, b'\x01', True)
        self.assertEqual(measure(compressed[:-1], 1)['status'], 'short_stream')
        damaged = bytearray(compressed)
        damaged[-1] ^= 1
        self.assertEqual(measure(damaged, 1)['status'], 'zlib_error')

    def test_zero_width_large_height_does_not_iterate(self):
        result = measure(texture(0, 0xffffffff, 0, b''), 0)
        self.assertEqual(result['status'], 'measured')
        self.assertEqual(result['visible_indices'], 0)
        self.assertIsNone(result['maximum_index'])

    def test_scan_candidate_cooccurrence_and_zero_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a.txd').write_bytes(container([(0x30, b'\0\0'), (0x40, texture(2, 1, 2, b'\xff\xff', True))]))
            result = scan(root)
            self.assertEqual(result['summary']['records_candidate_zero'], 1)
            self.assertEqual(result['summary']['indices_at_or_above_zero_candidate_count'], 2)
            self.assertEqual(result['files'][0]['records'][0]['distinct_indices'], 1)
            (root / 'b.txd').write_bytes(container([(0x30, b'\0\0'), (0x30, b'\0\0'), (0x40, texture(1, 1, 1, b'\x01'))]))
            result = scan(root)
            self.assertIsNone(result['files'][1]['selected_candidate_count'])
            self.assertNotIn('indices_at_or_above_candidate_count', result['files'][1]['records'][0])


if __name__ == '__main__':
    unittest.main()
