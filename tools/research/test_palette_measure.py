import struct
import tempfile
import unittest
from pathlib import Path

from palette_measure import measure_file, scan


def make_srsc(payloads):
    body = bytearray()
    entries = bytearray()
    for selector, data in payloads:
        start = 12 + len(body)
        entries.extend(struct.pack('<HHHII', selector, 0, 0, start, len(data)))
        body.extend(data)
    return b'SRSC' + struct.pack('<HIH', 0x100, 12 + len(body), len(payloads)) + body + entries


class PaletteMeasureTests(unittest.TestCase):
    def measure(self, data):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / 'synthetic.txd'
            path.write_bytes(data)
            return measure_file(path, root)

    def test_count_and_depth_association(self):
        palette = struct.pack('<H', 2) + bytes(8)
        texture = bytes(12) + struct.pack('<H', 8)
        result = self.measure(make_srsc([(0x30, palette), (0x40, texture)]))
        self.assertEqual(result['palette_candidates'][0]['status'], 'exact')
        self.assertEqual(result['palette_candidates'][0]['count'], 2)
        self.assertEqual(result['texture_counts']['depth8'], 1)

    def test_zero_short_and_trailing(self):
        data = make_srsc([(0x30, b'\0\0'), (0x30, b'\1'),
                          (0x30, b'\2\0' + bytes(4)), (0x30, b'\0\0!')])
        records = self.measure(data)['palette_candidates']
        self.assertEqual([r['status'] for r in records], ['exact', 'short_count', 'short_entries', 'trailing'])

    def test_bad_range_and_header(self):
        data = bytearray(make_srsc([(0x30, b'\0\0')]))
        table = struct.unpack_from('<I', data, 6)[0]
        struct.pack_into('<I', data, table + 6, table + 1)
        self.assertEqual(self.measure(data)['palette_candidates'][0]['status'], 'range')
        self.assertEqual(self.measure(b'SRSC' + struct.pack('<HIH', 0x100, 12, 1))['status'], 'skipped_header')

    def test_gate_requires_both_selector_keys_and_value(self):
        texture = bytes(12) + struct.pack('<H', 8)
        data = make_srsc([(0x402, struct.pack('<I', 0x204)),
                          (0x30, struct.pack('<H', 1) + bytes(4)), (0x40, texture)])
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / 'synthetic.txd'
            path.write_bytes(data)
            self.assertEqual(scan(root)['summary']['depth8_files_gate_and_qualified_nonzero'], 1)
            changed = bytearray(data)
            table = struct.unpack_from('<I', changed, 6)[0]
            struct.pack_into('<H', changed, table + 2, 1)
            path.write_bytes(changed)
            self.assertEqual(scan(root)['summary']['depth8_files_with_matching_gate'], 0)
            changed = bytearray(data)
            struct.pack_into('<I', changed, 12, 0x205)
            path.write_bytes(changed)
            self.assertEqual(scan(root)['summary']['depth8_files_with_matching_gate'], 0)


if __name__ == '__main__':
    unittest.main()
