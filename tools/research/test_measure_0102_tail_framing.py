import struct
import unittest

from measure_0102_tail_framing import MAX_ITEMS, candidate, measure
from test_measure_0102_tail_bytes import payload
from test_measure_srsc_prefix_selector import fixture


class TailFramingTests(unittest.TestCase):
    def test_candidate_boundaries(self):
        tail = struct.pack('<I', 2) + b'\x02\x00a\x00\x00\x00'
        self.assertEqual(candidate(tail, 2), ('exact', len(tail)))
        self.assertEqual(candidate(tail, 1)[0], 'remaining')
        self.assertEqual(candidate(tail[:-1], 2)[0], 'short_length')
        self.assertEqual(candidate(tail[:7], 1)[0], 'short_body')
        self.assertEqual(candidate(tail, MAX_ITEMS + 1)[0], 'count_limit')
        self.assertEqual(candidate(tail, 0)[0], 'remaining')

    def test_two_count_models_and_malformed_array(self):
        tail = struct.pack('<I', 0x1001) + b'\x02\x00a\x00'
        invalid = b'\x00\x00' + b'\x00' * 10 + struct.pack('<II', 0, 1)
        data = fixture([(0x102, 0, 0, payload(tail)),
                        (0x102, 0, 0, payload(b'')),
                        (0x102, 0, 0, invalid)])
        counts = measure(data)
        self.assertEqual(counts['records'], 3)
        self.assertEqual(counts['full_short_length'], 1)
        self.assertEqual(counts['low12_exact'], 1)
        self.assertEqual(counts['frame1_fits'], 1)
        self.assertEqual(counts['frame1_nul_terminated'], 1)
        self.assertEqual(counts['frame1_exact'], 1)
        self.assertEqual(counts['frame2_short_length'], 1)
        self.assertEqual(counts['greedy_exact'], 1)
        self.assertEqual(counts['greedy_frames'], 1)
        self.assertEqual(counts['empty_tail'], 1)
        self.assertEqual(counts['short_array'], 1)

    def test_greedy_distinguishes_short_body_and_short_length(self):
        data = fixture([(0x102, 0, 0, payload(struct.pack('<I', 1) + b'\x02\x00a')),
                        (0x102, 0, 0, payload(struct.pack('<I', 1) + b'\x00')),
                        (0x102, 0, 0, payload(struct.pack('<I', 1) + b'\x00\x00\x00'))])
        counts = measure(data)
        self.assertEqual(counts['greedy_short_body'], 1)
        self.assertEqual(counts['greedy_short_length'], 2)
        self.assertEqual(counts['greedy_frames'], 1)

    def test_rejects_invalid_payload_range(self):
        data = bytearray(fixture([(0x102, 0, 0, payload(b''))]))
        offset = struct.unpack_from('<I', data, 6)[0]
        struct.pack_into('<I', data, offset + 6, 11)
        with self.assertRaises(ValueError):
            measure(data)


if __name__ == '__main__':
    unittest.main()
