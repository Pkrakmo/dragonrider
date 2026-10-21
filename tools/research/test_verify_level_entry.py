import struct
import unittest
import zlib

from test_measure_srsc_prefix_selector import fixture
from verify_level_entry import decode, selected


class VerifyLevelEntryTests(unittest.TestCase):
    def test_fields_and_all_truncations(self):
        name = b'\x00\xffX'
        payload = (struct.pack('<I7I', 1, 0x80000000, 1, 2, 3, 4, 5, 6) +
                   struct.pack('<H', len(name)) + name + struct.pack('<6I', 7, 8, 9, 10, 11, 12) +
                   struct.pack('<2I', 1, 99))
        entry = decode(payload)[0]
        self.assertEqual(entry['Prefix dwords'], '80000000 00000001 00000002 00000003 00000004 00000005 00000006')
        self.assertEqual(entry['Byte sequence CRC32'], f'{zlib.crc32(name):08x}')
        self.assertEqual(entry['Following dwords'], '00000007 00000008 00000009 0000000a 0000000b 0000000c')
        self.assertEqual(entry['Inner count'], '1')
        for length in range(len(payload)):
            with self.assertRaises(ValueError):
                decode(payload[:length])

    def test_select_record_and_reject_duplicate(self):
        payload = struct.pack('<I', 0)
        self.assertEqual(selected(fixture([(1, 0, 0, payload)])), (0, []))
        with self.assertRaises(ValueError):
            selected(fixture([(1, 0, 0, payload), (1, 0, 0, payload)]))


if __name__ == '__main__':
    unittest.main()
