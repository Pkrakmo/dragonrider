import struct
import unittest

from measure_level_entry_caller import first_lookup_dword, selected_payload


def fixture(payload, selectors=((0x20, 0, 0),)):
    table_start = 12 + len(payload)
    header = struct.pack("<4sHIH", b"SRSC", 0x100, table_start, len(selectors))
    records = b"".join(struct.pack("<HHHII", *selector, 12, len(payload))
                       for selector in selectors)
    return header + payload + records


class FirstObjectTests(unittest.TestCase):
    def test_empty_list(self):
        self.assertEqual(first_lookup_dword(b"\0\0"), (0, None))

    def test_first_key_unsigned_and_no_following_parse(self):
        payload = struct.pack("<HIII", 2, 1, 2, 0xfedcba98)
        self.assertEqual(first_lookup_dword(payload), (2, 0xfedcba98))

    def test_truncation(self):
        for payload in (b"", b"\1", b"\1\0", b"\1\0" + bytes(11)):
            with self.subTest(length=len(payload)), self.assertRaises(ValueError):
                first_lookup_dword(payload)

    def test_selector_exact_and_unique(self):
        payload = struct.pack("<HIII", 1, 1, 2, 3)
        self.assertEqual(bytes(selected_payload(fixture(payload))), payload)
        for selectors in ((), ((0x20, 1, 0),), ((0x20, 0, 0), (0x20, 0, 0))):
            with self.subTest(selectors=selectors), self.assertRaises(ValueError):
                selected_payload(fixture(payload, selectors))

    def test_record_outside_payload(self):
        data = bytearray(fixture(bytes(14)))
        struct.pack_into("<I", data, 12 + 14 + 6, 0xffffffff)
        with self.assertRaises(ValueError):
            selected_payload(data)


if __name__ == "__main__":
    unittest.main()
