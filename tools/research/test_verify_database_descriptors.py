import unittest

from verify_database_descriptors import decode


class DescriptorVerificationTests(unittest.TestCase):
    def test_decodes_names_with_spaces_and_duplicate_ids(self):
        self.assertEqual(decode(b'version 1\r\ndependencies 2\r\n3 path one\r\n3 other\r\n'),
                         [(3, b'path one'), (3, b'other')])

    def test_rejects_wrong_counts_and_truncation(self):
        for data in (b'version 1\r\ndependencies 1\r\n',
                     b'version 1\r\ndependencies 1\r\n1 name',
                     b'version 1\r\ndependencies 1\r\n2147483648 name\r\n'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode(data)


if __name__ == '__main__':
    unittest.main()
