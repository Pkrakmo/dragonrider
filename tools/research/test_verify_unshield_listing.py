import unittest
from verify_unshield_listing import listing_index


class ListingTest(unittest.TestCase):
    def test_directory_spaces_only_and_collisions(self):
        listing = listing_index('Cabinet: file\n   12  First Group\\Some Dir\\File Name.txd\n'
                                '   12  First_Group\\Some_Dir\\File Name.txd\n')
        self.assertEqual(listing['first_group/some_dir/file name.txd'], [12, 12])
        self.assertNotIn('first_group/some_dir/file_name.txd', listing)


if __name__ == '__main__':
    unittest.main()
