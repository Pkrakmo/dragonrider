import struct
import unittest

from verify_model_geometry import decode


class ModelGeometryVerificationTest(unittest.TestCase):
    def test_counts_indices_and_tails(self):
        points = struct.pack('<HIII', 1, 0, 0, 0) + b'x'
        groups = struct.pack('<HHHHHII', 1, 7, 1, 9, 1, 4, 5) + b'y'
        self.assertEqual(decode(points, groups)[:6], (1, 1, 1, 1, len(points) - 1, len(groups) - 1))

    def test_truncation(self):
        points = struct.pack('<HIII', 1, 0, 0, 0)
        groups = struct.pack('<HHHHHII', 1, 7, 1, 9, 0, 4, 5)
        for i in range(len(points)):
            with self.assertRaises(ValueError):
                decode(points[:i], groups)
        for i in range(len(groups)):
            with self.assertRaises(ValueError):
                decode(points, groups[:i])


if __name__ == '__main__':
    unittest.main()
