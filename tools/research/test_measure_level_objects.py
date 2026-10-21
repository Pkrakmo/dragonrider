import struct
import unittest

from measure_level_objects import conditional_counts, decode, relation_counts


def obj(key=0, refs=(), flags=0, n=0, m=0, extra=b''):
    return (struct.pack('<7IHH', 1, 2, key, 4, 5, 6, flags, 7, len(refs))
            + b''.join(struct.pack('<H', x) for x in refs) + bytes(6)
            + (bytes(12) if flags & 0x100 else b'')
            + struct.pack('<ii', n, m) + extra)


class LevelObjectTests(unittest.TestCase):
    def test_conditional_fields_and_strings(self):
        item = obj(9, (0, 1), 0x100, 1, 1,
                   bytes(4 + 2 + 4) + struct.pack('<H', 3) + b'abc')
        rows, trailing = decode(struct.pack('<H', 1) + item + b'x')
        self.assertEqual(rows[0][:7], (9, 2, (0, 1), 0x100, 1, 1, 1))
        self.assertEqual(rows[0][14], [(0, b'abc')])
        self.assertEqual(trailing, 1)

    def test_truncations(self):
        data = struct.pack('<H', 1) + obj(2, (0,), 0x100, 1, 1,
                                         bytes(10) + struct.pack('<H', 2) + b'ab')
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                decode(data[:length])

    def test_nonpositive_counts_skip_arrays(self):
        rows, trailing = decode(struct.pack('<H', 1) + obj(n=-1, m=100))
        self.assertEqual((rows[0][4:7], trailing), ((-1, 100, 0), 0))

    def test_huge_positive_count_is_bounded_by_input(self):
        with self.assertRaises(ValueError):
            decode(struct.pack('<H', 1) + obj(n=0x7fffffff, m=1))

    def test_empty(self):
        self.assertEqual(decode(b'\0\0'), ([], 0))

    def test_reciprocal_edges_and_self_edges(self):
        data = struct.pack('<H', 3) + obj(refs=(0, 1, 2)) + obj(refs=(0,)) + obj()
        rows, _ = decode(data)
        self.assertEqual(relation_counts(rows)['distinct_edges_reciprocated'], 3)
        self.assertEqual(relation_counts(rows)['distinct_edges_unreciprocated'], 1)

    def test_conditional_word_comparison_counts_boundaries_and_duplicates(self):
        stats = conditional_counts(2, (0, 1, 2, 2, 65535))
        self.assertEqual(stats['conditional_array_words_below_first_count'], 2)
        self.assertEqual(stats['conditional_array_words_at_or_above_first_count'], 3)
        self.assertEqual(stats['objects_repeated_conditional_words'], 1)


if __name__ == '__main__':
    unittest.main()
