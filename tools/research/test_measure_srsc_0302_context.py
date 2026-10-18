import unittest

from measure_srsc_0302_context import measure


class Srsc0302ContextTests(unittest.TestCase):
    def test_both_kinds_but_only_nonzero_0302_third_word(self):
        result = measure([(0x0402, 0, 0), (0x0302, 7, 9)])
        self.assertEqual(result, {
            'has_0402_zero_tuple': True,
            'has_0302': True,
            'has_0302_zero_tuple': False,
            'has_both_0402_and_0302': True,
        })

    def test_exact_0302_zero_tuple_is_detected(self):
        result = measure([(0x0402, 0, 0), (0x0302, 0, 0)])
        self.assertTrue(result['has_0302_zero_tuple'])

    def test_independent_absence_cases(self):
        self.assertFalse(measure([(0x0302, 1, 2)])['has_0402_zero_tuple'])
        self.assertFalse(measure([(0x0402, 0, 0)])['has_0302'])
        self.assertFalse(measure([])['has_both_0402_and_0302'])


if __name__ == '__main__':
    unittest.main()
