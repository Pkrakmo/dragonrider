"""Synthetic checks for level discriminator/dimension aggregation."""

import struct
import unittest

from measure_level_discriminator_shapes import decode, measure, summarize


def payload(entries):
    encoded = [struct.pack("<I", len(entries))]
    for width, height, discriminator in entries:
        encoded.extend((
            struct.pack("<7I", 9, width, height, discriminator, 5, 6, 7),
            struct.pack("<H", 0), struct.pack("<6I", 0, 0, 0, 0, 0, 0),
            struct.pack("<I", 0),
        ))
    return b"".join(encoded)


def srsc(record_payload):
    table_offset = 12 + len(record_payload)
    return (b"SRSC" + struct.pack("<HIH", 0x100, table_offset, 1)
            + record_payload + struct.pack("<HHHII", 1, 0, 0, 12, len(record_payload)))


class LevelDiscriminatorShapeTests(unittest.TestCase):
    def test_aggregates_dimensions_by_raw_discriminator(self):
        entries, trailing = measure(srsc(payload([(2, 3, 0), (0, 5, 2), (4, 0, 2)])))
        self.assertEqual(trailing, 0)
        self.assertEqual(summarize(entries), {
            "0": {"entries": 1, "zero_width": 0, "zero_height": 0, "zero_area": 0,
                  "grid_items": 12, "cell_items": 6, "max_width": 2, "max_height": 3},
            "2": {"entries": 2, "zero_width": 1, "zero_height": 1, "zero_area": 2,
                  "grid_items": 11, "cell_items": 0, "max_width": 4, "max_height": 5},
        })

    def test_rejects_truncation_limits_and_bad_selected_range(self):
        data = payload([(2, 3, 0)])
        for size in range(len(data) - 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode(data[:size])
        with self.assertRaisesRegex(ValueError, "dimension"):
            decode(payload([(32 * 1024 * 1024 + 1, 1, 0)]))
        overlapping = b"SRSC" + struct.pack("<HIH", 0x100, 12, 1) + struct.pack("<HHHII", 1, 0, 0, 12, 1)
        with self.assertRaisesRegex(ValueError, "overlaps"):
            measure(overlapping)


if __name__ == "__main__":
    unittest.main()
