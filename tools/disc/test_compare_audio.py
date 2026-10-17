import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import compare_audio as c


class AudioComparisonTest(unittest.TestCase):
    def test_offset_and_changed_frame(self):
        randomizer = random.Random(1234)
        source = randomizer.randbytes(20_000)
        target = b'\x00' * 28 + source[:-28]
        self.assertEqual(c.anchors(source, target)['offset_frames'], 7)
        self.assertEqual(c.metrics(source, target, 7)['different_frames'], 0)
        changed = bytearray(target)
        changed[17_000] ^= 1
        self.assertEqual(c.metrics(source, bytes(changed), 7)['different_frames'], 1)
        self.assertGreater(c.metrics(source, target, 0)['different_frames'], 0)
        self.assertEqual(c.anchors(target, source)['offset_frames'], -7)

    def test_silence_and_no_exact_match(self):
        self.assertIsNone(c.anchors(bytes(20_000), bytes(20_000))['offset_frames'])
        a = random.Random(1).randbytes(20_000)
        b = random.Random(2).randbytes(20_000)
        self.assertIsNone(c.anchors(a, b)['offset_frames'])

    def test_cue_indexes_and_invalid_layout(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'a.bin').write_bytes(bytes(c.SECTOR * 3))
            (root / 'b.bin').write_bytes(bytes(c.SECTOR * 4))
            cue_a, cue_b = root / 'a.cue', root / 'b.cue'
            cue_a.write_text('FILE "a.bin" BINARY\n TRACK 02 AUDIO\n INDEX 00 00:00:00\n INDEX 01 00:00:01\n')
            cue_b.write_text('FILE "b.bin" BINARY\n TRACK 02 AUDIO\n INDEX 00 00:00:00\n INDEX 01 00:00:02\n')
            report = c.compare(cue_a, cue_b)['tracks'][0]
            self.assertEqual(report['index_01_comparison']['overlap_frames'], 2 * 588)
            self.assertEqual(report['inputs'][1]['index_01_bytes'], 2 * c.SECTOR)
            cue_b.write_text('FILE "b.bin" BINARY\n TRACK 02 AUDIO\n INDEX 01 00:01:00\n')
            with self.assertRaises(ValueError):
                c.compare(cue_a, cue_b)
            cue_b.write_text('FILE "../b.bin" BINARY\n TRACK 02 AUDIO\n INDEX 01 00:00:00\n')
            with self.assertRaises(ValueError):
                c.parse_cue(cue_b)
            cue_b.write_text('FILE "b.bin" BINARY\n TRACK 02 AUDIO\n PREGAP 00:02:00\n INDEX 01 00:00:00\n')
            with self.assertRaises(ValueError):
                c.parse_cue(cue_b)

    def test_output_cannot_overwrite_input_or_hardlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            original = root / 'a.bin'
            original.write_bytes(bytes(c.SECTOR))
            cue = root / 'a.cue'
            cue.write_text('FILE "a.bin" BINARY\n TRACK 02 AUDIO\n INDEX 01 00:00:00\n')
            link = root / 'alias'
            link.hardlink_to(original)
            for output in (cue, original, link):
                run = subprocess.run([sys.executable, str(Path(c.__file__)), str(cue), str(cue), str(output)], capture_output=True)
                self.assertNotEqual(run.returncode, 0)
            self.assertEqual(original.read_bytes(), bytes(c.SECTOR))
            self.assertIn('FILE', cue.read_text())


if __name__ == '__main__':
    unittest.main()
