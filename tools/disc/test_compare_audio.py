import hashlib
import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_compare_hashes_and_measures_one_snapshot_per_input(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cue_a, cue_b = root / 'a.cue', root / 'b.cue'
            bin_a, bin_b = root / 'a.bin', root / 'b.bin'
            data_a, data_b = bytes(c.SECTOR * 2), bytes(c.SECTOR * 2)
            bin_a.write_bytes(data_a)
            bin_b.write_bytes(data_b)
            cue_a.write_text('FILE "a.bin" BINARY\n TRACK 02 AUDIO\n INDEX 01 00:00:00\n')
            cue_b.write_text('FILE "b.bin" BINARY\n TRACK 02 AUDIO\n INDEX 01 00:00:00\n')
            originals = {path: path.read_bytes() for path in (cue_a, cue_b, bin_a, bin_b)}
            counts = {}
            original_read_bytes = Path.read_bytes

            def counted_read(path):
                resolved = path.resolve()
                counts[resolved] = counts.get(resolved, 0) + 1
                return original_read_bytes(path)

            with patch.object(Path, 'read_bytes', counted_read):
                report = c.compare(cue_a, cue_b)
            self.assertEqual(counts, {path.resolve(): 1 for path in originals})
            self.assertIn('source BIN byte order unverified', report['sample_interpretation'])
            self.assertEqual(report['cues'][0]['sha256'], hashlib.sha256(originals[cue_a]).hexdigest())
            self.assertEqual(report['tracks'][0]['inputs'][0]['sha256'],
                             hashlib.sha256(originals[bin_a]).hexdigest())
            self.assertEqual(report['tracks'][0]['index_01_comparison']['different_frames'], 0)

    def test_rejects_symlinked_cue_member(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            outside = root / 'outside'
            inside = root / 'inside'
            outside.mkdir()
            inside.mkdir()
            (outside / 'audio.bin').write_bytes(bytes(c.SECTOR))
            cue_a, cue_b = inside / 'a.cue', inside / 'b.cue'
            (inside / 'local.bin').write_bytes(bytes(c.SECTOR))
            (inside / 'linked.bin').symlink_to(outside / 'audio.bin')
            cue_a.write_text('FILE "linked.bin" BINARY\nTRACK 02 AUDIO\nINDEX 01 00:00:00\n')
            cue_b.write_text('FILE "local.bin" BINARY\nTRACK 02 AUDIO\nINDEX 01 00:00:00\n')
            with self.assertRaisesRegex(ValueError, 'symlinks'):
                c.compare(cue_a, cue_b)

    def test_rejects_symlinked_directory_component(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            outside = root / 'outside'
            inside = root / 'inside'
            outside.mkdir()
            inside.mkdir()
            (outside / 'audio.bin').write_bytes(bytes(c.SECTOR))
            (inside / 'local.bin').write_bytes(bytes(c.SECTOR))
            (inside / 'linked').symlink_to(outside, target_is_directory=True)
            cue_a, cue_b = inside / 'a.cue', inside / 'b.cue'
            cue_a.write_text('FILE "linked/audio.bin" BINARY\nTRACK 02 AUDIO\nINDEX 01 00:00:00\n')
            cue_b.write_text('FILE "local.bin" BINARY\nTRACK 02 AUDIO\nINDEX 01 00:00:00\n')
            with self.assertRaisesRegex(ValueError, 'symlinks'):
                c.compare(cue_a, cue_b)

    def test_cli_validates_and_compares_the_same_cue_snapshots(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cue_a, cue_b = root / 'a.cue', root / 'b.cue'
            bin_a, bin_b = root / 'a.bin', root / 'b.bin'
            output = root / 'report.json'
            bin_a.write_bytes(bytes(c.SECTOR))
            bin_b.write_bytes(bytes(c.SECTOR))
            cue_a.write_text('FILE "a.bin" BINARY\n TRACK 02 AUDIO\n INDEX 01 00:00:00\n')
            cue_b.write_text('FILE "b.bin" BINARY\n TRACK 02 AUDIO\n INDEX 01 00:00:00\n')
            counts = {}
            original_read_bytes = Path.read_bytes

            def counted_read(path):
                resolved = path.resolve()
                counts[resolved] = counts.get(resolved, 0) + 1
                return original_read_bytes(path)

            with patch.object(Path, 'read_bytes', counted_read), \
                    patch.object(sys, 'argv', ['compare_audio.py', str(cue_a), str(cue_b), str(output)]):
                c.main()
            self.assertEqual(counts, {path.resolve(): 1 for path in (cue_a, cue_b, bin_a, bin_b)})
            report = json.loads(output.read_text())
            self.assertIn('source BIN byte order unverified', report['sample_interpretation'])
            self.assertEqual(report['tracks'][0]['index_01_comparison']['different_frames'], 0)

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
