import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_track8_tail_levels import measure, summarize, trailing_zero_frames


class Track8TailLevelsTests(unittest.TestCase):
    def test_zero_tail_and_level_summary(self):
        values = np.array([[4, -4], [0, 0], [0, 0]], dtype='<i2').tobytes()
        self.assertEqual(trailing_zero_frames(values), 2)
        summary = summarize(np.array([[32767, -32767], [1, -1]], dtype=np.int16), 1)
        self.assertEqual(summary['windows'], 2)
        self.assertEqual(summary['rms_windows_at_or_above_dbfs']['-30.0'], 1)

    def test_measure_hashes_cue_and_final_track_without_samples(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cues = []
            frames = 588
            us = np.full((frames, 2), 100, dtype='<i2')
            us[-300:] = 0
            eu = np.full((frames, 2), 100, dtype='<i2')
            eu[-297:] = (32, -32)
            for label, data in (('us', us), ('eu', eu)):
                folder = root / label
                folder.mkdir()
                binary = folder / 'track.bin'
                binary.write_bytes(data.tobytes())
                cue = folder / 'disc.cue'
                cue.write_text('FILE "track.bin" BINARY\nTRACK 08 AUDIO\nINDEX 01 00:00:00\n')
                cues.append(cue)
            entries = []
            for path in (*cues, *(cue.parent / 'track.bin' for cue in cues)):
                entries.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.resolve()}')
            manifest = root / 'hashes.sha256'
            manifest.write_text('\n'.join(entries) + '\n')
            result = measure(*cues, manifest, offset=3, window_frames=100)
            self.assertTrue(result['input_hashes_verified'])
            self.assertFalse(result['sample_bytes_emitted'])
            self.assertEqual(result['us_zero_tail_frames'], 300)
            self.assertEqual(result['aligned_europe_tail_frames'], 297)
            self.assertEqual(result['europe_tail_level_bounds']['nonzero_channel_samples'], 594)

    def test_rejects_unverified_input_and_invalid_window(self):
        with self.assertRaises(ValueError):
            summarize(np.ones((1, 2), dtype=np.int16), 0)


if __name__ == '__main__':
    unittest.main()
