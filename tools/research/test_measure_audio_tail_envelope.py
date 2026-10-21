import tempfile
import unittest
from pathlib import Path

import numpy as np

from measure_audio_tail_envelope import compare, summarize_rms


class AudioTailEnvelopeTests(unittest.TestCase):
    def test_windowed_stereo_rms_and_partial_window(self):
        samples = np.array([[10, 10]] * 2 + [[5, 5]] * 2 + [[6, 6]], dtype=np.int16)
        result = summarize_rms(samples, 2)
        self.assertEqual(result['windows'], 3)
        self.assertEqual(result['last_window_frames'], 1)
        self.assertEqual(result['first_window_rms'], 10)
        self.assertEqual(result['last_window_rms'], 6)
        self.assertEqual(result['window_rms'], [10, 5, 6])
        self.assertEqual(result['decreasing_transitions'], 1)
        self.assertEqual(result['increasing_transitions'], 1)
        self.assertEqual(result['equal_transitions'], 0)

    def test_invalid_shape_empty_and_window(self):
        with self.assertRaises(ValueError):
            summarize_rms(np.array([1, 2], dtype=np.int16), 1)
        with self.assertRaises(ValueError):
            summarize_rms(np.empty((0, 2), dtype=np.int16), 1)
        with self.assertRaises(ValueError):
            summarize_rms(np.ones((1, 2), dtype=np.int16), 0)
        with self.assertRaises(ValueError):
            summarize_rms(np.ones((1, 2), dtype=np.int16), 441001)

    def test_cue_comparison_uses_final_program_tail_and_hashes_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            cues = []
            frames = 1176
            us = np.ones((frames, 2), dtype=np.int16)
            us[-588:] = 0
            europe = np.zeros_like(us)
            europe[3:] = us[:-3]
            europe[-585:] = (100, -100)
            for label, samples in (('us', us), ('eu', europe)):
                root = Path(temp) / label
                root.mkdir()
                (root / 'track.bin').write_bytes(samples.astype('<i2').tobytes())
                cue = root / 'disc.cue'
                cue.write_text('FILE "track.bin" BINARY\nTRACK 08 AUDIO\n'
                               'INDEX 00 00:00:00\nINDEX 01 00:00:01\n')
                cues.append(cue)
            result = compare(*cues, offset=3, window_frames=100)
            self.assertEqual(result['us_zero_tail_start_file_frame'], 588)
            self.assertEqual(result['aligned_tail_frames'], 585)
            self.assertEqual(result['aligned_tail_rms']['first_window_rms'], 100)
            self.assertEqual(result['aligned_tail_rms']['last_window_rms'], 100)
            self.assertEqual(len(result['cues']), 2)
            self.assertEqual(result['us_track']['bytes'], frames * 4)


if __name__ == '__main__':
    unittest.main()
