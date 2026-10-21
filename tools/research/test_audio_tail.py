#!/usr/bin/env python3
"""Synthetic tests for track-tail and cross-track measurements."""
import tempfile
import unittest
from pathlib import Path

import numpy as np

import audio_tail_analysis as audio


class AudioTailTests(unittest.TestCase):
    def test_metrics_and_silent_suffix(self):
        a = np.array([[0, 0], [-32768, 4], [0, 0]], dtype=np.int16)
        b = np.array([[0, 0], [4, -5], [2, 0]], dtype=np.int16)
        result = audio.frame_metrics(a, b)
        self.assertEqual(result['different_frames'], 2)
        self.assertEqual((result['first_different_frame'], result['last_different_frame']), (1, 2))
        self.assertEqual(result['peak_absolute_sample'], [32768, 5])
        self.assertEqual(audio.trailing_zero_frames(a), 1)
        self.assertEqual(audio.trailing_zero_frames(np.zeros((audio.CHUNK + 1, 2), dtype=np.int16)), audio.CHUNK + 1)
        with self.assertRaises(ValueError):
            audio.frame_metrics(a, b[:2])

    def test_cutoff_steps_and_bounds(self):
        a = np.array([[1, -1], [3, -3], [8, -8], [0, 0]], dtype=np.int16)
        b = np.array([[9, 9], [1, -1], [3, -3], [8, -8], [9, -7]], dtype=np.int16)
        result = audio.cutoff_transition(a, b, 3, 1, window=2)
        self.assertEqual(result['preceding_frames'], 2)
        self.assertEqual(result['boundary_absolute_step'], [[8, 8], [1, 1]])
        self.assertEqual(result['preceding_steps_at_least_boundary'], [[0, 0], [2, 2]])
        self.assertEqual(result['preceding_aligned_frames_different'], 0)
        with self.assertRaises(ValueError):
            audio.cutoff_transition(a, b, 0, 1)
        with self.assertRaises(ValueError):
            audio.cutoff_transition(a, b, 3, 2)
        with self.assertRaises(ValueError):
            audio.cutoff_transition(a, b, 3, 1, window=0)

    def test_synthetic_cues_cross_boundary_and_tail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            frames = 1176
            src = np.arange(frames * 2 * 2, dtype=np.int16).reshape(-1, 2) + 1
            src[-588:] = 0
            target = np.zeros_like(src)
            target[3:] = src[:-3]
            target[-585:] = [100, -100]
            paths = []
            for name, samples in [('a', src), ('b', target)]:
                directory = root / name
                directory.mkdir()
                for i in range(2):
                    (directory / f'{i}.bin').write_bytes(samples[i * frames:(i + 1) * frames].astype('<i2').tobytes())
                cue = directory / 'disc.cue'
                cue.write_text(''.join(f'FILE "{i}.bin" BINARY\n TRACK {i + 2:02} AUDIO\n INDEX 00 00:00:00\n INDEX 01 00:00:01\n' for i in range(2)))
                paths.append(cue)
            result = audio.compare(*paths, offset=3)
            self.assertEqual(result['tracks'][0]['pregap_overlap']['different_frames'], 0)
            self.assertEqual(result['tracks'][0]['program_overlap']['different_frames'], 0)
            self.assertEqual(result['boundaries'][0]['different_frames'], 0)
            self.assertEqual(result['terminal']['a_trailing_zero_frames'], 588)
            self.assertEqual(result['terminal']['a_tail_compared_overlap']['frames'], 585)
            self.assertEqual(result['terminal']['a_tail_compared_overlap']['different_frames'], 585)
            cutoff = result['terminal']['cutoff_transition']
            self.assertEqual(cutoff['preceding_aligned_frames_different'], 0)
            expected_steps = np.abs(target[-585].astype(np.int32) - target[-586].astype(np.int32))
            self.assertEqual(cutoff['boundary_absolute_step'][1], expected_steps.tolist())
            self.assertEqual(result['unpaired']['b_initial_track'], 2)
            self.assertEqual(result['unpaired']['a_final_track'], 3)
            self.assertEqual(result['unpaired']['initial_track_leading_zero_frames'], [0, 3])
            with self.assertRaises(ValueError):
                audio.compare(*paths, offset=589)
            with self.assertRaises(ValueError):
                audio.compare(*paths, offset=-1)


if __name__ == '__main__':
    unittest.main()
