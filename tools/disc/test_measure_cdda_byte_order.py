import hashlib
from pathlib import Path
import tempfile
import unittest

import numpy as np

from measure_cdda_byte_order import (highband_ratio, measure,
                                     parse_sha256_manifest, verified_snapshot)


def audio_fixture():
    frames = np.arange(588, dtype=np.float64)
    signal = np.rint(7000 * np.sin(2 * np.pi * 440 * frames / 44100)).astype('<i2')
    return np.column_stack((signal, signal)).astype('<i2').tobytes()


class CddaByteOrderTests(unittest.TestCase):
    def test_lowpass_pcm_shape_favors_its_encoded_endian(self):
        data = audio_fixture()
        little = highband_ratio(data, '<i2', 500)
        big = highband_ratio(data, '>i2', 500)
        self.assertLess(little, 1e-8)
        self.assertGreater(big, 0.01)

    def test_rejects_unaligned_short_and_silent_windows(self):
        with self.assertRaisesRegex(ValueError, 'byte order'):
            highband_ratio(bytes(2352), '=i2', 588)
        with self.assertRaisesRegex(ValueError, 'frame aligned'):
            highband_ratio(b'abc', '<i2', 1)
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            highband_ratio(bytes(8), '<i2', 3)
        with self.assertRaisesRegex(ValueError, 'one-second'):
            highband_ratio(bytes(2352), '<i2', 44101)
        with self.assertRaisesRegex(ValueError, 'no finite audible'):
            highband_ratio(bytes(2352), '<i2', 588)

    def test_manifest_validation_and_verified_input_snapshots(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cue_data = b'FILE "audio.bin" BINARY\nTRACK 02 AUDIO\nINDEX 01 00:00:00\n'
            audio = audio_fixture()
            cue = root / 'audio.cue'
            binary = root / 'audio.bin'
            cue.write_bytes(cue_data)
            binary.write_bytes(audio)
            lines = [f'{hashlib.sha256(data).hexdigest()}  {path.resolve()}'
                     for path, data in ((cue, cue_data), (binary, audio))]
            manifest_bytes = ('\n'.join(lines) + '\n').encode()
            manifest = parse_sha256_manifest(manifest_bytes)
            self.assertEqual(len(manifest), 2)
            hash_file = root / 'hashes.sha256'
            hash_file.write_bytes(manifest_bytes)
            result = measure((cue, cue), hash_file, sample_frames=500)
            self.assertTrue(result['input_hashes_verified'])
            self.assertFalse(result['sample_bytes_emitted'])
            self.assertEqual(result['editions'][0]['audio_tracks'], 1)
            self.assertEqual(result['editions'][1]['audio_tracks'], 1)
            self.assertEqual(result['editions'][0]['candidate_windows'], 1)
            self.assertLess(result['editions'][0]['ratios']['little_endian']['median'],
                            result['editions'][0]['ratios']['big_endian']['median'])
            grid = measure((cue, cue), hash_file, sample_frames=500, windows_per_track=5)
            self.assertEqual(grid['editions'][0]['candidate_windows'], 5)
            self.assertEqual(grid['editions'][0]['little_endian_lower_windows'], 5)
            self.assertEqual(grid['editions'][0]['ratios']['little_endian']['samples'], 5)
            self.assertLess(grid['editions'][0]['ratios']['little_endian']['median'],
                            grid['editions'][0]['ratios']['big_endian']['median'])
            for invalid_paths in ((), (cue,), (cue, cue, cue)):
                with self.assertRaisesRegex(ValueError, 'exactly two CUE paths'):
                    measure(invalid_paths, hash_file, sample_frames=500)
            for invalid in (0, 2, 10, True):
                with self.assertRaisesRegex(ValueError, 'odd integer'):
                    measure((cue, cue), hash_file, sample_frames=500,
                            windows_per_track=invalid)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                parse_sha256_manifest(manifest_bytes + lines[0].encode() + b'\n')
            with self.assertRaisesRegex(ValueError, 'invalid sha256sum'):
                parse_sha256_manifest(b'bad entry\n')
            with self.assertRaisesRegex(ValueError, 'invalid sha256sum'):
                parse_sha256_manifest(b'\\' + lines[0].encode() + b'\n')

    def test_rejects_unlisted_or_mutated_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cue = root / 'audio.cue'
            cue.write_text('FILE "audio.bin" BINARY\nTRACK 02 AUDIO\nINDEX 01 00:00:00\n')
            binary = root / 'audio.bin'
            binary.write_bytes(audio_fixture())
            cue_entry = f'{hashlib.sha256(cue.read_bytes()).hexdigest()}  {cue.resolve()}\n'
            binary_entry = f'{hashlib.sha256(binary.read_bytes()).hexdigest()}  {binary.resolve()}\n'
            manifest = root / 'hashes.sha256'
            manifest.write_text(cue_entry + binary_entry)
            binary.write_bytes(bytes(2352))
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                measure((cue, cue), manifest, sample_frames=500)

    def test_rejects_symlinked_input_component(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / 'real'
            real.mkdir()
            target = real / 'source.bin'
            target.write_bytes(audio_fixture())
            link = root / 'linked'
            link.symlink_to(real, target_is_directory=True)
            entry = f'{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.resolve()}\n'
            with self.assertRaisesRegex(ValueError, 'symlink'):
                verified_snapshot(link / 'source.bin', parse_sha256_manifest(entry.encode()))
            with self.assertRaisesRegex(ValueError, 'traversal'):
                verified_snapshot(Path('nested/../source.bin'), {})


if __name__ == '__main__':
    unittest.main()
