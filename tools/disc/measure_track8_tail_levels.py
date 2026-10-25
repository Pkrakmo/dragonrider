#!/usr/bin/env python3
"""Measure aggregate level bounds for the aligned nonzero Europe track-8 tail.

The result contains hashes and aggregate amplitudes only, never sample bytes.
Numeric values assume signed little-endian PCM; CUE metadata does not prove that
byte order.  Inputs must be listed in a SHA-256 manifest and are read only.
"""
import argparse
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_audio import FRAME, SECTOR, parse_cue_bytes, resolve_cue_file  # noqa: E402
from measure_cdda_byte_order import parse_sha256_manifest, verified_snapshot  # noqa: E402

SAMPLE_RATE = 44100
MAX_WINDOW_FRAMES = SAMPLE_RATE * 10


def trailing_zero_frames(values):
    """Return complete stereo frames of exact zero at the end of a byte snapshot."""
    if len(values) % FRAME:
        raise ValueError('audio data is not stereo-frame aligned')
    words = np.frombuffer(values, dtype='<i2').reshape(-1, 2)
    nonzero = np.flatnonzero(np.any(words != 0, axis=1))
    return len(words) if not len(nonzero) else len(words) - 1 - int(nonzero[-1])


def dbfs(value, reference=32768.0):
    return None if value <= 0 else 20.0 * math.log10(value / reference)


def summarize(values, window_frames):
    """Compute bounded per-window level aggregates without retaining samples."""
    if len(values) == 0 or type(window_frames) is not int or not 0 < window_frames <= MAX_WINDOW_FRAMES:
        raise ValueError('window frames must be in 1..441000 and values non-empty')
    rms, peaks = [], []
    for start in range(0, len(values), window_frames):
        part = values[start:start + window_frames].astype(np.int64)
        rms.append(float(np.sqrt(np.mean(part * part))))
        peaks.append(int(np.max(np.abs(part))))
    # These are signal-level bounds, not auditory thresholds or loudness estimates.
    thresholds = (-60.0, -50.0, -40.0, -30.0)
    return {
        'window_frames': window_frames,
        'windows': len(rms),
        'last_window_frames': len(values) % window_frames or window_frames,
        'rms_dbfs_first_last_min_max': [dbfs(rms[0]), dbfs(rms[-1]), dbfs(min(rms)), dbfs(max(rms))],
        'peak_dbfs_first_last_min_max': [dbfs(peaks[0]), dbfs(peaks[-1]), dbfs(min(peaks)), dbfs(max(peaks))],
        'rms_windows_at_or_above_dbfs': {
            str(threshold): int(sum(dbfs(value) is not None and dbfs(value) >= threshold for value in rms))
            for threshold in thresholds},
        'nonzero_channel_samples': int(np.count_nonzero(values)),
        'channel_samples': int(values.size),
    }


def measure(cue_us, cue_europe, manifest_path, offset=673, window_frames=4410):
    if type(offset) is not int or offset < 0:
        raise ValueError('offset must be a nonnegative integer')
    manifest = parse_sha256_manifest(Path(manifest_path).read_bytes())
    cues = (Path(cue_us), Path(cue_europe))
    cue_bytes = [verified_snapshot(path, manifest) for path in cues]
    track_lists = [parse_cue_bytes(data) for data in cue_bytes]
    finals = []
    for cue, tracks in zip(cues, track_lists):
        audio = [track for track in tracks if track['mode'] == 'AUDIO']
        if not audio:
            raise ValueError('CUE has no AUDIO track')
        finals.append(audio[-1])
    if finals[0]['number'] != finals[1]['number']:
        raise ValueError('final AUDIO track numbers differ')
    paths = [resolve_cue_file(cue, track['file']) for cue, track in zip(cues, finals)]
    raw = [verified_snapshot(path, manifest) for path in paths]
    starts = [track['indexes'][1] for track in finals]
    if (any(len(data) % SECTOR for data in raw) or any(start > len(data) for start, data in zip(starts, raw))
            or len(raw[0]) != len(raw[1]) or starts[0] != starts[1]):
        raise ValueError('final AUDIO track size or INDEX 01 is incompatible')
    programs = [data[start:] for data, start in zip(raw, starts)]
    zero_tail = trailing_zero_frames(programs[0])
    cutoff = len(programs[0]) // FRAME - zero_tail
    overlap_end = len(programs[0]) // FRAME - offset
    if zero_tail == 0 or cutoff >= overlap_end:
        raise ValueError('US program has no aligned trailing zero region')
    europe_tail = np.frombuffer(programs[1], dtype='<i2').reshape(-1, 2)[cutoff + offset:overlap_end + offset]
    return {
        'method': 'signed 16-bit little-endian stereo, fixed non-overlapping level windows; no normalization',
        'byte_order_caveat': 'CUE/BIN provenance does not independently establish sample byte order; raw zero-frame boundaries do not depend on it.',
        'sample_rate_hz': SAMPLE_RATE,
        'input_hashes_verified': True,
        'sample_bytes_emitted': False,
        'track': finals[0]['number'],
        'alignment_assumption_europe_minus_us_frames': offset,
        'us_zero_tail_frames': zero_tail,
        'aligned_europe_tail_frames': len(europe_tail),
        'cues': [{'sha256': __import__('hashlib').sha256(data).hexdigest()} for data in cue_bytes],
        'tracks': [{'bytes': len(data), 'sha256': __import__('hashlib').sha256(data).hexdigest()} for data in raw],
        'europe_tail_level_bounds': summarize(europe_tail, window_frames),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('us_cue', type=Path)
    parser.add_argument('europe_cue', type=Path)
    parser.add_argument('sha256_manifest', type=Path)
    parser.add_argument('--offset', type=int, default=673)
    parser.add_argument('--window-frames', type=int, default=4410)
    args = parser.parse_args()
    print(json.dumps(measure(args.us_cue, args.europe_cue, args.sha256_manifest,
                             args.offset, args.window_frames), indent=2))


if __name__ == '__main__':
    main()
