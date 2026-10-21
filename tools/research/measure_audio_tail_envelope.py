#!/usr/bin/env python3
"""Summarize short-window RMS for the aligned Europe tail after US silence starts."""
import argparse
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'disc'))
from compare_audio import SECTOR, file_sha256, parse_cue  # noqa: E402
from audio_tail_analysis import trailing_zero_frames  # noqa: E402

FRAME_BYTES = 4
MAX_WINDOW_FRAMES = 441000  # Ten seconds at 44.1 kHz; bounds temporary RMS arrays.


def summarize_rms(samples, window_frames):
    """Return windowed stereo RMS summaries without exporting sample values."""
    if (samples.ndim != 2 or samples.shape[1] != 2 or window_frames <= 0
            or window_frames > MAX_WINDOW_FRAMES
            or len(samples) == 0):
        raise ValueError('Expected non-empty stereo samples and window in 1..441000 frames')
    values = []
    for start in range(0, len(samples), window_frames):
        part = samples[start:start + window_frames].astype(np.int64)
        values.append(float(np.sqrt(np.mean(part * part))))
    steps = np.diff(values)
    return {'window_frames': window_frames, 'windows': len(values),
            'last_window_frames': len(samples) % window_frames or window_frames,
            'window_rms': values,
            'first_window_rms': values[0], 'last_window_rms': values[-1],
            'minimum_window_rms': min(values), 'maximum_window_rms': max(values),
            'decreasing_transitions': int(np.count_nonzero(steps < 0)),
            'increasing_transitions': int(np.count_nonzero(steps > 0)),
            'equal_transitions': int(np.count_nonzero(steps == 0))}


def compare(cue_us, cue_eu, offset=673, window_frames=4410):
    cues = [Path(cue_us), Path(cue_eu)]
    tracks = [[t for t in parse_cue(cue) if t['mode'] == 'AUDIO'] for cue in cues]
    if not tracks[0] or not tracks[1] or tracks[0][-1]['number'] != tracks[1][-1]['number']:
        raise ValueError('Final AUDIO track numbers differ or are missing')
    pair = []
    for cue, audio in zip(cues, tracks):
        track = audio[-1]
        path = cue.parent / track['file']
        size = path.stat().st_size
        index01 = track['indexes'][1] // FRAME_BYTES
        if size == 0 or size % SECTOR or track['indexes'][1] > size:
            raise ValueError('Bad final track length or INDEX 01')
        pair.append({'track': track['number'], 'path': path, 'size': size,
                     'index01': index01, 'sha256': file_sha256(path),
                     'samples': np.memmap(path, dtype='<i2', mode='r').reshape(-1, 2)})
    if pair[0]['size'] != pair[1]['size'] or pair[0]['index01'] != pair[1]['index01']:
        raise ValueError('Final track sizes or INDEX 01 positions differ')
    if offset < 0 or offset > pair[0]['index01'] or offset > len(pair[1]['samples']):
        raise ValueError('Invalid alignment offset')

    us, europe = pair[0]['samples'], pair[1]['samples']
    zero_tail = trailing_zero_frames(us)
    start = len(us) - zero_tail
    end = len(us) - offset
    if (zero_tail == 0 or start < pair[0]['index01'] or start >= end
            or end + offset > len(europe)):
        raise ValueError('No US zero-tail overlap in final program region under alignment')
    aligned_europe_tail = europe[start + offset:end + offset]
    return {'method': 'signed 16-bit little-endian stereo; no normalization',
            'sample_rate_hz': 44100,
            'track': pair[0]['track'], 'alignment_assumption_europe_minus_us_frames': offset,
            'cues': [{'path': str(cue), 'sha256': file_sha256(cue)} for cue in cues],
            'us_track': {'path': str(pair[0]['path']), 'bytes': pair[0]['size'],
                         'sha256': pair[0]['sha256']},
            'europe_track': {'path': str(pair[1]['path']), 'bytes': pair[1]['size'],
                             'sha256': pair[1]['sha256']},
            'us_zero_tail_start_file_frame': start,
            'aligned_tail_frames': end - start,
            'aligned_tail_rms': summarize_rms(aligned_europe_tail, window_frames)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('us_cue', type=Path)
    parser.add_argument('europe_cue', type=Path)
    parser.add_argument('--offset', type=int, default=673)
    parser.add_argument('--window-frames', type=int, default=4410)
    args = parser.parse_args()
    print(json.dumps(compare(args.us_cue, args.europe_cue, args.offset,
                             args.window_frames), indent=2))


if __name__ == '__main__':
    main()
