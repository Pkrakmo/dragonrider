#!/usr/bin/env python3
"""Measure aligned audio-track boundaries and terminal silence; print metadata only.

The fixed offset is a previously observed hypothesis, not estimated here. CUE and
BIN inputs are opened read-only. Requires numpy and the project's CUE parser.
"""
import argparse
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'disc'))
from compare_audio import SECTOR, file_sha256, parse_cue  # noqa: E402

FRAME_BYTES = 4
CHUNK = 262144


def frame_metrics(a, b):
    """Report aggregate differences and RMS; no sample values are exported."""
    if a.shape != b.shape or a.ndim != 2 or a.shape[1] != 2:
        raise ValueError('Aligned frame ranges must have equal stereo shapes')
    different = nonzero_a = nonzero_b = peak_a = peak_b = sum_a = sum_b = 0
    first = last = None
    for i in range(0, len(a), CHUNK):
        left = a[i:i + CHUNK].astype(np.int32)
        right = b[i:i + CHUNK].astype(np.int32)
        pos = np.flatnonzero(np.any(left != right, axis=1))
        different += len(pos)
        if len(pos):
            if first is None:
                first = i + int(pos[0])
            last = i + int(pos[-1])
        nonzero_a += int(np.count_nonzero(left))
        nonzero_b += int(np.count_nonzero(right))
        if left.size:
            peak_a = max(peak_a, int(np.max(np.abs(left))))
            peak_b = max(peak_b, int(np.max(np.abs(right))))
        sum_a += int(np.sum(left.astype(np.int64) ** 2))
        sum_b += int(np.sum(right.astype(np.int64) ** 2))
    samples = len(a) * 2
    return {'frames': len(a), 'different_frames': int(different),
            'first_different_frame': first, 'last_different_frame': last,
            'nonzero_channel_samples': [nonzero_a, nonzero_b],
            'peak_absolute_sample': [peak_a, peak_b],
            'rms_sample': [(v / samples) ** 0.5 if samples else 0.0 for v in (sum_a, sum_b)]}


def trailing_zero_frames(a):
    count = 0
    for end in range(len(a), 0, -CHUNK):
        start = max(0, end - CHUNK)
        positions = np.flatnonzero(np.any(a[start:end] != 0, axis=1))
        if len(positions):
            return count + end - start - 1 - int(positions[-1])
        count += end - start
    return count


def compare(cue_a, cue_b, offset=673):
    if offset < 0:
        raise ValueError('This boundary analysis requires a nonnegative offset')
    cues = [Path(cue_a), Path(cue_b)]
    track_lists = [parse_cue(c) for c in cues]
    audio = [[t for t in tracks if t['mode'] == 'AUDIO'] for tracks in track_lists]
    if not audio[0] or [t['number'] for t in audio[0]] != [t['number'] for t in audio[1]]:
        raise ValueError('Audio track numbers differ or are empty')
    for tracks in track_lists:
        indices = [i for i, t in enumerate(tracks) if t['mode'] == 'AUDIO']
        numbers = [tracks[i]['number'] for i in indices]
        if any(b != a + 1 for a, b in zip(indices, indices[1:])) or any(
                b != a + 1 for a, b in zip(numbers, numbers[1:])):
            raise ValueError('Boundary comparison requires consecutive AUDIO tracks')
    maps = [[], []]
    inputs = []
    for n, (ta, tb) in enumerate(zip(*audio)):
        pair = []
        for side, t in enumerate((ta, tb)):
            path = cues[side].parent / t['file']
            size = path.stat().st_size
            if size == 0 or size % SECTOR or any(index > size for index in t['indexes'].values()):
                raise ValueError('Bad track length or CUE index')
            maps[side].append(np.memmap(path, dtype='<i2', mode='r').reshape(-1, 2))
            pair.append({'name': t['file'], 'bytes': size, 'sha256': file_sha256(path),
                         'index_01_frame': t['indexes'][1] // FRAME_BYTES})
        if pair[0]['bytes'] != pair[1]['bytes'] or pair[0]['index_01_frame'] != pair[1]['index_01_frame']:
            raise ValueError('Track lengths or INDEX 01 positions differ')
        if offset > min(pair[0]['bytes'] // FRAME_BYTES, pair[0]['index_01_frame']):
            raise ValueError('Offset exceeds track or pregap')
        inputs.append({'track': ta['number'], 'files': pair})
    result = {'numpy_version': np.__version__, 'sample_interpretation': 'signed 16-bit little-endian stereo',
              'alignment_assumption_b_minus_a_frames': offset,
              'cues': [{'path': str(c), 'sha256': file_sha256(c)} for c in cues], 'inputs': inputs,
              'tracks': [], 'boundaries': []}
    for index, pair in enumerate(inputs):
        a, b = maps[0][index], maps[1][index]
        start = pair['files'][0]['index_01_frame']
        end = len(a) - offset
        result['tracks'].append({'track': pair['track'],
                                 'pregap_overlap': frame_metrics(a[:start], b[offset:offset + start]),
                                 'program_overlap': frame_metrics(a[start:end], b[start + offset:])})
        if index + 1 < len(inputs):
            # The selected offset extends the A track's end into B's next track.
            boundary = frame_metrics(a[end:], maps[1][index + 1][:offset])
            result['boundaries'].append({'from_track': pair['track'], 'to_track': inputs[index + 1]['track'], **boundary})
    a, b = maps[0][-1], maps[1][-1]
    trailing = trailing_zero_frames(a)
    overlap_end = len(a) - offset
    overlap_start = min(overlap_end, len(a) - trailing)
    result['terminal'] = {'track': inputs[-1]['track'], 'a_trailing_zero_frames': trailing,
                          'b_trailing_zero_frames': trailing_zero_frames(b),
                          'a_tail_start_file_frame': len(a) - trailing,
                          'a_tail_compared_overlap': frame_metrics(a[overlap_start:overlap_end], b[overlap_start + offset:]),
                          'a_tail_aligned_half_second_windows': [
                              frame_metrics(a[i:min(i + 22050, overlap_end)],
                                            b[i + offset:min(i + 22050, overlap_end) + offset])
                              for i in range(overlap_start, overlap_end, 22050)],
                          'a_unpaired_final_frames': offset}
    result['unpaired'] = {'a_final_track': inputs[-1]['track'], 'a_final_frames': offset,
                          'b_initial_track': inputs[0]['track'], 'b_initial_frames': offset,
                          'initial_track_leading_zero_frames': [
                              trailing_zero_frames(maps[side][0][::-1]) for side in (0, 1)]}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cue_a', type=Path)
    parser.add_argument('cue_b', type=Path)
    parser.add_argument('--offset', type=int, default=673, help='assumed B minus A frame offset (default: 673)')
    args = parser.parse_args()
    print(json.dumps(compare(args.cue_a, args.cue_b, args.offset), indent=2))


if __name__ == '__main__':
    main()
