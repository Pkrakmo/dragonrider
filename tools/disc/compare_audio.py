#!/usr/bin/env python3
"""Compare separate-file CUE AUDIO tracks; interpret sample values as PCM.

Numeric samples assume signed 16-bit little-endian stereo; raw BIN byte order is
not established by CUE metadata. Requires numpy. Inputs are read only; output
contains no sample bytes.
Exact-anchor search detects a constant frame offset only where raw audio matches.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

import numpy as np

SECTOR = 2352
FRAME = 4


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def parse_cue_bytes(data):
    text = data.decode('utf-8-sig')
    files, current, track = [], None, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('REM ', 'TITLE ', 'PERFORMER ', 'CATALOG ')):
            continue
        match = re.fullmatch(r'FILE "([^"\r\n]+)" BINARY', line, re.I)
        if match:
            name = Path(match.group(1))
            if name.is_absolute() or '..' in name.parts:
                raise ValueError('CUE file must be a relative path inside its directory')
            current = {'file': str(name)}
            files.append(current)
            track = None
            continue
        match = re.fullmatch(r'TRACK (\d+) (AUDIO|MODE1/2352)', line, re.I)
        if match and current is not None and 'number' not in current:
            track = current
            track.update(number=int(match.group(1)), mode=match.group(2).upper(), indexes={})
            continue
        match = re.fullmatch(r'INDEX (\d+) (\d+):(\d+):(\d+)', line, re.I)
        if match and track is not None:
            ix, minute, second, frame = map(int, match.groups())
            if ix in track['indexes'] or second >= 60 or frame >= 75:
                raise ValueError('Invalid or duplicate CUE index')
            track['indexes'][ix] = (minute * 60 * 75 + second * 75 + frame) * SECTOR
            continue
        raise ValueError(f'Unsupported CUE directive or track layout: {line}')
    if not files or any('number' not in t or 1 not in t['indexes'] for t in files):
        raise ValueError('Each BINARY file must contain one track with INDEX 01')
    if len({t['number'] for t in files}) != len(files):
        raise ValueError('Duplicate track number')
    for t in files:
        if 0 in t['indexes'] and t['indexes'][0] > t['indexes'][1]:
            raise ValueError('INDEX 00 follows INDEX 01')
    return files


def parse_cue(path):
    return parse_cue_bytes(Path(path).read_bytes())


def resolve_cue_file(cue_path, name):
    """Resolve a CUE member without following links outside its directory."""
    cue_path = Path(cue_path)
    parent = cue_path.parent.resolve(strict=True)
    candidate = parent / name
    current = parent
    for part in Path(name).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f'CUE member must not contain symlinks: {name}')
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(parent)
    except ValueError as exc:
        raise ValueError(f'CUE member escapes its directory: {name}') from exc
    if not resolved.is_file():
        raise ValueError(f'CUE member must be a regular file: {name}')
    return resolved


def anchors(a, b):
    """Find common exact 64-byte anchors from three positions, on stereo frames."""
    candidates = []
    for numerator in (1, 2, 3):
        position = (len(a) * numerator // 4) // FRAME * FRAME
        # Skip low-information anchors (e.g. silence); search forward up to one second.
        end = min(len(a) - 64, position + 44100 * FRAME)
        while position <= end and len(set(a[position:position + 64])) < 20:
            position += FRAME
        if position > end:
            continue
        needle = a[position:position + 64]
        found = set()
        start = 0
        while True:
            p = b.find(needle, start)
            if p < 0:
                break
            if p % FRAME == 0:
                found.add((p - position) // FRAME)
                if len(found) > 100:
                    break
            start = p + 1
        if len(found) <= 100:
            candidates.append(found)
    if not candidates:
        return {'usable_anchors': 0, 'offset_frames': None}
    common = set.intersection(*candidates)
    return {'usable_anchors': len(candidates), 'offset_frames': next(iter(common)) if len(common) == 1 and len(candidates) >= 2 else None}


def metrics(a, b, offset):
    """Offset is B's frame index minus A's; only compare overlapping frames."""
    astart = max(0, -offset) * FRAME
    bstart = max(0, offset) * FRAME
    n = min(len(a) - astart, len(b) - bstart) // FRAME
    left = np.frombuffer(a, dtype='<i2', count=n * 2, offset=astart).reshape(-1, 2)
    right = np.frombuffer(b, dtype='<i2', count=n * 2, offset=bstart).reshape(-1, 2)
    # Process chunks so peak temporary allocations do not scale with track size.
    different_frames = different_samples = max_difference = 0
    first_difference = last_difference = None
    for i in range(0, n, 262144):
        delta = left[i:i + 262144].astype(np.int32) - right[i:i + 262144].astype(np.int32)
        different_samples += int(np.count_nonzero(delta))
        frame_difference = np.any(delta != 0, axis=1)
        positions = np.flatnonzero(frame_difference)
        different_frames += len(positions)
        if len(positions):
            if first_difference is None:
                first_difference = i + int(positions[0])
            last_difference = i + int(positions[-1])
        if delta.size:
            max_difference = max(max_difference, int(np.max(np.abs(delta))))
    return {'a_start_frame': astart // FRAME, 'b_start_frame': bstart // FRAME,
            'overlap_frames': n, 'different_frames': different_frames,
            'different_channel_samples': different_samples, 'max_absolute_sample_difference': max_difference,
            'first_difference_overlap_frame': first_difference, 'last_difference_overlap_frame': last_difference}


def compare(cue_a, cue_b, cue_bytes=None):
    cues = [Path(cue_a), Path(cue_b)]
    if cue_bytes is None:
        cue_bytes = [c.read_bytes() for c in cues]
    elif len(cue_bytes) != len(cues):
        raise ValueError('Provide exactly two CUE byte snapshots')
    tracks = [parse_cue_bytes(data) for data in cue_bytes]
    if [(t['number'], t['mode']) for t in tracks[0]] != [(t['number'], t['mode']) for t in tracks[1]]:
        raise ValueError('Track numbers or modes differ')
    result = {'format': 'CD-DA 44100 Hz signed 16-bit little-endian interleaved stereo',
              'sample_interpretation': 'little-endian assumption; source BIN byte order unverified',
              'numpy_version': np.__version__,
              'cues': [{'path': str(c), 'sha256': sha256(data)}
                       for c, data in zip(cues, cue_bytes)], 'tracks': []}
    for ta, tb in zip(*tracks):
        paths = [resolve_cue_file(c, t['file']) for c, t in zip(cues, (ta, tb))]
        raw = [p.read_bytes() for p in paths]
        sizes = [len(data) for data in raw]
        for t, size in zip((ta, tb), sizes):
            if size % SECTOR or any(v > size for v in t['indexes'].values()):
                raise ValueError(f"Invalid length or out-of-bounds index: {t['file']}")
        entry = {'number': ta['number'], 'mode': ta['mode'],
                 'inputs': [{'file': t['file'], 'size': size, 'sha256': sha256(data),
                             'index_00_bytes': t['indexes'].get(0), 'index_01_bytes': t['indexes'][1]}
                            for t, data, size in zip((ta, tb), raw, sizes)]}
        if ta['mode'] == 'AUDIO':
            a, b = (data[t['indexes'][1]:] for data, t in zip(raw, (ta, tb)))
            entry['program_sha256'] = [sha256(a), sha256(b)]
            entry['index_01_comparison'] = metrics(a, b, 0)
            entry['anchor_search'] = anchors(a, b)
            offset = entry['anchor_search']['offset_frames']
            if offset is not None:
                entry['aligned_comparison'] = metrics(a, b, offset)
        result['tracks'].append(entry)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('cue_a', type=Path)
    p.add_argument('cue_b', type=Path)
    p.add_argument('output', type=Path, help='private JSON output (must not be an input)')
    args = p.parse_args()
    # Never overwrite CUE/BIN inputs, including via symlinks.
    cue_bytes = [cue.read_bytes() for cue in (args.cue_a, args.cue_b)]
    tracks = [parse_cue_bytes(data) for data in cue_bytes]
    inputs = [args.cue_a, args.cue_b]
    for cue, cue_tracks in zip((args.cue_a, args.cue_b), tracks):
        inputs.extend(resolve_cue_file(cue, t['file']) for t in cue_tracks)
    if args.output.resolve() in {p.resolve() for p in inputs} or (args.output.exists() and any(args.output.samefile(p) for p in inputs)):
        raise ValueError('Output must not overwrite an input')
    result = compare(args.cue_a, args.cue_b, cue_bytes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
