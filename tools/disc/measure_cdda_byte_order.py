#!/usr/bin/env python3
"""Compare candidate CD-DA byte orders using hash-verified CUE/BIN snapshots.

The report contains only aggregate spectral ratios. It cannot establish rip
provenance or prove which interpretation is correct.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re

import numpy as np

from compare_audio import FRAME, SECTOR, parse_cue_bytes

SAMPLE_RATE = 44100
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def parse_sha256_manifest(data):
    entries = {}
    for line in data.decode("utf-8").splitlines():
        if (len(line) < 67 or line.startswith("\\") or line[64] != " "
                or line[65] not in {" ", "*"}):
            raise ValueError("invalid sha256sum manifest line")
        digest, name = line[:64], line[66:]
        if not _SHA256.fullmatch(digest) or not name or ".." in Path(name).parts:
            raise ValueError("invalid or duplicate sha256sum manifest entry")
        key = str(Path(name).resolve())
        if key in entries:
            raise ValueError("invalid or duplicate sha256sum manifest entry")
        entries[key] = digest
    if not entries:
        raise ValueError("empty sha256sum manifest")
    return entries


def verified_snapshot(path, manifest):
    path = Path(path)
    if ".." in path.parts:
        raise ValueError("parent traversal in input path")
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink in input path")
    if not path.is_file():
        raise ValueError("input must be a regular file")
    resolved = path.resolve(strict=True)
    expected = manifest.get(str(resolved))
    if expected is None:
        raise ValueError("input is absent from the archival hash manifest")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("input SHA-256 differs from archival manifest")
    return data


def highband_ratio(data, byte_order, sample_frames=44100):
    if byte_order not in {"<i2", ">i2"}:
        raise ValueError("byte order must be '<i2' or '>i2'")
    if type(sample_frames) is not int or sample_frames <= 0:
        raise ValueError("sample frame count must be a positive integer")
    if sample_frames > SAMPLE_RATE:
        raise ValueError("sample window exceeds the one-second measurement limit")
    if len(data) % FRAME:
        raise ValueError("audio byte length is not stereo-frame aligned")
    total_frames = len(data) // FRAME
    if sample_frames > total_frames:
        raise ValueError("sample window exceeds available audio")
    start = ((total_frames - sample_frames) // 2) * FRAME
    values = np.frombuffer(data, dtype=byte_order, count=sample_frames * 2,
                           offset=start).reshape(sample_frames, 2).astype(np.float64)
    values -= values.mean(axis=0)
    window = np.hanning(sample_frames)
    spectrum = np.fft.rfft(values * window[:, None], axis=0)
    power = np.square(np.abs(spectrum)).sum(axis=1)
    frequencies = np.fft.rfftfreq(sample_frames, d=1 / SAMPLE_RATE)
    audible = power[(frequencies >= 20) & (frequencies <= 20000)].sum()
    high = power[frequencies > 20000].sum()
    if not np.isfinite(audible) or not np.isfinite(high) or audible <= 0:
        raise ValueError("sample window has no finite audible-band power")
    return float(high / audible)


def summarize(values):
    return {"median": float(np.median(values)), "minimum": float(min(values)),
            "maximum": float(max(values)), "samples": len(values)}


def measure(cue_paths, manifest_path, sample_frames=44100, windows_per_track=1):
    if len(cue_paths) != 2:
        raise ValueError("provide exactly two CUE paths")
    if (type(windows_per_track) is not int or windows_per_track < 1
            or windows_per_track > 9 or windows_per_track % 2 == 0):
        raise ValueError("windows per track must be an odd integer from 1 to 9")
    manifest = parse_sha256_manifest(Path(manifest_path).read_bytes())
    cue_bytes = [verified_snapshot(path, manifest) for path in cue_paths]
    cue_tracks = [parse_cue_bytes(data) for data in cue_bytes]
    if [(t["number"], t["mode"]) for t in cue_tracks[0]] != [
            (t["number"], t["mode"]) for t in cue_tracks[1]]:
        raise ValueError("CUE track numbers or modes differ")

    ratios = [defaultdict(list), defaultdict(list)]
    audio_counts = [0, 0]
    candidate_windows = [0, 0]
    unusable_windows = [0, 0]
    little_endian_lower = [0, 0]
    for edition_index, (cue_path, tracks, summary) in enumerate(zip(cue_paths, cue_tracks, ratios)):
        for track in tracks:
            if track["mode"] != "AUDIO":
                continue
            path = Path(cue_path).parent / track["file"]
            data = verified_snapshot(path, manifest)
            if len(data) % SECTOR or any(index > len(data)
                                         for index in track["indexes"].values()):
                raise ValueError("audio track length or CUE index is out of bounds")
            audio = data[track["indexes"][1]:]
            total_frames = len(audio) // FRAME
            if sample_frames > total_frames:
                raise ValueError("sample window exceeds available audio")
            if windows_per_track == 1:
                starts = [((total_frames - sample_frames) // 2)]
            else:
                starts = [round(i * (total_frames - sample_frames) /
                                (windows_per_track - 1))
                          for i in range(windows_per_track)]
            for start in starts:
                candidate_windows[edition_index] += 1
                window = audio[start * FRAME:(start + sample_frames) * FRAME]
                try:
                    measured = {label: highband_ratio(window, dtype, sample_frames)
                                for label, dtype in (("little_endian", "<i2"),
                                                     ("big_endian", ">i2"))}
                except ValueError as exc:
                    if "no finite audible-band power" not in str(exc):
                        raise
                    unusable_windows[edition_index] += 1
                    continue
                if measured["little_endian"] < measured["big_endian"]:
                    little_endian_lower[edition_index] += 1
                for label, ratio in measured.items():
                    summary[label].append(ratio)
            audio_counts[edition_index] += 1

    if not audio_counts[0] or audio_counts[0] != audio_counts[1] or any(
            not summary["little_endian"] or
            len(summary["little_endian"]) != len(summary["big_endian"])
            for summary in ratios):
        raise ValueError("CUEs contain no comparable AUDIO tracks")
    return {
        "method": "centered Hann-window FFT; two-channel power above 20 kHz divided by 20 Hz–20 kHz power",
        "sample_rate_hz": SAMPLE_RATE,
        "sample_frames_per_track": sample_frames,
        "windows_per_track": windows_per_track,
        "input_hashes_verified": True,
        "sample_bytes_emitted": False,
        "editions": [{"label": label, "audio_tracks": count,
                      "candidate_windows": candidates,
                      "unusable_windows_skipped": unusable,
                      "little_endian_lower_windows": wins,
                      "ratios": {name: summarize(values) for name, values in summary.items()}}
                     for label, summary, count, candidates, unusable, wins in
                     zip(("A", "B"), ratios, audio_counts, candidate_windows,
                         unusable_windows, little_endian_lower)],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cue_a", type=Path)
    parser.add_argument("cue_b", type=Path)
    parser.add_argument("sha256_manifest", type=Path)
    parser.add_argument("--sample-frames", type=int, default=44100)
    parser.add_argument("--windows-per-track", type=int, default=1,
                        help="odd number of evenly distributed windows, from 1 to 9")
    args = parser.parse_args()
    print(json.dumps(measure((args.cue_a, args.cue_b), args.sha256_manifest,
                             args.sample_frames, args.windows_per_track), indent=2))


if __name__ == "__main__":
    main()
