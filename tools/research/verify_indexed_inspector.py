#!/usr/bin/env python3
"""Compare explicit indexed checks against private independent measurements."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inspector', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    data = json.loads(args.manifest.read_text())
    items = [(file, record) for file in data['files'] if 'candidate_index' in file
             for record in file['records'] if record['status'] == 'measured']
    if not items:
        parser.error('manifest contains no measured explicit pairs')

    def check(item):
        file, record = item
        result = subprocess.run([str(args.inspector), '--indexed-check', str(record['index']),
                                 str(file['candidate_index']), str(args.root / file['path'])],
                                capture_output=True, text=True)
        maximum = record['maximum_index'] if record['maximum_index'] is not None else 'none'
        expected = (f"Palette entries: {file['selected_candidate_count']}\n"
                    f"Visible index bytes: {record['visible_indices']}\n"
                    f"Distinct indices: {record['distinct_indices']}\n"
                    f"Maximum index: {maximum}\n"
                    f"Indices outside selected palette: {record['indices_at_or_above_candidate_count']}\n"
                    "Runtime association: not established\n")
        return result.returncode == 0 and expected in result.stdout

    with ThreadPoolExecutor(max_workers=8) as pool:
        matched = sum(pool.map(check, items))
    print(f'Private explicit indexed comparisons: {matched}/{len(items)} matched')
    if matched != len(items):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
