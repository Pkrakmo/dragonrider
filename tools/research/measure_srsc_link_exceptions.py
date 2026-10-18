#!/usr/bin/env python3
"""Measure candidate 0x0201 missing links without exporting identifiers or payloads."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from measure_srsc_lookup import read_records


def measure_files(files):
    """Count file-local exceptions and finite candidate chain outcomes.

    Files are independent selector tables. A zero third word terminates the
    simulation; this is an analytical convention, not a demonstrated runtime rule.
    """
    files = list(files)
    other_file_keys = Counter()
    for records in files:
        other_file_keys.update({second for kind, second, _ in records if kind == 0x0201})
    totals = Counter({key: 0 for key in (
        'files', 'files_with_direct_missing', 'direct_missing_records',
        'distinct_file_missing_keys', 'missing_keys_matching_other_kind_in_same_file',
        'missing_keys_matching_0201_in_another_file', 'affected_0201_chains',
        'affected_0200_chains', 'ambiguous_chains', 'cyclic_chains')})
    depths = {'0201': Counter(), '0200': Counter()}
    for records in files:
        totals['files'] += 1
        targets = defaultdict(list)
        other_kinds = set()
        for kind, second, third in records:
            if kind == 0x0201:
                targets[second].append(third)
            else:
                other_kinds.add(second)
        missing = [third for kind, _, third in records
                   if kind == 0x0201 and third != 0 and third not in targets]
        missing_keys = set(missing)
        totals['files_with_direct_missing'] += bool(missing)
        totals['direct_missing_records'] += len(missing)
        totals['distinct_file_missing_keys'] += len(missing_keys)
        totals['missing_keys_matching_other_kind_in_same_file'] += len(missing_keys & other_kinds)
        totals['missing_keys_matching_0201_in_another_file'] += sum(
            other_file_keys[key] > 0 for key in missing_keys)
        for kind, second, third in records:
            if kind not in (0x0200, 0x0201):
                continue
            # A 0201 chain begins at its own record; a 0200 chain begins
            # at its first candidate 0201 target. Count matched hops only.
            visited = {second} if kind == 0x0201 else set()
            hops = 0
            while third:
                matches = targets.get(third, [])
                if not matches:
                    totals[f'affected_{kind:04x}_chains'] += 1
                    depths[f'{kind:04x}'][str(hops)] += 1
                    break
                if len(matches) != 1:
                    totals['ambiguous_chains'] += 1
                    break
                if third in visited:
                    totals['cyclic_chains'] += 1
                    break
                visited.add(third)
                hops += 1
                third = matches[0]
    return {'totals': totals, 'missing_chain_matched_hops': depths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if any(entry['status'] != 'examined' for entry in entries):
        raise ValueError('inventory contains unexamined files')
    print(json.dumps(measure_files(read_records(root, entry) for entry in entries),
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
