#!/usr/bin/env python3
"""Compare model-relative record indexes before and after stable selector ordering."""
import argparse
from collections import Counter
import json
from pathlib import Path
from measure_srsc_lookup import read_records


def measure(records):
    # Pair search returns the first matching index in the current table.
    ordered = sorted(enumerate(records), key=lambda item: item[1][1])
    first = {}
    for position, (original, (kind, selector, _)) in enumerate(ordered):
        first.setdefault((kind, selector), (position, original))
    result = Counter({key: 0 for key in (
        'lookup_pairs', 'missing_relative_records', 'reordered_lookup_positions',
        'relative_1_to_4_same_original_indices', 'relative_2_and_3_same_original_indices',
        'fourth_relative_kind_0208', 'fourth_relative_kind_0209', 'fourth_relative_kind_other',
        'first_four_same_other_selectors', 'zero_second_word', 'zero_third_word',
        'second_equals_third')})
    for (kind, _), (position, original) in first.items():
        if kind != 0x200:
            continue
        result['lookup_pairs'] += 1
        second, third = records[original][1:3]
        result['zero_second_word'] += second == 0
        result['zero_third_word'] += third == 0
        result['second_equals_third'] += second == third
        if position + 4 >= len(ordered) or original + 4 >= len(records):
            result['missing_relative_records'] += 1
            continue
        runtime = ordered[position:position + 5]
        result['reordered_lookup_positions'] += position != original
        result['relative_1_to_4_same_original_indices'] += all(runtime[j][0] == original + j for j in range(1, 5))
        result['relative_2_and_3_same_original_indices'] += all(runtime[j][0] == original + j for j in (2, 3))
        result['fourth_relative_kind_0208'] += runtime[4][1][0] == 0x208
        result['fourth_relative_kind_0209'] += runtime[4][1][0] == 0x209
        result['fourth_relative_kind_other'] += runtime[4][1][0] not in (0x208, 0x209)
        result['first_four_same_other_selectors'] += all(item[1][1:3] == runtime[0][1][1:3] for item in runtime[:4])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    selected = [entry for entry in entries if entry['status'] == 'examined' and entry['path'].lower().endswith('.mod')]
    if not selected:
        raise ValueError('no examined model containers')
    totals = Counter()
    for entry in selected:
        for key, value in measure(read_records(root, entry)).items():
            totals[key] += value
        totals['files'] += 1
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
