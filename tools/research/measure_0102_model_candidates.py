#!/usr/bin/env python3
"""Compare descriptor-derived model candidates to 0x0102 payload low words.

Descriptor names are normalized only as strings and matched against inventory
entries. Files are opened solely using the separately supplied inventory paths.
"""
import argparse
from collections import Counter, defaultdict
import json
import ntpath
from pathlib import Path, PurePosixPath
import struct

from measure_0102_descriptor_keys import verified
from verify_database_descriptors import decode


def table(data):
    if len(data) < 12 or data[:4] != b'SRSC':
        raise ValueError('invalid SRSC header')
    version, offset, count = struct.unpack_from('<HIH', data, 4)
    if version != 0x100 or not count or offset < 12 or offset + count * 14 > len(data):
        raise ValueError('invalid SRSC table')
    return offset, list(struct.iter_unpack('<HHHII', data[offset:offset + count * 14]))


def candidate_path(descriptor_path, raw_name):
    """Produce an overlay-relative comparison string, never a filesystem path."""
    parts = PurePosixPath(descriptor_path).parts
    if len(parts) < 2 or any(part in ('.', '..') for part in parts):
        raise ValueError('invalid descriptor inventory path')
    try:
        name = raw_name.decode('ascii')
    except UnicodeDecodeError:
        return None
    if not name or '\x00' in name or '/' in name or name.startswith('\\') or ntpath.splitdrive(name)[0]:
        return None
    base = '\\'.join(parts[1:-1])
    combined = ntpath.normpath(ntpath.join(base, name))
    if combined in ('.', '..') or combined.startswith(('..\\', '\\')) or ntpath.splitdrive(combined)[0]:
        return None
    if ntpath.splitext(combined)[1]:
        return None
    return (combined + '.mod').lower()


def model_keys(data):
    _, entries = table(data)
    return Counter(second for kind, second, _, _, _ in entries if kind == 0x0200)


def self_candidate_path(descriptor_path):
    """Form a same-base overlay comparison string for the zero-key receiver."""
    parts = PurePosixPath(descriptor_path).parts
    if (len(parts) < 2 or any(part in ('.', '..') for part in parts)
            or not parts[-1].lower().endswith('.db')):
        raise ValueError('invalid descriptor inventory path')
    return ('\\'.join(parts[1:])[:-3] + '.mod').lower()


def measure(odb, dependencies, descriptor_path, model_index, inventory_paths=()):
    offset, entries = table(odb)
    by_id = defaultdict(list)
    for ident, name in dependencies:
        by_id[ident].append(name)
    result = Counter({key: 0 for key in ('records', 'zero_high', 'dependency_missing',
        'dependency_multiple', 'unsupported_name', 'model_missing', 'model_multiple',
        'model_unique', 'low_missing', 'low_unique', 'low_multiple',
        'low_zero', 'low_missing_zero', 'zero_high_low_zero',
        'self_model_missing', 'self_model_unique', 'self_model_multiple',
        'self_low_missing', 'self_low_unique', 'self_low_multiple',
        'self_low_zero_missing', 'self_low_zero_unique', 'self_low_zero_multiple',
        'model_missing_with_db',
        'model_missing_with_odb', 'model_missing_with_both')})
    categories = ('dependency_missing', 'model_missing', 'low_missing')
    for category in categories:
        for scope in ('zero', 'one', 'multiple'):
            result[f'{category}_inventoried_model_{scope}'] = 0
    exception_keys = {category: set() for category in categories}
    model_presence = Counter()
    for candidates in model_index.values():
        for model in candidates:
            model_presence.update(key for key, count in model.items() if count > 0)

    def note_exception(category, low, identity):
        exception_keys[category].add(identity)
        count = model_presence[low]
        scope = 'zero' if count == 0 else 'one' if count == 1 else 'multiple'
        result[f'{category}_inventoried_model_{scope}'] += 1

    for kind, _, _, start, length in entries:
        if kind != 0x0102:
            continue
        if start < 12 or start + length > offset or length < 2:
            raise ValueError('invalid 0x0102 payload')
        prefix = struct.unpack_from('<H', odb, start)[0]
        if prefix + 8 > length:
            raise ValueError('short 0x0102 payload')
        low, high = struct.unpack_from('<HH', odb, start + prefix + 4)
        result['records'] += 1
        if high == 0:
            result['zero_high'] += 1
            result['zero_high_low_zero'] += low == 0
            models = model_index.get(self_candidate_path(descriptor_path), [])
            if not models:
                result['self_model_missing'] += 1
            elif len(models) > 1:
                result['self_model_multiple'] += 1
            else:
                result['self_model_unique'] += 1
                matches = models[0][low]
                category = 'missing' if matches == 0 else 'unique' if matches == 1 else 'multiple'
                result['self_low_' + category] += 1
                if low == 0:
                    result['self_low_zero_' + category] += 1
            continue
        names = by_id[high]
        if not names:
            result['dependency_missing'] += 1
            note_exception('dependency_missing', low, (high, low))
            continue
        if len(names) != 1:
            result['dependency_multiple'] += 1
            continue
        candidate = candidate_path(descriptor_path, names[0])
        if candidate is None:
            result['unsupported_name'] += 1
            continue
        models = model_index.get(candidate, [])
        if not models:
            result['model_missing'] += 1
            note_exception('model_missing', low, (candidate, low))
            has_db = candidate[:-4] + '.db' in inventory_paths
            has_odb = candidate[:-4] + '.odb' in inventory_paths
            result['model_missing_with_db'] += has_db
            result['model_missing_with_odb'] += has_odb
            result['model_missing_with_both'] += has_db and has_odb
            continue
        if len(models) != 1:
            result['model_multiple'] += 1
            continue
        result['model_unique'] += 1
        matches = models[0][low]
        result['low_zero'] += low == 0
        result['low_missing'] += matches == 0
        result['low_missing_zero'] += matches == 0 and low == 0
        if matches == 0:
            note_exception('low_missing', low, (candidate, low))
        result['low_unique'] += matches == 1
        result['low_multiple'] += matches > 1
    for category in categories:
        result[f'{category}_files'] = bool(exception_keys[category])
        result[f'{category}_distinct_per_file'] = len(exception_keys[category])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    by_path = {entry['path'].lower(): entry for entry in entries}
    if not entries or len(by_path) != len(entries):
        raise ValueError('empty inventory or case-insensitive path collision')
    model_index = defaultdict(list)
    inventory_paths = set()
    for entry in entries:
        parts = PurePosixPath(entry['path']).parts
        if len(parts) >= 2:
            inventory_paths.add('\\'.join(parts[1:]).lower())
        if entry['path'].lower().endswith('.mod'):
            if len(parts) < 2 or any(part in ('.', '..') for part in parts):
                raise ValueError('invalid model inventory path')
            key = '\\'.join(parts[1:]).lower()
            model_index[key].append(model_keys(verified(root, entry)))
    totals = Counter()
    for entry in entries:
        if not entry['path'].lower().endswith('.odb'):
            continue
        descriptor = by_path.get((entry['path'][:-4] + '.db').lower())
        if descriptor is None:
            totals['odb_without_descriptor'] += 1
            continue
        data = verified(root, entry)
        dependencies = decode(verified(root, descriptor))
        totals.update(measure(data, dependencies, descriptor['path'], model_index, inventory_paths))
        totals['pairs'] += 1
    print(json.dumps(dict(sorted(totals.items())), indent=2))


if __name__ == '__main__':
    main()
