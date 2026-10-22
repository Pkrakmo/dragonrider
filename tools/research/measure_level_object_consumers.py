#!/usr/bin/env python3
"""List bounded direct calls and tail jumps to level-object consumer routines.

Only direct relative calls and tail jumps shown by objdump are reported.
Immediate pushes within the preceding eight instructions are recorded in x86
source order for calls; register, memory and indirect arguments intentionally
remain unclassified.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess


INSTRUCTION = re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+(.+?)\s*$', re.I)
CALL = re.compile(r'\bcall\s+0x([0-9a-f]+)\b', re.I)
JUMP = re.compile(r'\bjmp\s+0x([0-9a-f]+)\b', re.I)
PUSH_IMMEDIATE = re.compile(r'\bpush\s+0x([0-9a-f]+)\b', re.I)
PUSH = re.compile(r'\bpush\b', re.I)


def measure(disassembly, targets):
    """Return direct-call counts and nearby immediate-push summaries by target."""
    targets = set(targets)
    result = {target: Counter() for target in targets}
    prior = []
    for line in disassembly.splitlines():
        match = INSTRUCTION.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        instruction = match.group(2)
        call = CALL.search(instruction)
        jump = JUMP.search(instruction)
        if jump and (target := int(jump.group(1), 16)) in targets:
            counts = result[target]
            counts['direct_tail_jumps'] += 1
            counts[f'tail_jump_{address:08x}'] += 1
        if call and (target := int(call.group(1), 16)) in targets:
            counts = result[target]
            counts['direct_calls'] += 1
            counts[f'call_{address:08x}'] += 1
            immediates, other_pushes = [], 0
            for earlier in reversed(prior[-8:]):
                pushed = PUSH_IMMEDIATE.search(earlier)
                if pushed:
                    immediates.append(int(pushed.group(1), 16))
                    if len(immediates) == 3:
                        break
                elif PUSH.search(earlier):
                    other_pushes += 1
            if immediates:
                counts[f'first_immediate_{immediates[0]:08x}'] += 1
                if len(immediates) >= 2:
                    counts[f'immediate_pair_{immediates[0]:08x}_{immediates[1]:08x}'] += 1
                if len(immediates) == 3:
                    counts[f'immediate_triple_{immediates[0]:08x}_{immediates[1]:08x}_{immediates[2]:08x}'] += 1
            else:
                counts['calls_without_nearby_immediate_push'] += 1
            if other_pushes:
                counts['calls_with_non_immediate_pushes'] += 1
        prior.append(instruction)
    return {f'0x{target:08x}': dict(sorted(counts.items())) for target, counts in sorted(result.items())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--target', action='append', type=lambda text: int(text, 0),
                        default=[0x4294d0, 0x4213f0, 0x445bd0],
                        help='direct-call/tail-jump target (repeatable)')
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    output = subprocess.run(['objdump', '-d', '-Mintel', str(executable)], check=True,
                            text=True, stdout=subprocess.PIPE).stdout
    print(json.dumps({'targets': measure(output, args.target)}, indent=2))


if __name__ == '__main__':
    main()
