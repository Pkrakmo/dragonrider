#!/usr/bin/env python3
"""List immediate selector values at direct calls to the SRSC record initializer.

The result is limited to direct relative calls visible in objdump text. It
does not find virtual calls, function-pointer calls, or selectors supplied by
registers or memory.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess


INSTRUCTION = re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+(.+?)\s*$', re.I)
CALL = re.compile(r'\bcall\s+0x([0-9a-f]+)\b', re.I)
PUSH_IMMEDIATE = re.compile(r'\bpush\s+0x([0-9a-f]+)\b', re.I)
# A preceding call may have consumed a different argument sequence, while an
# unconditional transfer has no sequential fall-through.  Do not let either
# contribute pushes to the next direct-call observation.  Conditional jumps
# deliberately remain in the bounded window: the fall-through instructions
# are still a possible sequential path and this text scan cannot prove which
# path executed.
BREAKS_LOOKBACK = re.compile(r'^\s*(?:call\b|(?:repz?\s+)?ret\b|jmp\b)', re.I)


def measure(disassembly, target=0x45f600):
    """Return aggregate direct-call and up-to-three-immediate-push counts.

    x86 callers push arguments right-to-left, so reversing the nearby pushes
    restores their source order.  The lookback stops at a prior call, return,
    or unconditional jump to avoid crossing a distinct sequential call path.
    This remains a deliberately bounded text scan: it cannot recover
    register, memory, indirect, distant, or path-dependent arguments.
    """
    prior = []
    result = Counter()
    for line in disassembly.splitlines():
        match = INSTRUCTION.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        instruction = match.group(2)
        call = CALL.search(instruction)
        if call and int(call.group(1), 16) == target:
            result['direct_calls'] += 1
            result[f'call_{address:08x}'] += 1
            selectors = []
            for earlier in reversed(prior[-8:]):
                pushed = PUSH_IMMEDIATE.search(earlier)
                if pushed:
                    selectors.append(int(pushed.group(1), 16))
                    if len(selectors) == 3:
                        break
            if not selectors:
                result['calls_without_nearby_immediate_push'] += 1
            else:
                result[f'selector_{selectors[0]:04x}'] += 1
                if len(selectors) >= 2:
                    result[f'selector_pair_{selectors[0]:04x}_{selectors[1]:04x}'] += 1
                if len(selectors) == 3:
                    result[f'selector_triple_{selectors[0]:04x}_{selectors[1]:04x}_{selectors[2]:04x}'] += 1
        if BREAKS_LOOKBACK.search(instruction):
            prior.clear()
        else:
            prior.append(instruction)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--target', type=lambda text: int(text, 0), default=0x45f600)
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    output = subprocess.run(['objdump', '-d', '-Mintel', str(executable)], check=True,
                            text=True, stdout=subprocess.PIPE).stdout
    print(json.dumps({'target': f'0x{args.target:08x}',
                      'counts': dict(sorted(measure(output, args.target).items()))}, indent=2))


if __name__ == '__main__':
    main()
