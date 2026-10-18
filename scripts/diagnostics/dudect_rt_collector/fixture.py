"""Non-timing protocol fixture: release retained bytes only at their original looks."""
import json
import os
from pathlib import Path
import sys
import time

path, mode = Path(sys.argv[1]), sys.argv[2]
fd = int(os.environ['AEGAEON_DUDECT_TIMING_FD'])
rows = (path / 'native.stdout').read_bytes().splitlines()
proofs = [json.loads(x)['proof'] for x in (path / 'sparse-prefixes.jsonl').read_bytes().splitlines()]
with (path / 'native.timing').open('rb') as raw:
    for index, (row, proof) in enumerate(zip(rows, proofs, strict=True)):
        count = proof['prefix_end'] - raw.tell()
        data = raw.read(count)
        if mode != 'missing-prefix':
            while data:
                data = data[os.write(fd, data):]
        if mode == 'wrong-row' and index == 1:
            value = json.loads(row); value['look'] = 1
            row = json.dumps(value).encode()
        os.write(1, row + b'\n')
        if os.read(0, 1) != b'c':
            raise ValueError('missing real ACK')
        if mode == 'stall' and index == 0:
            time.sleep(60)
    tail = raw.read()
    if tail:
        os.write(fd, tail)
if mode == 'partial-tail':
    os.write(1, b'{')
