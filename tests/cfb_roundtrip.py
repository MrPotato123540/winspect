#!/usr/bin/env python3
# Round-trip test for the compound-file reader (src/cfb.c): build random
# compound files with tests/wine/cfbwrite.py (small and large streams, empty
# ones, sizes right at the 4096-byte mini-stream cutoff), read them back with
# the C reader via tests/cfb_dump.c, and require every stream's size and MD5 to
# match. Usage: python3 tests/cfb_roundtrip.py <path-to-cfb_dump> [rounds]
import hashlib, os, random, subprocess, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wine'))
import cfbwrite

dump = sys.argv[1]
rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 200
rnd = random.Random(2024)
sizes = [0, 1, 63, 64, 65, 511, 512, 513, 4095, 4096, 4097, 9000, 20000]
bad = 0
with tempfile.TemporaryDirectory() as td:
    for r in range(rounds):
        streams = []
        for i in range(rnd.randint(1, 12)):
            n = rnd.choice(sizes) if rnd.random() < 0.5 else rnd.randint(0, 6000)
            streams.append((f's{i}', bytes(rnd.getrandbits(8) for _ in range(n))))
        path = os.path.join(td, f'r{r}.cfb')
        with open(path, 'wb') as f:
            f.write(cfbwrite.build(streams))
        want = sorted(f'{nm}\t{len(d)}\t{hashlib.md5(d).hexdigest()}' for nm, d in streams)
        got = sorted(subprocess.run([dump, path], capture_output=True, text=True).stdout.splitlines())
        if got != want:
            bad += 1
            print('MISMATCH round', r, [(n, len(d)) for n, d in streams])
print(f'cfb round-trip: {rounds} files, {bad} mismatch(es)')
sys.exit(1 if bad else 0)
