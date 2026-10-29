#!/usr/bin/env python3
# Round-trip test for the hive reader (src/regf.c) and the TEST-ONLY writer
# tests/wine/regfwrite.py: random key trees (Latin-1 and non-Latin names,
# empty keys, many subkeys, values of every small type, inline and cell data
# sizes) are written, read back with tests/regf_dump.c and compared. The real
# reader is also checked against real hives (regf_check.py); this makes sure
# the writer used for offline fixtures produces what the reader understands.
# Usage: python3 tests/regf_roundtrip.py <path-to-regf_dump> [rounds]
import json, os, random, subprocess, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wine'))
import regfwrite as rw

dump = sys.argv[1]
rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 100
rnd = random.Random(7)
alpha = 'abcXYZ09 _-.{}' + 'éşĞ中'


def rname():
    return ''.join(rnd.choice(alpha) for _ in range(rnd.randint(1, 12)))


def rkey(depth):
    vals, seen = [], set()
    for _ in range(rnd.randint(0, 5)):
        n = '' if rnd.random() < 0.15 else rname()
        if n.upper() in seen:
            continue
        seen.add(n.upper())
        t = rnd.choice([rw.REG_SZ, rw.REG_BINARY, rw.REG_DWORD])
        d = rw.sz(rname()) if t == rw.REG_SZ else rw.dword(rnd.getrandbits(32)) if t == rw.REG_DWORD else \
            bytes(rnd.getrandbits(8) for _ in range(rnd.choice([0, 1, 4, 5, 300, 5000])))
        vals.append(rw.Value(n, t, d))
    kids, kseen = [], set()
    for _ in range(rnd.randint(0, 6 if depth < 3 else 0)):
        k = rkey(depth + 1)
        if k.name.upper() not in kseen:
            kseen.add(k.name.upper())
            kids.append(k)
    return rw.Key(rname(), vals, kids, last_written=rnd.getrandbits(56))


def walk(k, path, out):
    out[path] = (k.last_written, sorted((v.name, v.type, v.data.hex()) for v in k.values),
                 sorted(s.name for s in k.subkeys))
    for s in k.subkeys:
        walk(s, (path + '\\' if path else '') + s.name, out)


def read(hive, path):
    r = subprocess.run([dump, hive, 'key', path], capture_output=True, text=True)
    return json.loads(r.stdout)


bad = 0
with tempfile.TemporaryDirectory() as td:
    for r in range(rounds):
        root = rkey(0)
        hp = os.path.join(td, f'h{r}.hiv')
        with open(hp, 'wb') as f:
            f.write(rw.build(root))
        want = {}
        walk(root, '', want)
        for path, (lw, vals, subs) in want.items():
            got = read(hp, path)
            gv = sorted((v['name'], v['type'], v['hex']) for v in got.get('values', []))
            if got.get('last_written') != lw or gv != vals or sorted(got.get('subkeys', [])) != subs:
                bad += 1
                print('MISMATCH', r, repr(path), got.get('error'))
                break
print(f'regf round-trip: {rounds} hives, {bad} mismatch(es)')
sys.exit(1 if bad else 0)
