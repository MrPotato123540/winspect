#!/usr/bin/env python3
# Differential test: src/sqlite.c (via tests/sqlite_dump) against Python's own
# sqlite3 module. Random databases - page sizes 512..65536, UTF-8 / UTF-16le /
# UTF-16be text, values big enough to need overflow pages, integers of every
# stored width, floats, NULLs, enough rows for interior b-tree pages, deleted
# rows - must read back row for row. Some databases are in WAL mode and are
# copied while the writer still holds uncheckpointed frames, so the rows exist
# only in the -wal file. Usage: sqlite_diff.py <sqlite_dump> [rounds]
import json, os, random, shutil, sqlite3, subprocess, sys, tempfile

dump = sys.argv[1]
rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 40
rnd = random.Random(99)
alpha = 'abcXYZ09 _-"\\\\\n' + 'éşĞ中😀'


def rval():
    k = rnd.randint(0, 9)
    if k == 0: return None
    if k == 1: return rnd.choice([0, 1, -1, 127, -128, 32767, -32768, 2**23 - 1, -2**23, 2**31 - 1, -2**31,
                                  2**47 - 1, -2**47, 2**63 - 1, -2**63])
    if k == 2: return rnd.randint(-2**63, 2**63 - 1)
    if k == 3: return rnd.uniform(-1e9, 1e9)
    if k in (4, 5): return ''.join(rnd.choice(alpha) for _ in range(rnd.randint(0, 30)))
    if k == 6: return ''.join(rnd.choice(alpha) for _ in range(rnd.randint(500, 9000)))      # overflow
    if k == 7: return bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 40)))
    if k == 8: return bytes(rnd.getrandbits(8) for _ in range(rnd.randint(2000, 70000)))     # long chains
    return rnd.randint(-1000, 1000)


def norm(v):
    if isinstance(v, bytes): return 'x:' + v.hex()
    if isinstance(v, float): return round(v, 9)
    return v


bad = 0
with tempfile.TemporaryDirectory() as td:
    for r in range(rounds):
        path = os.path.join(td, f'd{r}.db')
        con = sqlite3.connect(path)
        ps = rnd.choice([512, 1024, 4096, 8192, 65536])
        enc = rnd.choice(['UTF-8', 'UTF-16le', 'UTF-16be'])
        con.execute(f'PRAGMA page_size={ps}')
        con.execute(f'PRAGMA encoding="{enc}"')
        wal = rnd.random() < 0.4
        if wal:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('PRAGMA wal_autocheckpoint=0')
        ncol = rnd.randint(1, 8)
        con.execute('CREATE TABLE t (' + ','.join(f'c{i}' for i in range(ncol)) + ')')
        con.execute('CREATE TABLE other (a, b)')
        con.execute('INSERT INTO other VALUES (1, 2)')
        rows = [tuple(rval() for _ in range(ncol)) for _ in range(rnd.randint(0, 600))]
        con.executemany('INSERT INTO t VALUES (' + ','.join('?' * ncol) + ')', rows)
        con.commit()
        if rows and rnd.random() < 0.5:
            con.execute('DELETE FROM t WHERE rowid % 3 = 0')
            con.commit()
        if wal and rnd.random() < 0.7:
            con.executemany('INSERT INTO t VALUES (' + ','.join('?' * ncol) + ')',
                            [tuple(rval() for _ in range(ncol)) for _ in range(rnd.randint(1, 50))])
            con.commit()
        want = [[rid] + [norm(v) for v in row] for rid, *row in con.execute('SELECT rowid, * FROM t ORDER BY rowid')]
        # Copy while the connection is open: WAL frames are not checkpointed yet.
        cp = os.path.join(td, f'c{r}.db')
        shutil.copy(path, cp)
        args = [dump, cp, 't']
        if wal and os.path.exists(path + '-wal'):
            shutil.copy(path + '-wal', cp + '-wal')
            args.append(cp + '-wal')
        con.close()
        out = subprocess.run(args, capture_output=True).stdout.decode('utf-8')
        try:
            got = [[norm(v) if not isinstance(v, str) or not v.startswith('x:') else v for v in json.loads(l)]
                   for l in out.splitlines()]
        except Exception as e:
            got = [str(e), out[:200]]
        # Records store all declared columns, even trailing NULLs added later, so compare padded.
        got = [g + [None] * (len(w) - len(g)) for g, w in zip(got, want)] if len(got) == len(want) else got
        if got != want:
            bad += 1
            print(f'MISMATCH round {r}: page {ps}, {enc}, wal={wal}, rows {len(want)} vs {len(got)}')
            for g, w in zip(got, want):
                if g != w:
                    print('  want', str(w)[:160]); print('  got ', str(g)[:160]); break
# Column names: odd but legal declarations, then ALTER TABLE ADD COLUMN.
with tempfile.TemporaryDirectory() as td:
    for r in range(20):
        path = os.path.join(td, f'n{r}.db')
        con = sqlite3.connect(path)
        names = []
        decl = []
        for i in range(rnd.randint(1, 10)):
            name = rnd.choice([f'c{i}', f'"col {i}"', f'[b{i}]', f'`q{i}`', f'x_{i}'])
            names.append(name)
            typ = rnd.choice(['', 'INTEGER', 'TEXT NOT NULL DEFAULT ""', "VARCHAR(255) DEFAULT 'a,b'",
                              'INTEGER DEFAULT (0)', 'REAL CHECK (1 > 0)'])
            decl.append(f'{name} {typ}'.strip())
        tail = rnd.choice(['', ', UNIQUE(' + names[0] + ')', ', CONSTRAINT k CHECK (1)'])
        con.execute('CREATE TABLE t (' + ', '.join(decl) + tail + ')')
        for i in range(rnd.randint(0, 3)):
            con.execute(f'ALTER TABLE t ADD COLUMN added{i} INTEGER DEFAULT 5')
        want = [row[1] for row in con.execute('PRAGMA table_info(t)')]
        con.close()
        got = subprocess.run([dump, path, 'cols:t'], capture_output=True).stdout.decode().splitlines()
        if got != want:
            bad += 1
            print('COLUMN MISMATCH', want, got)
print(f'sqlite diff: {rounds} databases, {bad} mismatch(es)')
sys.exit(1 if bad else 0)
