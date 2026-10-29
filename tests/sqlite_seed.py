#!/usr/bin/env python3
# Builds a small realistic seed database (+ uncheckpointed WAL) for
# tests/fuzz_sqlite.c: a Chrome-like urls/downloads pair with overflow-size
# values. Usage: sqlite_seed.py <out.db>   (writes <out.db> and <out.db>-wal)
import os, random, shutil, sqlite3, sys, tempfile
out = sys.argv[1]
rnd = random.Random(5)
with tempfile.TemporaryDirectory() as td:
    p = os.path.join(td, 's.db')
    con = sqlite3.connect(p)
    con.execute('PRAGMA page_size=1024')
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA wal_autocheckpoint=0')
    con.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER, last_visit_time INTEGER)')
    con.execute('CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path LONGVARCHAR, start_time INTEGER, danger_type INTEGER)')
    for i in range(300):
        con.execute('INSERT INTO urls VALUES (NULL, ?, ?, ?, ?)', ('https://example.org/' + 'p' * rnd.randint(0, 3000),
                    'title %d' % i, rnd.randint(0, 50), rnd.getrandbits(56)))
    for i in range(40):
        con.execute('INSERT INTO downloads VALUES (NULL, ?, ?, ?)', ('C:\\\\Users\\\\u\\\\Downloads\\\\f%d.exe' % i, rnd.getrandbits(56), i % 9))
    con.commit()
    shutil.copy(p, out)
    shutil.copy(p + '-wal', out + '-wal')
    con.close()
