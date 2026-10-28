#!/usr/bin/env python3
# Compare tests/rb_dump (our Recycle Bin parser) against values published
# independently in plaso's tests/parsers/recycler.py for its test files
# (test_data/recycler/: $II3DF3L.zip = Vista, $I103S5F.jpg = Windows 10,
# INFO2 = XP). Only the data files are used; no third-party code runs.
# Usage: rb_check.py <rb_dump> <dir with the three files>
import os, subprocess, sys

dump, d = sys.argv[1], sys.argv[2]
want = {
    '$II3DF3L.zip': [('1', '724919', '2012-03-12 20:49:58', r'C:\Users\nfury\Documents\Alloy Research\StarFury.zip')],
    '$I103S5F.jpg': [('2', '222255', '2016-06-29 21:37:45', r'C:\Users\random\Downloads\bunnies.jpg')],
}
fails = 0
for name, exp in want.items():
    out = subprocess.run([dump, os.path.join(d, name)], capture_output=True, text=True).stdout
    got = [(f[0], f[1], f[2], f[6]) for f in (l.split('\t') for l in out.splitlines())]
    if got != exp:
        print(f'FAIL {name}: got {got}, want {exp}'); fails += 1
    else:
        print(f'ok   {name}')
# INFO2: 4 records; the first one is fully specified by plaso's test.
out = subprocess.run([dump, os.path.join(d, 'INFO2')], capture_output=True, text=True).stdout
rows = [l.split('\t') for l in out.splitlines()]
first = rows[0] if rows else None
if len(rows) != 4 or first[0] != '5' or first[2] != '2004-08-25 16:18:25' or first[3] != '1' or first[4] != '2' \
        or first[6] != r'C:\Documents and Settings\Mr. Evil\Desktop\lalsetup250.exe':
    print(f'FAIL INFO2: {rows}'); fails += 1
else:
    print('ok   INFO2 (4 records)')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
