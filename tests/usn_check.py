#!/usr/bin/env python3
# Compare tests/usn_dump (src/usn.c) with plaso's test_data/UsnJrnl.raw: the
# record count (19, as plaso's $UsnJrnl test on the volume this file comes
# from asserts) and the first record's values from that test; then every
# record against an independent decoder written here from Microsoft's
# USN_RECORD_V2 documentation. Usage: usn_check.py <usn_dump> <UsnJrnl.raw>
import struct, subprocess, sys

dump, path = sys.argv[1], sys.argv[2]
got = [l.split('\t') for l in subprocess.run([dump, path], capture_output=True).stdout.decode('utf-8').splitlines()]
d = open(path, 'rb').read()
want, o = [], 0
while o + 8 <= len(d):
    ln, major = struct.unpack_from('<IH', d, o)
    if ln == 0:
        o += 8
        continue
    fref, pref, usn, ts, reason = struct.unpack_from('<QQqQI', d, o + 8)
    nlen, noff = struct.unpack_from('<HH', d, o + 56)
    want.append([str(usn), str(ts), hex(fref), hex(pref), '0x%08x' % reason, d[o + noff:o + noff + nlen].decode('utf-16-le')])
    o += ln
fails = 0
def check(c, m):
    global fails
    print(('ok   ' if c else 'FAIL ') + m)
    fails += 0 if c else 1
check(len(got) == 19, f'{len(got)} records (plaso: 19)')
f = got[0] if got else [''] * 7
check(f[6] == 'Nieuw - Tekstdocument.txt' and f[2] == '0x100000000001e' and f[3] == '0x5000000000005'
      and f[4] == '0x00000100' and f[1] == '130933917272031250', 'first record: name, references, FILE_CREATE, 2015-11-30 21:15:27.2031250 (plaso)')
check([[g[0], g[1], g[2], g[3], g[4], g[6]] for g in got] == want, 'every record equal to an independent decoder')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
