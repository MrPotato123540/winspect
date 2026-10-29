#!/usr/bin/env python3
# Compare tests/mft_dump (src/mft.c) with values published in plaso's
# tests/parsers/ntfs.py for its test_data/MFT file (data only, no
# third-party code runs): a regular file's path and times, a deleted file's
# path, an orphaned file's "$Orphan\..." path, and the Object ID (Distributed
# Link Tracking) of record 462, whose v1 UUID time and MAC are decoded here
# independently of the C code.
# Usage: mft_check.py <mft_dump> <MFT file>
import datetime, subprocess, sys

dump, mft = sys.argv[1], sys.argv[2]
rows = {}
for line in subprocess.run([dump, mft], capture_output=True).stdout.decode('utf-8').splitlines():
    f = line.split('\t')
    rows[int(f[0])] = f
fails = 0


def check(cond, msg):
    global fails
    print(('ok   ' if cond else 'FAIL ') + msg)
    fails += 0 if cond else 1


def ft(s):
    t = int(s)
    return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=t // 10)).strftime('%Y-%m-%dT%H:%M:%S.') + '%07d' % (t % 10000000)


by_path = {f[-1]: f for f in rows.values()}
sam = by_path.get('\\WINDOWS\\system32\\config\\SAM')
check(sam is not None and ft(sam[4]) == '2007-06-30T12:58:50.2740544' and ft(sam[8]) == '2007-06-30T12:58:50.2740544',
      'SAM: path and creation time 2007-06-30 12:58:50.2740544 (plaso)')
caja = [f for f in rows.values() if f[-1].endswith('\\Content.IE5\\9EUWFPZ1\\CAJA1S19.js')]
check(len(caja) == 1 and caja[0][-1] == '\\Documents and Settings\\Donald Blake\\Local Settings\\Temporary Internet Files\\Content.IE5\\9EUWFPZ1\\CAJA1S19.js'
      and caja[0][2] == '0' and ft(caja[0][4]) == '2009-01-14T03:38:58.5869993', 'deleted CAJA1S19.js: full path, not in use, time (plaso)')
orph = [f for f in rows.values() if f[-1] == '$Orphan\\session\\menu.text.css']
check(len(orph) == 1 and ft(orph[0][4]) == '2009-01-14T21:07:11.5721856', 'orphan: "$Orphan\\session\\menu.text.css" and its time (plaso)')
oid = rows.get(462, [''] * 15)[13]
ok = len(oid) == 32
if ok:
    b = bytes.fromhex(oid)
    uuid = '%08x-%04x-%04x-%s-%s' % (int.from_bytes(b[0:4], 'little'), int.from_bytes(b[4:6], 'little'),
                                     int.from_bytes(b[6:8], 'little'), b[8:10].hex(), b[10:16].hex())
    ts = ((int.from_bytes(b[6:8], 'little') & 0x0FFF) << 48) | (int.from_bytes(b[4:6], 'little') << 32) | int.from_bytes(b[0:4], 'little')
    when = datetime.datetime(1582, 10, 15) + datetime.timedelta(microseconds=ts // 10)
    mac = ':'.join('%02x' % x for x in b[10:16])
    ok = uuid == '9fe44b69-2709-11dc-a06b-db3099beae3c' and when.strftime('%Y-%m-%dT%H:%M:%S.') + '%07d' % (ts % 10000000) == '2007-06-30T12:58:40.5000041' and mac == 'db:30:99:be:ae:3c'
check(ok, 'record 462 Object ID: uuid, v1 time 2007-06-30 12:58:40.5000041, MAC db:30:99:be:ae:3c (plaso)')
check(len(rows) > 13000, f'{len(rows)} file records read')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
