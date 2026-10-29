#!/usr/bin/env python3
# Compare tests/ese_dump (src/esedb.c) with plaso's SRUM test values for its
# test_data/SRUDB.dat (data only): 18283 records over the three tables plaso
# reads, network usage row 3495 (DiagTrack, 2076 bytes sent, interface,
# S-1-5-18), application usage row 22167 ("Memory Compression") and network
# connectivity row 501 (connected since 2017-11-05 10:30:48.1679714).
# Usage: srum_check.py <ese_dump> <SRUDB.dat>
import datetime, subprocess, sys

dump, db = sys.argv[1], sys.argv[2]
NET, APP, CONN = '{973F5D5C-1D90-4944-BE8E-24B94231A174}', '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}', '{DD6636C4-8929-4683-974E-22C046A43763}'


def rows(table):
    out = subprocess.run([dump, db, table], capture_output=True).stdout.decode()
    return [dict(f.split('=', 1) for f in l.split('\t')) for l in out.splitlines()]


fails = 0
def check(c, m):
    global fails
    print(('ok   ' if c else 'FAIL ') + m)
    fails += 0 if c else 1


ids = {}
for r in rows('SruDbIdMapTable'):
    b = r['IdBlob']
    ids[int(r['IdIndex'])] = (int(r['IdType']), b)
def name(i):
    t, b = ids.get(i, (None, 'null'))
    if b == 'null': return str(i)
    raw = bytes.fromhex(b)
    if t == 3:
        n = raw[1]
        return 'S-%d-%d' % (raw[0], int.from_bytes(raw[2:8], 'big')) + ''.join('-%d' % int.from_bytes(raw[8 + 4 * k:12 + 4 * k], 'little') for k in range(n))
    return raw.decode('utf-16-le').rstrip('\0')

net, app, conn = rows(NET), rows(APP), rows(CONN)
check(len(net) + len(app) + len(conn) == 18283, f'{len(net)} + {len(app)} + {len(conn)} records (plaso: 18283)')
ole = lambda v: datetime.datetime(1899, 12, 30) + datetime.timedelta(milliseconds=round(float(v) * 86400000))
r = next((x for x in net if x['AutoIncId'] == '3495'), None)
check(r is not None and name(int(r['AppId'])) == 'DiagTrack' and r['BytesSent'] == '2076' and r['InterfaceLuid'] == '1689399632855040'
      and name(int(r['UserId'])) == 'S-1-5-18' and ole(r['TimeStamp']) == datetime.datetime(2017, 11, 5, 11, 32),
      'network usage 3495: DiagTrack, 2076 bytes sent, interface, S-1-5-18, 2017-11-05 11:32 (plaso)')
r = next((x for x in app if x['AutoIncId'] == '22167'), None)
check(r is not None and name(int(r['AppId'])) == 'Memory Compression' and ole(r['TimeStamp']) == datetime.datetime(2017, 11, 5, 11, 32),
      'application usage 22167: Memory Compression, 2017-11-05 11:32 (plaso)')
r = next((x for x in conn if x['AutoIncId'] == '501'), None)
ft = int(r['ConnectStartTime']) if r else 0
start = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
check(r is not None and r['AppId'] == '1' and start.strftime('%Y-%m-%dT%H:%M:%S.') + '%07d' % (ft % 10000000) == '2017-11-05T10:30:48.1679714'
      and ole(r['TimeStamp']) == datetime.datetime(2017, 11, 5, 13, 33), 'network connectivity 501: connect start 2017-11-05 10:30:48.1679714 (plaso)')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
