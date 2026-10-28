#!/usr/bin/env python3
# Check winspect's DestList parser (tests/destlist_dump) against real jump
# lists from Eric Zimmerman's JumpList project (MIT): only its sample FILES
# are used, never its code. Two kinds of checks:
#  * facts about those samples that project's own tests assert (entry/pinned
#    counts, format version, MRU order, host, MAC, interaction count, times)
#  * self-consistency inside each file: every DestList entry number must name
#    an existing link stream (hex), the pinned entries must match the header
#    count, MRU positions must be 0..n-1.
# Usage: python3 tests/destlist_check.py ./destlist_dump <TestFiles dir>
import json, os, subprocess, sys
from datetime import datetime, timezone
dump, root = sys.argv[1:3]

def ft(iso):          # "2015-11-24T20:31:34.4475253" (UTC) -> FILETIME
    date, frac = iso.split('.')
    t = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    secs = int((t - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds())
    return secs * 10**7 + int(frac.ljust(7, '0'))

# (folder, appid): (entries, pinned, version)
COUNTS = {
    ('Win10', '5f7b5f1e01b83767'): (0, 0, 0),
    ('Win10', '7e4dca80246863e3'): (1, 0, 3),
    ('Win10', 'f01b4d95cf55d32a'): (9, 4, 3),
    ('Win7', '1b4dd67f29cb1962'): (4, 0, 1),
    ('Win80', 'f01b4d95cf55d32a'): (4, 0, 1),
    ('Win81', 'f01b4d95cf55d32a'): (4, 0, 1),
    ('dtformats', '1b4dd67f29cb1962'): (7, 0, 1),
    ('dtformats', '9d1f905ce5044aee'): (2, 0, 3),
}
fails = 0
def check(cond, msg):
    global fails
    if not cond:
        print('FAIL', msg); fails += 1

for (folder, appid), (n, pinned, ver) in COUNTS.items():
    path = os.path.join(root, folder, appid + '.automaticDestinations-ms')
    out = subprocess.run([dump, path], capture_output=True, text=True)
    try:
        d = json.loads(out.stdout)
    except Exception:
        check(False, f'{folder}/{appid}: bad output rc={out.returncode}'); continue
    es = d.get('entries', [])
    tag = f'{folder}/{appid}'
    check(len(es) == n, f'{tag}: {len(es)} entries, expected {n}')
    check(sum(e['pinned'] for e in es) == pinned, f'{tag}: pinned count')
    if n:
        check(d['version'] == ver, f'{tag}: version {d["version"]} != {ver}')
        check(d['pinned_header'] == pinned, f'{tag}: header pinned count')
        check([e['mru'] for e in es] == list(range(n)), f'{tag}: MRU positions')
        streams = set(d['link_streams'])
        missing = [e['entry'] for e in es if format(e['entry'], 'x') not in streams]
        check(not missing, f'{tag}: entries without a link stream: {missing}')
        check(len(streams) == n, f'{tag}: {len(streams)} link streams for {n} entries')
    if (folder, appid) == ('Win10', 'f01b4d95cf55d32a'):
        check([e['entry'] for e in es] == [7, 9, 8, 1, 2, 6, 5, 4, 3], f'{tag}: MRU order')
        f = es[0]
        check(f['path'] == 'C:\\Temp', f'{tag}: first path {f["path"]!r}')
        check(f['host'] == 'desktop-annfp9d', f'{tag}: host {f["host"]!r}')
        check(f['mac'] == '00:15:5d:01:6d:02', f'{tag}: mac {f["mac"]!r}')
        check(f['interactions'] == 2, f'{tag}: interactions')
        check(not f['pinned'], f'{tag}: first not pinned')
        check(f['droid_time'] == ft('2015-11-24T18:39:02.4912714'), f'{tag}: droid time {f["droid_time"]}')
        check(f['last_used'] == ft('2015-11-24T20:31:34.4475253'), f'{tag}: last used {f["last_used"]}')
        p1 = [e for e in es if e['entry'] == 1]
        check(p1 and p1[0]['pinned'] and p1[0]['path'] == 'C:\\Users\\e\\Desktop', f'{tag}: pinned entry 1')
    if (folder, appid) == ('dtformats', '9d1f905ce5044aee'):
        for e in es:
            check(e['mac'] == '' and e['droid_time'] == 0 and e['host'] == '', f'{tag}: zero droid handled')
        check(es[0]['path'] == 'http://support.microsoft.com/kb/3124263', f'{tag}: url path')
        check(es[0]['last_used'] == ft('2016-01-17T13:08:08.2475045'), f'{tag}: url last used')
    print(f'checked {tag}  ({len(es)} entries)')
print(f'\n{fails} failure(s)')
sys.exit(1 if fails else 0)
