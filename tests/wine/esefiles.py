#!/usr/bin/env python3
# srum and webcache end to end under wine on plaso's ESE test files (data
# only): SRUDB.dat - the network row plaso's test asserts, the summary order,
# the connectivity row's times (OLE date rounding), a flagged Downloads
# program; WebCacheV01.dat / PartitionsEx-WebCacheV01.dat - "Visited:" rows
# split into user and URL, and the Content entry plaso's test asserts.
# Usage: esefiles.py <winspect.exe> <dir with SRUDB.dat, WebCacheV01.dat, PartitionsEx-WebCacheV01.dat>
import json, os, shutil, subprocess, sys, tempfile

exe, src = sys.argv[1], sys.argv[2]
if os.path.isfile(src): src = os.path.dirname(src) or '.'
pfx = os.path.abspath(os.environ.get('WINEPREFIX', 'wpfx'))
env = dict(os.environ, WINEPREFIX=pfx, WINEDEBUG='-all', LC_ALL='C.UTF-8')
WINE = os.environ.get('WINE') or shutil.which('wine64') or shutil.which('wine') or '/usr/lib/wine/wine64'
dst = os.path.join(pfx, 'drive_c', 'srumref')
os.makedirs(dst, exist_ok=True)
for f in ('SRUDB.dat', 'WebCacheV01.dat', 'PartitionsEx-WebCacheV01.dat'):
    shutil.copy(os.path.join(src, f), os.path.join(dst, f))
fails = 0


def run(*args):
    with tempfile.TemporaryFile() as o:
        rc = subprocess.run([WINE, exe] + list(args), env=env, stdout=o, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, timeout=600).returncode
        o.seek(0)
        return rc, o.read().decode('utf-8', 'replace')


def check(c, m):
    global fails
    print(('ok   ' if c else 'FAIL ') + m)
    fails += 0 if c else 1


rc, out = run('srum', r'C:\srumref\SRUDB.dat', '--json')
r = json.loads(out) if rc == 0 else []
row = [x for x in r if x['id'] == 3495]
check(len(r) == 1840 and row and row[0]['application'] == 'DiagTrack' and row[0]['bytes_sent'] == 2076
      and row[0]['user'] == 'S-1-5-18' and row[0]['time'] == '2017-11-05 11:32:00', 'srum --json: 1840 network rows, row 3495 (plaso)')
rc, out = run('srum', r'C:\srumref\SRUDB.dat', '--summary', '--json')
s = json.loads(out) if rc == 0 else []
check(s and all(s[i]['bytes_sent'] >= s[i + 1]['bytes_sent'] for i in range(len(s) - 1))
      and any(x['suspicious'] and 'downloads\\setup-x86_64.exe' in x['application'] for x in s),
      f'srum --summary: {len(s)} applications, largest upload first, Downloads installer flagged')
rc, out = run('srum', r'C:\srumref\SRUDB.dat', '--connectivity', '--json')
c = [x for x in (json.loads(out) if rc == 0 else []) if x['id'] == 501]
check(c and c[0]['time'] == '2017-11-05 13:33:00' and c[0]['connect_start'] == '2017-11-05 10:30:48',
      'srum --connectivity: row 501 times (13:33:00, not 13:32:59)')
rc, out = run('srum', r'C:\srumref\SRUDB.dat', '--apps', '--find', 'Memory Compression', '--csv')
check(rc == 0 and out.count('\n') > 1 and 'Memory Compression' in out, 'srum --apps --find --csv')
rc, out = run('webcache', r'C:\srumref\WebCacheV01.dat', '--json')
w = json.loads(out) if rc == 0 else []
check(w and all(x['container'] in ('History', 'iedownload') for x in w)
      and any(x['user'] == 'test' and x['url'] == 'http://plaso.kiddaland.net/' and x['access_count'] == 10 for x in w),
      f'webcache: {len(w)} history rows, "Visited: test@..." split into user and URL')
rc, out = run('webcache', r'C:\srumref\PartitionsEx-WebCacheV01.dat', '--all', '--json')
w = [x for x in (json.loads(out) if rc == 0 else []) if x['container_id'] == 14 and x['entry_id'] == 63]
check(w and w[0]['url'] == 'https://www.bing.com/rs/3R/kD/ic/878ca0cd/b83d57c0.svg' and w[0]['filename'] == 'b83d57c0[1].svg'
      and w[0]['access_count'] == 5 and w[0]['file_size'] == 726 and w[0]['modified'] == '2019-03-20 17:22:14',
      'webcache --all: container 14 entry 63 (plaso)')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
