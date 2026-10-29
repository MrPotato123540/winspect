#!/usr/bin/env python3
# winspect srum end to end under wine on plaso's test_data/SRUDB.dat (data
# only): the network row plaso's test asserts, the per-application summary
# order, the connectivity row's times (OLE date rounding), and a flagged
# program from the user's Downloads folder. Usage: srumfile.py <winspect.exe> <SRUDB.dat>
import json, os, shutil, subprocess, sys, tempfile

exe, src = sys.argv[1], sys.argv[2]
pfx = os.path.abspath(os.environ.get('WINEPREFIX', 'wpfx'))
env = dict(os.environ, WINEPREFIX=pfx, WINEDEBUG='-all', LC_ALL='C.UTF-8')
WINE = os.environ.get('WINE') or shutil.which('wine64') or shutil.which('wine') or '/usr/lib/wine/wine64'
dst = os.path.join(pfx, 'drive_c', 'srumref')
os.makedirs(dst, exist_ok=True)
shutil.copy(src, os.path.join(dst, 'SRUDB.dat'))
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
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
