#!/usr/bin/env python3
# events --evtx end to end under wine, on plaso's System.evtx test file (data
# only). The expected rows - 25 service installs (7045), newest at
# 2015-08-08 09:32:12 "DNS Server", oldest at 2015-06-23 06:01:28 - were taken
# from the rendered XML with a separate regex filter, so this checks the
# command's channel / ID / --max / --since plumbing on top of the reader that
# tests/evtx_check.py verifies against plaso's published values.
# Usage: evtxfiles.py <winspect.exe> <dir with System.evtx and System2.evtx>
import json, os, shutil, subprocess, sys, tempfile

exe, src = sys.argv[1], sys.argv[2]
pfx = os.path.abspath(os.environ.get('WINEPREFIX', 'wpfx'))
# UTF-8 unix locale: wine maps non-ASCII file names through it.
env = dict(os.environ, WINEPREFIX=pfx, WINEDEBUG='-all', LC_ALL='C.UTF-8')
WINE = os.environ.get('WINE') or shutil.which('wine64') or shutil.which('wine') or '/usr/lib/wine/wine64'
dst = os.path.join(pfx, 'drive_c', 'evtx')
os.makedirs(dst, exist_ok=True)
for f in ('System.evtx', 'System2.evtx'):
    shutil.copy(os.path.join(src, f), dst)
fails = 0


def run(*args):
    with tempfile.TemporaryFile() as o:
        rc = subprocess.run([WINE, exe] + list(args), env=env, stdout=o, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, timeout=300).returncode
        o.seek(0)
        return rc, o.read().decode('utf-8', 'replace')


def check(cond, msg):
    global fails
    print(('ok   ' if cond else 'FAIL ') + msg)
    fails += 0 if cond else 1


rc, out = run('events', '--evtx', r'C:\evtx\System.evtx', '--max', '1000', '--json')
rows = json.loads(out) if rc == 0 else []
check(len(rows) == 25 and all(r['id'] == 7045 and r['channel'] == 'System' for r in rows),
      f'events --evtx System.evtx: {len(rows)} service installs (expected 25)')
check(rows and rows[0]['time'] == '2015-08-08 09:32:12' and 'DNS Server' in rows[0]['summary']
      and rows[-1]['time'] == '2015-06-23 06:01:28', 'events --evtx: newest / oldest rows and summary text')
rc, out = run('events', '--evtx', r'C:\evtx\System.evtx', '--json')
check(rc == 0 and len(json.loads(out)) == 20, 'events --evtx: default --max 20 per channel')
rc, out = run('events', '--evtx', r'C:\evtx\System.evtx', '--since', '24', '--json')
check(rc == 0 and json.loads(out) == [], 'events --evtx --since 24: 2015 events filtered out')
rc, out = run('events', '--evtx', r'C:\evtx\System.evtx', '--evtx', r'C:\evtx\System2.evtx', '--summary', '--json')
check(rc == 0 and json.loads(out) == [], 'events --evtx (two files) --summary: no failed logons in these logs')
rc, out = run('events', '--evtx', r'C:\windows\win.ini')
check(rc == 1, 'events --evtx on a non-evtx file: rc 1')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
