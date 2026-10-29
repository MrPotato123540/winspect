#!/usr/bin/env python3
# winspect mft end to end under wine on plaso's test_data/MFT (data only).
# Values: record 462 compmgmt.msc with its Object ID creation time and MAC,
# the deleted and the orphaned file of plaso's own tests, and --timestomp
# listing only files whose $SI creation time precedes $FN's.
# Usage: mftfile.py <winspect.exe> <MFT file>
import json, os, shutil, subprocess, sys, tempfile

exe, src = sys.argv[1], sys.argv[2]
pfx = os.path.abspath(os.environ.get('WINEPREFIX', 'wpfx'))
env = dict(os.environ, WINEPREFIX=pfx, WINEDEBUG='-all', LC_ALL='C.UTF-8')
WINE = os.environ.get('WINE') or shutil.which('wine64') or shutil.which('wine') or '/usr/lib/wine/wine64'
dst = os.path.join(pfx, 'drive_c', 'mftref')
os.makedirs(dst, exist_ok=True)
shutil.copy(src, os.path.join(dst, 'MFT'))
fails = 0


def run(*args):
    with tempfile.TemporaryFile() as o:
        rc = subprocess.run([WINE, exe] + list(args), env=env, stdout=o, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, timeout=600).returncode
        o.seek(0)
        return rc, o.read().decode('utf-8', 'replace')


def check(cond, msg):
    global fails
    print(('ok   ' if cond else 'FAIL ') + msg)
    fails += 0 if cond else 1


rc, out = run('mft', r'C:\mftref\MFT', '--find', 'compmgmt.msc', '--json')
r = json.loads(out) if rc == 0 else []
check(len(r) == 1 and r[0]['record'] == 462 and r[0]['objid_created'] == '2007-06-30 12:58:40'
      and r[0]['objid_mac'] == 'db:30:99:be:ae:3c' and r[0]['si_created'] == '2006-02-28 12:00:00'
      and r[0]['timestomp_hint'], 'mft --find: record 462, Object ID time / MAC (plaso), timestomp hint')
rc, out = run('mft', r'C:\mftref\MFT', '--deleted', '--find', 'CAJA1S19', '--json')
r = json.loads(out) if rc == 0 else []
check(len(r) == 1 and not r[0]['in_use'] and r[0]['path'].endswith('\\Content.IE5\\9EUWFPZ1\\CAJA1S19.js'),
      'mft --deleted: the deleted CAJA1S19.js with its full path (plaso)')
rc, out = run('mft', r'C:\mftref\MFT', '--find', 'menu.text.css', '--csv')
check(rc == 0 and '$Orphan\\session\\menu.text.css' in out, 'mft --csv: the orphan path (plaso)')
rc, out = run('mft', r'C:\mftref\MFT', '--timestomp', '--json')
r = json.loads(out) if rc == 0 else []
check(r and all(x['timestomp_hint'] and x['si_created'] < x['fn_created'] for x in r) and not any(x['directory'] for x in r),
      f'mft --timestomp: {len(r)} candidates, all with $SI created before $FN created')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
