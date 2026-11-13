#!/usr/bin/env python3
# Smoke test under wine: runs every winspect command (text/--json/--csv) and
# checks the exit code is 0/1 (never a crash), --json parses, and every --csv
# row has the header's column count. Wine lacks some APIs (drivers, WMI,
# shares...), which is fine: those commands must fail CLEANLY with rc 1.
# Usage: python3 tests/wine/wsmoke.py <winspect.exe> [command-filter]
import subprocess, json, csv, io, os, sys
exe = sys.argv[1]
flt = sys.argv[2] if len(sys.argv) > 2 else None
# The wine prefix is a throw-away test sandbox: WINEPREFIX (default ./wpfx).
# The wine binary comes from $WINE, else wine64/wine on PATH, else
# /usr/lib/wine/wine64 (Debian/Ubuntu wine64 package).
import shutil
pfx = os.path.abspath(os.environ.get('WINEPREFIX', 'wpfx'))
# UTF-8 unix locale: wine maps non-ASCII file names through it.
env = dict(os.environ, WINEPREFIX=pfx, WINEDEBUG='-all', LC_ALL='C.UTF-8')
WINE = os.environ.get('WINE') or shutil.which('wine64') or shutil.which('wine') or '/usr/lib/wine/wine64'
WINESERVER = shutil.which('wineserver') or os.path.join(os.path.dirname(WINE), 'wineserver')
# Keep one wineserver alive for the whole run.
subprocess.Popen([WINESERVER, '-p'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
pe = r'C:\windows\system32\notepad.exe'
dll = r'C:\windows\system32\kernel32.dll'

import tempfile
# Output goes to files, not pipes: wine helper processes (wineserver, services)
# inherit the handles and would keep a pipe open forever.
def run(args, timeout=120):
    with tempfile.TemporaryFile() as o, tempfile.TemporaryFile() as e:
        try:
            p = subprocess.run([WINE, exe] + args, env=env, stdout=o, stderr=e,
                               stdin=subprocess.DEVNULL, timeout=timeout)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc = 'TIMEOUT'
        o.seek(0); e.seek(0)
        return rc, o.read().decode('utf-8', 'replace'), e.read().decode('utf-8', 'replace')

# Need a live pid: our own process tree - use 'list --json' to grab one.
rc, out, _ = run(['list', '--json'])
pid = None
try:
    procs = json.loads(out)
    for pr in procs:
        if 'explorer' in str(pr.get('name', '')).lower() or 'services' in str(pr.get('name', '')).lower():
            pid = str(pr.get('pid')); break
    if pid is None and procs:
        pid = str(procs[-1].get('pid'))
except Exception as e:
    print('list --json not parseable:', e)

nopid = ['list','services','drivers','autoruns','pipes','hosts','net','arp','routes','sessions',
         'shares','certstore','tasks','objects','defender','usb','prefetch','shimcache','bam',
         'firewall','taskcache','wmi','lnk','hunt','posture','events','hidden','sweep','userassist','mru','jumplist']
withpid = ['inspect','threads','handles','regions','token','secinfo','modules','verify','triage']
csvable = {'list','services','drivers','autoruns','pipes','hosts','net','arp','routes','sessions',
           'shares','certstore','tasks','objects','defender','usb','prefetch','shimcache','bam',
           'firewall','taskcache','wmi','lnk','hunt','posture','events','hidden','handles','regions','threads','modules'}
cases = []
for c in nopid:
    cases.append([c]); cases.append([c, '--json'])
    if c in csvable: cases.append([c, '--csv'])
if pid:
    for c in withpid:
        cases.append([c, pid]); cases.append([c, pid, '--json'])
        if c in csvable: cases.append([c, pid, '--csv'])
for f in (pe, dll):
    cases += [['pe', f], ['pe', f, '--json'], ['strings', f, '--ioc'], ['strings', f, '--json'],
              ['hash', f], ['hash', f, '--json'], ['sign', f], ['sign', f, '--json']]
# Every command has long help, and it names the command.
for c in sorted(set(nopid + withpid + ['pe', 'sign', 'strings', 'hash', 'lnk', 'streams', 'ssn', 'launch'])):
    cases.append(['help', c])
cases += [['ssn','NtOpenProcess'], ['ssn','NtOpenProcess','--json'], ['modules', pid or '4', '--unsigned'],
          ['drivers','--sig'], ['services','--flagged'], ['firewall','--inbound','--allow','--active','--csv'],
          ['objects','--global','--type','Mutant'], ['nosuchcmd'], ['pe'], ['pe','C:\\nonexistent.exe'],
          ['handles','--find','ntdll','--json'], ['handles','--find','x','--type','Key','--csv'], ['handles'],
          ['handles','4','--find','x'], ['prefetch','--flagged','--json'], ['hunt','--all','--csv'],
          ['events','--summary','--json'], ['events','--since','24'], ['events','--since','0'],
          ['autoruns','--sig','--flagged','--json'], ['lnk','--csv'], ['jumplist','--csv'],
          ['hive'], ['hive','C:\\nonexistent.dat'], ['hive','C:\\windows\\system32\\notepad.exe'],
          ['userassist','--hive','C:\\nonexistent.dat'], ['bam','--hive','C:\\windows\\win.ini'],
          ['shimcache','--hive','C:\\nonexistent.dat'], ['mru','--hive','C:\\nonexistent.dat','--json'],
          ['amcache'], ['amcache','--json'], ['amcache','C:\\nonexistent.hve','--csv'],
          ['sysinfo','--software','C:\\nonexistent'], ['services','--hive','C:\\nonexistent'],
          ['autoruns','--ntuser','C:\\nonexistent'], ['usb','--hive','C:\\nonexistent'],
          ['shellbags','--csv'], ['shellbags','--usrclass','C:\\nonexistent'], ['programs','--flagged'], ['pshistory'], ['pshistory','--csv'], ['pshistory','--all-users','--flagged'],
          ['pshistory','C:\\nonexistent'], ['pshistory','a','b'],
          ['recyclebin'], ['recyclebin','--csv'], ['recyclebin','--flagged','--json'], ['recyclebin','C:\\$Recycle.Bin'],
          ['recyclebin','C:\\windows\\win.ini'], ['recyclebin','C:\\nonexistent'], ['recyclebin','a','b'],
          ['bits'], ['bits','--csv'], ['bits','--flagged','--json'], ['bits','x'],
          ['tasks','--dir','C:\\tasks_copy','--csv'], ['tasks','--dir','C:\\nonexistent'], ['tasks','--dir'],
          ['comhijack'], ['comhijack','--all','--csv'], ['comhijack','--flagged','--json'], ['comhijack','--software','x'],
          ['comhijack','--usrclass','C:\\nonexistent'], ['comhijack','--usrclass','C:\\windows\\win.ini'], ['comhijack','x'],
          ['users'], ['users','--csv'], ['users','--flagged','--json'], ['users','--sam','C:\\nonexistent'],
          ['users','--sam','C:\\windows\\win.ini'], ['users','--sam'], ['users','x'],
          ['timeline'], ['timeline','--csv'], ['timeline','--flagged','--json'], ['timeline','--since','24'],
          ['timeline','--since','-5'], ['timeline','--sources','bam,mru'], ['timeline','--sources','bogus'], ['timeline','--since'],
          ['certstore','--software','C:\\nonexistent'], ['certstore','--software','a','--ntuser','b'], ['certstore','--ntuser'],
          ['certstore','--store','CA','--csv'],
          ['events','--evtx','C:\\nonexistent.evtx'], ['events','--evtx','C:\\windows\\win.ini','--json'], ['events','--evtx'], ['logons'], ['logons','--json'], ['logons','--csv','--all'], ['logons','--summary','--since','24'], ['logons','--evtx','C:\\nonexistent.evtx'], ['logons','--evtx','C:\\windows\\win.ini','--json'], ['logons','--type','99'], ['logons','--since','0'], ['logons','--user'], ['logons','bogus'], ['boots'], ['boots','--json'], ['boots','--csv','--since','24'], ['boots','--evtx','C:\\nonexistent.evtx'], ['boots','--evtx','C:\\windows\\win.ini'], ['boots','--max','0'], ['boots','--since'], ['boots','bogus'], ['dns'], ['dns','--json'], ['dns','--csv','--find','x'], ['dns','--find'], ['dns','bogus'], ['wer'], ['wer','--json'], ['wer','--csv','--modules'], ['wer','--flagged','--find','x'], ['wer','C:\\nonexistent','--json'], ['wer','C:\\windows','--csv'], ['wer','a','b'], ['wer','--find'], ['office'], ['office','--json'], ['office','--csv','--flagged'], ['office','--hive','C:\\offline\\NTUSER_office.DAT'], ['office','--hive','C:\\windows\\win.ini','--json'], ['office','--hive'], ['office','bogus'], ['capability'], ['capability','--json','--all'], ['capability','--csv','--flagged','--find','x'], ['capability','--software','C:\\offline\\SOFTWARE_cam'], ['capability','--ntuser','C:\\windows\\win.ini','--json'], ['capability','--software'], ['capability','bogus'], ['magic'], ['magic','C:\\windows'], ['magic','C:\\windows','--json','--flagged'], ['magic','C:\\magic','-r','--csv'], ['magic','C:\\windows\\win.ini','--json'], ['magic','C:\\nonexistent','--json'], ['magic','a','b'], ['magic','--bogus'], ['detections'], ['detections','--json'], ['detections','--csv','--find','x'], ['detections','C:\\windows\\win.ini','--json'], ['detections','C:\\nonexistent','--json'], ['detections','C:\\windows','--csv'], ['detections','a','b'], ['detections','--find'], ['hash','C:\\windows'], ['hash','C:\\windows','--csv'], ['hash','C:\\hashes','-r','--match','C:\\hashes\\iocs.txt'], ['hash','C:\\windows\\win.ini','--csv'], ['hash','C:\\windows\\win.ini','--match','C:\\nonexistent'], ['hash','C:\\nonexistent','--json'], ['hash','C:\\nonexistent','--csv'], ['hash','--match'], ['hash','C:\\windows','--bogus'],
          ['image'], ['image','C:\\nonexistent'], ['image','C:\\windows'], ['image','C:\\img2'], ['image','a','b'],
          ['timeline','--root','C:\\img2','--csv'], ['timeline','--root','C:\\nonexistent'], ['timeline','--root','C:\\img2','--sources','amcache,prefetch'],
          ['browser'], ['browser','--csv'], ['browser','--downloads','--json'], ['browser','--all-users','--flagged'], ['browser','--since','5'],
          ['browser','--home','C:\\img2\\Users\\bob'], ['browser','C:\\windows\\win.ini'], ['browser','C:\\nonexistent'], ['browser','--since','0'],
          ['pca'], ['pca','--csv'], ['pca','--flagged','--json'], ['pca','C:\\nonexistent'], ['pca','a','b'], ['setupapi'], ['setupapi','--all','--csv'], ['setupapi','C:\\saref','--utc-offset','+03:00','--json'], ['setupapi','C:\\saref\\setupapi.dev.log','--find','vbox','--flagged'], ['setupapi','--utc-offset','bad'], ['setupapi','C:\\nonexistent'], ['setupapi','a','b'],
          ['activities'], ['activities','--csv'], ['activities','--flagged','--json'], ['activities','--home','C:\\img2\\Users\\bob'],
          ['activities','C:\\windows\\win.ini'], ['activities','C:\\nonexistent'],
          ['mft'], ['mft','C:\\windows\\win.ini'], ['mft','C:\\nonexistent'], ['mft','C:\\mftref\\MFT','--timestomp','--csv'],
          ['mft','C:\\mftref\\MFT','--deleted','--find','zzz_none'], ['mft','C:\\mftref\\MFT','--find'], ['mft','--live','C:'], ['mft','--live','7'], ['mft','--live'], ['mft','--live','C:','--find','x'], ['mft','--image','C:\\ntfs\\vol.img','--csv'], ['mft','--image','C:\\ntfs\\vol_nolist.img','--json'], ['mft','--image','C:\\windows\\win.ini'], ['mft','--image'], ['mft','--image','C:\\ntfs\\vol.img','--live','C:'],
          ['usn'], ['usn','C:\\ntfs\\J'], ['usn','C:\\ntfs\\J','--csv','--flagged'], ['usn','C:\\ntfs\\J','--reason','bogus'],
          ['usn','C:\\ntfs\\J','--mft','C:\\windows\\win.ini'], ['usn','C:\\nonexistent'], ['usn','--live','C:'], ['usn','--live','7'], ['usn','--live'],
          ['srum'], ['srum','C:\\windows\\win.ini'], ['srum','C:\\srumref\\SRUDB.dat','--summary','--flagged','--csv'], ['srum','C:\\mftref\\MFT'],
          ['webcache'], ['webcache','C:\\windows\\win.ini'], ['webcache','C:\\srumref\\WebCacheV01.dat','--csv','--all'], ['webcache','--home','C:\\img2\\Users\\bob','--json']]

bad = 0
for args in cases:
    if flt and flt not in args[0]: continue
    rc, out, err = run(args)
    status = 'ok'
    if rc == 'TIMEOUT' or not isinstance(rc, int) or rc not in (0, 1):
        status = f'BAD rc={rc}'
    elif args[0] == 'help' and (rc != 0 or f'winspect {args[1]}' not in out):
        status = f'BAD help: rc={rc}, command name not in text'
    elif '--json' in args and rc == 0:
        try:
            json.loads(out)
        except Exception as e:
            status = f'BAD json: {e}; head={out[:120]!r}'
    elif '--csv' in args and rc == 0 and out.strip():
        rows = list(csv.reader(io.StringIO(out)))
        n = len(rows[0])
        badrows = [i for i, r in enumerate(rows) if len(r) != n]
        if badrows:
            status = f'BAD csv cols row {badrows[0]}: {rows[badrows[0]]} vs header {n}'
    if status != 'ok': bad += 1
    print(f'{status:6.200s}  rc={rc}  {" ".join(args)}' + ('' if status=='ok' else f'\n        stderr: {err.strip()[:200]}'))
print(f'\n{bad} problem(s) in {len(cases)} cases; pid={pid}')
sys.exit(1 if bad else 0)
