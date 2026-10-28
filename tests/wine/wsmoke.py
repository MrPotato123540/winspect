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
          ['certstore','--store','CA','--csv']]

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
