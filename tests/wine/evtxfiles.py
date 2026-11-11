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
# Optional: Security logs of recorded attacks from the EVTX-ATTACK-SAMPLES
# collection (data only), for `logons`. Their file names say what was done.
ATTACK = ('DE_RDP_Tunneling_4624.evtx', 'LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx', 'LM_WMIC_4648_rpcss.evtx')
have_attack = all(os.path.exists(os.path.join(src, f)) for f in ATTACK)
if have_attack:
    for f in ATTACK:
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

# logons: System2.evtx also holds Security events. Independent of winspect,
# a regex over the rendered XML finds 80 logons (4624), 7 + 2 logoffs
# (4634 / 4647), 12 explicit-credential events (4648) and 65 privilege
# events (4672); the two interactive sessions that end inside the log are
# 0x3dd12 (16:58:39 -> 17:01:04) and 0x1aba6 (09:14:56 -> 09:17:13).
rc, out = run('logons', '--evtx', r'C:\evtx\System2.evtx', '--all', '--json')
rows = json.loads(out) if rc == 0 else []
lg = [r for r in rows if r['event'] == 'logon']
check(len(lg) == 80 and sum(1 for r in rows if r['event'] == 'explicit') == 12,
      f"logons --evtx --all: {len(lg)} logons, {sum(1 for r in rows if r['event'] == 'explicit')} explicit (expected 80 / 12)")
ended = {int(r['logon_id'], 16): (r['time'], r['logoff'], r['duration_s']) for r in lg if r['logoff']}
check(len(ended) == 9 and ended.get(0x3dd12) == ('2015-08-08 16:58:39', '2015-08-08 17:01:04', 145)
      and ended.get(0x1aba6) == ('2015-08-09 09:14:56', '2015-08-09 09:17:13', 137),
      'logons: 9 logons paired with their logoff, durations of the two interactive sessions')
check(0 < sum(1 for r in lg if r['admin']) <= 65, 'logons: privileged sessions marked admin (bounded by the 65 privilege events)')
rc, out = run('logons', '--evtx', r'C:\evtx\System2.evtx', '--json')
quiet = json.loads(out) if rc == 0 else []
check(quiet and all(not r['account'].endswith('$') and 'SYSTEM' not in r['account'] and r['logon_type'] != 5 for r in quiet)
      and len(quiet) < len(rows), 'logons (default): service / system / machine accounts hidden')
rc, out = run('logons', '--evtx', r'C:\evtx\System2.evtx', '--user', 'gold_administrator', '--type', '2', '--summary', '--json')
sm = json.loads(out) if rc == 0 else []
check(sm and all(g['logon_type'] == 2 and 'gold_administrator' in g['account'] for g in sm)
      and sum(g['count'] for g in sm) == sum(1 for r in quiet if r['logon_type'] == 2 and 'gold_administrator' in r['account']),
      'logons --summary --user --type: groups add up to the listed rows')
rc, out = run('logons', '--evtx', r'C:\evtx\System2.evtx', '--since', '24', '--json')
check(rc == 0 and json.loads(out) == [], 'logons --since 24: 2015 events filtered out')
rc, out = run('logons', '--evtx', r'C:\evtx\System2.evtx', '--csv')
check(rc == 0 and out.splitlines()[0].startswith('time,event,id,') and len(out.splitlines()) == len(quiet) + 1, 'logons --csv: header + one line per row')
rc, out = run('logons', '--evtx', r'C:\windows\win.ini', '--json')
check(rc == 1 and out.strip() == '[]', 'logons --evtx on a non-evtx file: rc 1, empty JSON array')
if have_attack:
    rc, out = run('logons', '--evtx', r'C:\evtx\DE_RDP_Tunneling_4624.evtx', '--flagged', '--json')
    fl = json.loads(out) if rc == 0 else []
    check(len(fl) == 1 and fl[0]['logon_type'] == 10 and fl[0]['source'] == '127.0.0.1' and 'loopback' in fl[0]['reason'],
          'logons: recorded RDP-over-tunnel logon flagged (type 10 from 127.0.0.1), anonymous NTLMv1 null sessions not')
    rc, out = run('logons', '--evtx', r'C:\evtx\LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx', '--json')
    fl = json.loads(out) if rc == 0 else []
    check(len(fl) == 1 and fl[0]['logon_type'] == 9 and fl[0]['suspicious'] and fl[0]['admin'] and 'pass-the-hash' in fl[0]['reason'],
          'logons: recorded pass-the-hash logon flagged (type 9 by seclogo) and marked admin')
    rc, out = run('logons', '--evtx', r'C:\evtx\LM_WMIC_4648_rpcss.evtx', '--json')
    fl = json.loads(out) if rc == 0 else []
    check(len(fl) == 3 and all(r['event'] == 'explicit' and r['by'] == 'EXAMPLE\\user01' and not r['suspicious'] for r in fl)
          and any(r['process'].lower().endswith('wmic.exe') for r in fl),
          'logons: explicit-credential use (WMIC with another account) listed with who / as whom / process, not flagged')
else:
    print('skip logons attack samples (not downloaded)')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
