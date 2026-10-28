#!/usr/bin/env python3
# Offline-hive mode of winspect under wine, checked against real Windows hives
# from the regipy project's test data (its .xz data files only; no regipy code
# runs). Expected values are facts about those files that regipy's validation
# cases assert, re-derived where regipy counts differently:
#   * userassist: 29 programs (regipy reports 62 because it also counts the
#     two UEME_CTLCUACount session counters and lists each value twice);
#     EXCEL.EXE 4 runs 2012-04-04 15:43:14, RemoteDesktop 8 runs.
#   * mru: TypedPaths exactly as regipy's exact_expected_result, key time.
#   * bam: 55 records = 31 in bam\State\UserSettings + 24 in the legacy
#     bam\UserSettings key (regipy reads both too); the dwm.exe record.
#   * amcache: 1367 entries (1120 Root\File + 247 InventoryApplicationFile,
#     same total as regipy); the TPVMMondeu.dll entry's SHA-1 and times.
#   * usb: regipy's exact USBSTOR result for the Win10 1709 SYSTEM hive
#     (identity, install / last connected / last removed, disk id).
#   * shimcache: Windows 7 x86 cache, 330 entries (regipy's 660 counts the
#     identical ControlSet001 and ControlSet002 copies); the mfeann.exe entry
#     with the executed flag.
# Usage: python3 tests/wine/hives.py <winspect.exe> <regipy_tests/data dir>
import json, lzma, os, shutil, subprocess, sys, tempfile
exe, data = sys.argv[1:3]
pfx = os.path.abspath(os.environ.get('WINEPREFIX', 'wpfx'))
env = dict(os.environ, WINEPREFIX=pfx, WINEDEBUG='-all')
WINE = os.environ.get('WINE') or shutil.which('wine64') or shutil.which('wine') or '/usr/lib/wine/wine64'
hdir = os.path.join(pfx, 'drive_c', 'hives')
os.makedirs(hdir, exist_ok=True)
fails = 0

def hive(name):
    out = os.path.join(hdir, name)
    if not os.path.exists(out):
        with open(out, 'wb') as f:
            f.write(lzma.open(os.path.join(data, name + '.xz')).read())
    return 'C:\\hives\\' + name

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

rc, out = run('userassist', '--hive', hive('NTUSER.DAT'), '--json')
ua = json.loads(out)
check(len(ua) == 29, f'userassist --hive: {len(ua)} programs (29 expected)')
xl = [r for r in ua if r['program'].endswith('Office14\\EXCEL.EXE')]
check(xl and xl[0]['runs'] == 4 and xl[0]['last_run'] == '2012-04-04 15:43:14', 'userassist: EXCEL.EXE runs/time')
rd = [r for r in ua if r['program'] == 'Microsoft.Windows.RemoteDesktop']
check(rd and rd[0]['runs'] == 8 and rd[0]['last_run'] == '2012-04-03 22:06:58', 'userassist: RemoteDesktop runs/time')

rc, out = run('mru', '--hive', hive('NTUSER_BAGMRU.DAT'), '--json')
tp = [r for r in json.loads(out) if r['list'] == 'TypedPaths']
want = ['cmd', 'C:\\Offline\\AD', 'git', 'powershell', 'C:\\Program Files', 'Network',
        '\\\\wsl$\\Ubuntu\\projects\\CAD316_001\\partition_p1', '\\\\wsl$\\Ubuntu\\projects', '\\\\wsl$\\Ubuntu',
        'C:\\Users\\tony\\Github', 'C:\\Users\\tony\\Github\\velocity-client-master', 'C:\\Users\\tony\\Github\\cogz',
        'C:\\Users\\tony\\Github\\cogz\\cogz', 'Quick access', 'C:\\ProgramData\\chocolatey\\lib\\yara\\tools',
        'C:\\Training\\MT01\\exercise']
check([r['value'] for r in tp] == want, 'mru --hive: TypedPaths url1..url16 in order')
check(tp and tp[0]['time'] == '2022-02-06 13:46:04', 'mru: TypedPaths key last-write time')

ww = [r for r in json.loads(run('mru', '--hive', hive('NTUSER.DAT'), '--json')[1]) if r['list'] == 'WordWheel']
check(len(ww) == 6 and ww[0]['value'] == 'alloy' and ww[0]['time'] == '2012-04-04 15:45:18',
      'mru: WordWheelQuery 6 terms, newest "alloy" + key time')
rc, out = run('rdp', '--hive', hive('NTUSER.DAT'), '--json')
check(rc == 0 and json.loads(out) == [], 'rdp --hive: no RDP history in this hive -> []')

rc, out = run('bam', '--hive', hive('SYSTEM_WIN_10_1709'), '--json')
bam = json.loads(out)
check(len(bam) == 55, f'bam --hive: {len(bam)} records (55 expected)')
check(sum(r['location'] == 'legacy' for r in bam) == 24, 'bam: 24 records only in the legacy key')
dwm = [r for r in bam if r['path'] == '\\Device\\HarddiskVolume2\\Windows\\System32\\dwm.exe' and r['location'] == 'State']
check(dwm and dwm[0]['sid'] == 'S-1-5-90-0-1' and dwm[0]['last_run'] == '2020-04-19 09:09:35', 'bam: dwm.exe record')

rc, out = run('shimcache', '--hive', hive('SYSTEM'), '--json')
sc = json.loads(out)
check(len(sc) == 330, f'shimcache --hive (Windows 7): {len(sc)} entries (330 expected)')
mf = [r for r in sc if r['path'] == '\\??\\C:\\Program Files\\McAfee\\VirusScan Enterprise\\mfeann.exe']
check(mf and mf[0]['file_modified'] == '2011-01-12 12:08:00' and mf[0]['executed'] is True, 'shimcache: mfeann.exe + executed flag')

rc, out = run('amcache', hive('amcache.hve'), '--json')
am = json.loads(out)
check(len(am) == 1367, f'amcache: {len(am)} entries (1120 Root\\File + 247 Inventory = 1367)')
tp = [r for r in am if r['sha1'] == '056f4b9d9ec9b5dc548e1b460da889e44089d76f']
check(tp and tp[0]['path'] == 'C:\\Windows\\system32\\TPVMMondeu.dll' and tp[0]['recorded'] == '2017-08-03 11:34:02'
      and tp[0]['file_modified'] == '2017-03-17 05:06:04', 'amcache: TPVMMondeu.dll path / SHA-1 / times')
check(sum(r['layout'] == 'Inventory' for r in am) == 247, 'amcache: 247 InventoryApplicationFile entries')
rc, out = run('amcache', hive('amcache.hve'), '--sha1', '056F4B9D9EC9B5DC548E1B460DA889E44089D76F', '--json')
check(len(json.loads(out)) == 1, 'amcache --sha1 lookup (case-insensitive)')

rc, out = run('usb', '--hive', hive('SYSTEM_WIN_10_1709'), '--json')
u = json.loads(out)
check(len(u) == 1 and u[0]['serial'] == '200608767007B7C08A6A&0' and u[0]['friendly_name'] == 'SanDisk Cruzer USB Device'
      and u[0]['vendor'] == 'SanDisk' and u[0]['product'] == 'Cruzer' and u[0]['revision'] == '1.20',
      'usb --hive (Win10): device identity')
check(u and u[0]['first_installed'] == '2020-03-17 14:02:38' and u[0]['last_connected'] == '2020-03-17 14:02:38'
      and u[0]['last_removed'] == '2020-03-17 14:23:45', 'usb: first installed / last connected / last removed')
check(u and u[0]['disk_id'] == '{fc416b61-6437-11ea-bd0c-a483e7c21469}', 'usb: Partmgr disk id')
rc, out = run('usb', '--hive', hive('SYSTEM'), '--json')
u = json.loads(out)
check(u and 'E:' in u[0]['mounted_as'] and u[0]['last_connected'] is None, 'usb (Win7): drive letter via MountedDevices, no devprop times')

rc, out = run('autoruns', '--software', hive('SOFTWARE'), '--system', hive('SYSTEM'), '--ntuser', hive('NTUSER.DAT'), '--json')
ar = json.loads(out)
runs = [r['name'] for r in ar if r['location'] == 'HKLM\\...\\Run']
check(runs == ['VMware Tools', 'VMware User Process', 'Adobe ARM', 'McAfeeUpdaterUI', 'ShStatEXE',
               'McAfee Host Intrusion Prevention Tray', 'svchost'], 'autoruns offline: HKLM Run values as regipy lists them')
sv = [r for r in ar if r['name'] == 'svchost']
check(sv and 'masquerading' in sv[0]['reason'], 'autoruns: c:\\windows\\system32\\dllhost\\svchost.exe flagged as masquerading')
check(any(r['name'] == 'Sidebar' and r['location'].startswith('HKCU') for r in ar), 'autoruns: HKCU Run from NTUSER.DAT')
check(any(r['name'] == 'Userinit' and not r['suspicious'] for r in ar), 'autoruns: stock Userinit from another machine not flagged')
lsa = [r['command'] for r in ar if r['location'] == 'LSA' and r['name'] == 'Security Packages']
check(lsa == ['kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u'], 'autoruns: LSA Security Packages')
rc, out = run('autoruns', '--software', hive('SOFTWARE'), '--sig')
check(rc == 1, 'autoruns: --sig refused with offline hives')

rc, out = run('services', '--hive', hive('corrupted_system_hive'), '--drivers', '--json')
ab = [r for r in json.loads(out) if r['name'] == 'Abiosdsk']
check(ab and ab[0]['start_type'] == 'disabled', 'services --hive --drivers: Abiosdsk (Start 4) as regipy reads it')
rc, out = run('services', '--hive', hive('SYSTEM'), '--json')
sv = json.loads(out)
ad = [r for r in sv if r['name'] == 'AdobeARMservice']
check(ad and ad[0]['account'] == 'LocalSystem' and ad[0]['start_type'] == 'auto' and 'armsvc.exe' in ad[0]['binary_path'],
      'services --hive: AdobeARMservice config')
check(all(r['state'] == '-' for r in sv), 'services --hive: no live state claimed')
rc, out = run('services', '--hive', hive('SYSTEM'), '--sig')
check(rc == 1, 'services: --sig refused with --hive')

rc, out = run('sysinfo', '--software', hive('SOFTWARE'), '--system', hive('SYSTEM'), '--json')
si = json.loads(out)
cp, wv = si['computer'], si['windows']
check(cp['name'] == 'WKS-WIN732BITA' and cp['name_key_written'] == '2010-11-10 17:18:08'
      and 'WIN-V5T3CSP8U4H' in cp['other_names'], 'sysinfo: computer names (both control sets, as regipy)')
check(cp['last_shutdown_utc'] == '2012-04-04 01:58:40', 'sysinfo: last shutdown')
check(wv['ProductName'] == 'Windows 7 Ultimate' and wv['CurrentBuild'] == '7601' and wv['CSDVersion'] == 'Service Pack 1'
      and wv['install_date_utc'] == '2010-11-10 16:28:55' and wv['ProductId'] == '00426-067-1817155-86250', 'sysinfo: Windows version + install date')
check(wv['last_logged_on_user'] == 'SHIELDBASE\\rsydow' and wv['last_logon_key_written'] == '2012-04-04 12:20:41', 'sysinfo: last logged-on user')
ifs = {i['ip_address']: i for i in si['interfaces']}
check('10.3.58.5' in ifs and ifs['10.3.58.5']['default_gateway'] == '10.3.58.1' and ifs['10.3.58.5']['name_server'] == '10.3.58.4'
      and '192.168.1.123' in ifs, 'sysinfo: static interfaces as regipy reads them')
pr = si['profiles']
check(len(pr) == 11 and pr[0]['sid'] == 'S-1-5-18' and pr[0]['key_written'] == '2009-07-14 04:41:12', 'sysinfo: 11 profiles')
nw = [n for n in si['networks'] if n['name'] == 'shieldbase.local']
check(nw and nw[0]['type'] == 'wired' and nw[0]['category'] == 'domain' and nw[0]['first_connected_local'] == '2010-11-10 11:23:43'
      and nw[0]['last_connected_local'] == '2012-04-04 07:48:39', 'sysinfo: NetworkList profile with SYSTEMTIME dates')

rc, out = run('posture', '--software', hive('SOFTWARE'), '--system', hive('SYSTEM'), '--json')
po = {r['check']: r for r in json.loads(out)}
check(po['WDigest cleartext']['value'] == '1' and po['WDigest cleartext']['status'] == 'WARN',
      'posture offline: WDigest UseLogonCredential=1 -> WARN (regipy reads 1)')
check(po['Admin consent prompt']['value'] == '5' and po['UAC enabled']['value'] == '1', 'posture offline: UAC values as regipy')
check('AlwaysInstallElevated (HKCU)' not in po, 'posture offline: HKCU rules skipped without --ntuser')
rc, out = run('defender', '--software', hive('SOFTWARE'), '--json')
df = json.loads(out)
check(any(p['source'] == 'local' and p['name'] == 'DisableAntiSpyware' and p['protection_off'] for p in df['policies']),
      'defender offline: local DisableAntiSpyware=1 (regipy antispyware_disabled) reported')

rc, out = run('programs', '--software', hive('SOFTWARE'), '--json')
pg = json.loads(out)
check(len(pg) == 67 and any(r['id'] == 'AddressBook' for r in pg)
      and any(r['id'] == 'Connection Manager' and r['hidden'] for r in pg), 'programs --software: 67 Uninstall entries (as regipy)')
rc, out = run('programs', '--ntuser', hive('NTUSER_with_winscp.DAT'), '--json')
pg = json.loads(out)
zm = [r for r in pg if r['name'] == 'Zoom']
check(len(pg) == 4 and zm and zm[0]['version'] == '5.9.3 (3169)' and zm[0]['key_written'] == '2022-02-28 09:05:31'
      and zm[0]['scope'] == 'user', 'programs --ntuser: 4 per-user installs, Zoom fields')

rc, out = run('shellbags', '--ntuser', hive('NTUSER_BAGMRU.DAT'), '--json')
sb = json.loads(out)
check(len(sb) == 102, f'shellbags --ntuser: {len(sb)} entries (102 as regipy)')
rk = [r for r in sb if r['path'] == 'Search Folder\\tmp\\rekall']
check(rk and rk[0]['created'] == '2021-08-16 09:41:32' and rk[0]['accessed'] == '2021-08-16 09:43:22'
      and rk[0]['modified'] == '2021-08-16 09:41:32' and rk[0]['key_written'] == '2021-08-16 09:44:39'
      and rk[0]['mru_position'] == 0, 'shellbags: "Search Folder\\tmp\\rekall" path, item times, key time (regipy)')
rc, out = run('shellbags', '--usrclass', hive('UsrClass.dat'), '--json')
sb = json.loads(out)
check(len(sb) == 29, f'shellbags --usrclass: {len(sb)} entries (29 as regipy)')
db = [r for r in sb if r['path'] == 'Dropbox' and r['slot'] == 9]
check(db and db[0]['mru_position'] == 4 and db[0]['key_written'] == '2018-04-05 02:13:26', 'shellbags: Dropbox root slot 9, MRU position 4 (regipy)')
check(any(r['path'] == 'D:\\AKMonitor\\logs\\pic' for r in sb), 'shellbags: drive root + directory chain')
check(any(r['path'] == 'User Files\\Google Drive' and r['created'] for r in sb), 'shellbags: CFSF delegate item name + times')

rc, out = run('hive', hive('NTUSER.DAT'), 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', '--json')
h = json.loads(out)
check(h['checksum_ok'] and not h['dirty'] and h['keys'][0]['values'][0]['name'] == 'Sidebar', 'hive: Run key browse')
rc, out = run('hive', hive('NTUSER.DAT'), '--recurse', '--json')
check(len(json.loads(out)['keys']) == 1812, 'hive --recurse: 1812 keys')
rc, out = run('hive', hive('SYSTEM_WIN_10_1709'), 'Select', '--json')
check(json.loads(out)['dirty'] is True, 'hive: dirty hive reported')
rc, out = run('userassist', '--hive', 'C:\\nonexistent.dat')
check(rc == 1, 'missing hive file -> rc 1')

print(f'\n{fails} failure(s)')
sys.exit(1 if fails else 0)
