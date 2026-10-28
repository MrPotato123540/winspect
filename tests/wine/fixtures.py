#!/usr/bin/env python3
# Functional test under wine: seeds a THROW-AWAY wine prefix with known-bad
# artifacts (Run key in a user-writable dir, IFEO debugger, changed BootExecute,
# extra LSA package, firewall rule, Defender exclusion, USB, BAM, ShimCache,
# task without SD, unquoted service path), runs winspect and asserts that each
# one is reported WITH the expected reason - and that the benign controls
# (stock LSA package, a normal firewall rule) are not. Never point WINEPREFIX
# at a prefix you care about. Usage: python3 tests/wine/fixtures.py <winspect.exe>
import subprocess, os, sys, json, struct, tempfile
exe = sys.argv[1]
# The wine prefix is a throw-away test sandbox: WINEPREFIX (default ./wpfx).
# The wine binary comes from $WINE, else wine64/wine on PATH, else
# /usr/lib/wine/wine64 (Debian/Ubuntu wine64 package).
import shutil
pfx = os.path.abspath(os.environ.get('WINEPREFIX', 'wpfx'))
env = dict(os.environ, WINEPREFIX=pfx, WINEDEBUG='-all')
WINE = os.environ.get('WINE') or shutil.which('wine64') or shutil.which('wine') or '/usr/lib/wine/wine64'
WINESERVER = shutil.which('wineserver') or os.path.join(os.path.dirname(WINE), 'wineserver')

def wine(args, timeout=120):
    with tempfile.TemporaryFile() as o, tempfile.TemporaryFile() as e:
        try:
            rc = subprocess.run([WINE] + args, env=env, stdout=o, stderr=e,
                                stdin=subprocess.DEVNULL, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            rc = 'TIMEOUT'
        o.seek(0); e.seek(0)
        return rc, o.read().decode('utf-8', 'replace'), e.read().decode('utf-8', 'replace')

def reg(*a):
    rc, out, err = wine(['reg', 'add'] + list(a) + ['/f'])
    if rc != 0:
        print('reg add failed:', a, err.strip()[:200])

HK = 'HKLM\\'
# --- autoruns -----------------------------------------------------------------
reg(HK + r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', '/v', 'Updater', '/t', 'REG_SZ', '/d', r'C:\Users\Public\upd.exe')
reg(HK + r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe', '/v', 'Debugger', '/t', 'REG_SZ', '/d', r'C:\windows\system32\cmd.exe')
reg(HK + r'SYSTEM\CurrentControlSet\Control\Session Manager', '/v', 'BootExecute', '/t', 'REG_MULTI_SZ', '/d', r'autocheck autochk *\0evilboot.exe')
reg(HK + r'SYSTEM\CurrentControlSet\Control\Lsa', '/v', 'Notification Packages', '/t', 'REG_MULTI_SZ', '/d', r'scecli\0passfilt_x')
reg(HK + r'SOFTWARE\Microsoft\NetSh', '/v', 'evilhelper', '/t', 'REG_SZ', '/d', r'C:\tools\nshelper.dll')
# newer ASEPs (Autoruns' other tabs, by concept)
HKCU = 'HKCU\\'
reg(HKCU + r'Software\Microsoft\Command Processor', '/v', 'AutoRun', '/t', 'REG_SZ', '/d', r'C:\Users\Public\init.bat')
reg(HKCU + r'Environment', '/v', 'UserInitMprLogonScript', '/t', 'REG_SZ', '/d', r'C:\ProgramData\logon.cmd')
reg(HKCU + r'Software\Classes\ms-settings\Shell\Open\command', '/ve', '/t', 'REG_SZ', '/d', r'C:\windows\system32\cmd.exe /c msuac')
reg(HKCU + r'Software\Microsoft\Office test\Special\Perf', '/ve', '/t', 'REG_SZ', '/d', r'C:\Users\Public\perf.dll')
reg(HK + r'SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls', '/v', 'certx', '/t', 'REG_SZ', '/d', r'C:\windows\system32\certx.dll')
reg(HK + r'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\EvilTP', '/v', 'DllName', '/t', 'REG_SZ', '/d', r'C:\tools\tp.dll')
reg(HK + r'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient', '/v', 'DllName', '/t', 'REG_EXPAND_SZ', '/d', r'%systemroot%\system32\w32time.dll')
reg(HK + r'SOFTWARE\Microsoft\Active Setup\Installed Components\{TEST-AS}', '/v', 'StubPath', '/t', 'REG_SZ', '/d', r'C:\Users\Public\as.exe')
# --- firewall -----------------------------------------------------------------
reg(HK + r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules',
    '/v', '{TEST-1}', '/t', 'REG_SZ', '/d',
    r'v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|App=%APPDATA%\x\listener.exe|Name=Test Listener|')
reg(HK + r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules',
    '/v', '{TEST-2}', '/t', 'REG_SZ', '/d',
    r'v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=17|RPort=53|App=C:\windows\system32\svchost.exe|Name=Benign Block|')
# --- defender -----------------------------------------------------------------
reg(HK + r'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths', '/v', r'C:\Temp\drop', '/t', 'REG_DWORD', '/d', '0')
reg(HK + r'SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection', '/v', 'DisableRealtimeMonitoring', '/t', 'REG_DWORD', '/d', '1')
# --- usb ----------------------------------------------------------------------
reg(HK + r'SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\4C530001234567&0', '/v', 'FriendlyName', '/t', 'REG_SZ', '/d', 'SanDisk Cruzer USB Device')
reg(HK + r'SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Generic&Prod_Flash&Rev_0.1\7&2a5c3f1&0', '/v', 'FriendlyName', '/t', 'REG_SZ', '/d', 'Generic Flash')
# --- bam ----------------------------------------------------------------------
ft = struct.pack('<Q', 133500000000000000) + b'\0' * 16
reg(HK + r'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1-2-3-1001',
    '/v', r'\Device\HarddiskVolume3\Users\bob\AppData\Local\Temp\a.exe', '/t', 'REG_BINARY', '/d', ft.hex())
reg(HK + r'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1-2-3-1001',
    '/v', 'Version', '/t', 'REG_DWORD', '/d', '1')
# legacy (1709) location, left behind after upgrades: must be read too
reg(HK + r'SYSTEM\CurrentControlSet\Services\bam\UserSettings\S-1-5-21-1-2-3-1001',
    '/v', r'\Device\HarddiskVolume3\Tools\oldtool.exe', '/t', 'REG_BINARY', '/d', ft.hex())
# --- shimcache (Win10 layout, 2 entries) ---------------------------------------
def shim_entry(path, t):
    p = path.encode('utf-16-le')
    body = struct.pack('<H', len(p)) + p + struct.pack('<Q', t) + struct.pack('<I', 0)
    return b'10ts' + b'\0' * 4 + struct.pack('<I', len(body)) + body
blob = struct.pack('<I', 0x34) + b'\0' * (0x34 - 4)
blob += shim_entry(r'C:\Users\bob\Downloads\tool.exe', 133400000000000000)
blob += shim_entry(r'C:\windows\system32\notepad.exe', 133300000000000000)
reg(HK + r'SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache', '/v', 'AppCompatCache', '/t', 'REG_BINARY', '/d', blob.hex())
# --- taskcache + task XML ------------------------------------------------------
tree = HK + r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
reg(tree + r'\HiddenOne', '/v', 'Id', '/t', 'REG_SZ', '/d', '{11111111-1111-1111-1111-111111111111}')
reg(tree + r'\GoodOne', '/v', 'Id', '/t', 'REG_SZ', '/d', '{22222222-2222-2222-2222-222222222222}')
# Self-relative SD "O:BAG:SYD:(A;;FA;;;BA)" - binary via a tiny known blob is
# awkward; any bytes count as "has SD" for check 1, and an invalid SD is never
# reported as deny, so a placeholder is fine here.
reg(tree + r'\GoodOne', '/v', 'SD', '/t', 'REG_BINARY', '/d', '0100048000000000000000000000000014000000')
tasks = os.path.join(pfx, 'drive_c', 'windows', 'system32', 'Tasks')
os.makedirs(tasks, exist_ok=True)
xml = ('<?xml version="1.0" encoding="UTF-16"?>\n<Task><Settings><Hidden>true</Hidden></Settings>'
       '<Actions><Exec><Command>C:\\windows\\system32\\wscript.exe</Command>'
       '<Arguments>//B C:\\ProgramData\\x.vbs</Arguments></Exec></Actions></Task>')
with open(os.path.join(tasks, 'GoodOne'), 'wb') as f:
    f.write(b'\xff\xfe' + xml.encode('utf-16-le'))
# --- prefetch: an uncompressed v30 SCCA file (pre-MAM layout is still valid) ---
def make_pf(exe='EVIL.EXE', h=0xDEADBEEF, files=None):
    d = bytearray(1024)
    struct.pack_into('<I', d, 0, 30)
    d[4:8] = b'SCCA'
    name = exe.encode('utf-16-le')
    d[16:16 + len(name)] = name
    struct.pack_into('<I', d, 76, h)
    struct.pack_into('<I', d, 84, 0x130)              # long-form file info
    struct.pack_into('<Q', d, 128, 133500000000000000) # last run
    struct.pack_into('<Q', d, 136, 133400000000000000) # previous run
    struct.pack_into('<I', d, 208, 3)                  # run count
    files = files or ('\\VOLUME{1}\\WINDOWS\\SYSTEM32\\NTDLL.DLL\0\\VOLUME{1}\\USERS\\BOB\\APPDATA\\LOCAL\\TEMP\\PAYLOAD.DLL\0'
                      '\\VOLUME{1}\\USERS\\BOB\\DOWNLOADS\\EVIL.EXE\0')
    fb = files.encode('utf-16-le')
    struct.pack_into('<II', d, 100, 400, len(fb))
    d[400:400 + len(fb)] = fb
    vol = 700
    struct.pack_into('<III', d, 108, vol, 1, 120)
    struct.pack_into('<II', d, vol, 96, 9)            # path at +96, 9 chars
    struct.pack_into('<Q', d, vol + 8, 133000000000000000)
    struct.pack_into('<I', d, vol + 16, 0xCAFE1234)
    dev = '\\DEVICE\\X'.encode('utf-16-le')
    d[vol + 96:vol + 96 + len(dev)] = dev
    return bytes(d)
pfdir = os.path.join(pfx, 'drive_c', 'windows', 'Prefetch')
os.makedirs(pfdir, exist_ok=True)
with open(os.path.join(pfdir, 'EVIL.EXE-DEADBEEF.pf'), 'wb') as f:
    f.write(make_pf())
with open(os.path.join(pfdir, 'NOTEPAD.EXE-12345678.pf'), 'wb') as f:
    f.write(make_pf('NOTEPAD.EXE', 0x12345678, '\\VOLUME{1}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\0'))

# --- shortcuts: a Startup .lnk that runs powershell, a Recent .lnk -------------
def make_lnk(target, args):
    clsid = bytes([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46])
    hdr = bytearray(0x4C)
    struct.pack_into('<I', hdr, 0, 0x4C)
    hdr[4:20] = clsid
    struct.pack_into('<I', hdr, 0x14, 0x02 | 0x20 | 0x80)   # LinkInfo | Args | Unicode
    struct.pack_into('<Q', hdr, 0x1C, 133000000000000000)
    base = target.encode('ascii') + b'\0'
    li = bytearray(0x1C)
    total = 0x1C + len(base) + 1                          # + empty suffix
    struct.pack_into('<IIIIIII', li, 0, total, 0x1C, 1, 0, 0x1C, 0, 0x1C + len(base))
    li += base + b'\0'
    a = args.encode('utf-16-le')
    sd = struct.pack('<H', len(args)) + a
    return bytes(hdr) + bytes(li) + sd
def make_destlist(entries):
    # Version-3 (Windows 10) DestList: 32-byte header, then per entry 130 fixed
    # bytes + UTF-16 path + 4 trailing bytes. entries: (number, path, pinned, interactions)
    hdr = struct.pack('<IIIfIIII', 3, len(entries), sum(1 for e in entries if e[2]), 0.0,
                      max(e[0] for e in entries), 0, len(entries), 0)
    body = b''
    for num, path, pinned, inter in entries:
        e = bytearray(130)
        e[72:72 + 8] = b'ws-hr-07'
        struct.pack_into('<I', e, 88, num)
        struct.pack_into('<Q', e, 100, 133500000000000000)
        struct.pack_into('<i', e, 108, 0 if pinned else -1)
        struct.pack_into('<I', e, 116, inter)
        struct.pack_into('<H', e, 128, len(path))
        body += bytes(e) + path.encode('utf-16-le') + b'\0' * 4
    return hdr + body
def make_lnk_crafted(target, args, machine, mac):
    # A link on a REMOVABLE volume (serial 1A2B3C4D, label "STICK") whose
    # WORKING_DIR count claims 1000 characters: the shell reads 260 and the
    # arguments follow - hidden from parsers that trust the count. Ends with a
    # TrackerDataBlock naming the machine and a v1 droid carrying its MAC.
    clsid = bytes([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46])
    hdr = bytearray(0x4C)
    struct.pack_into('<I', hdr, 0, 0x4C); hdr[4:20] = clsid
    struct.pack_into('<I', hdr, 0x14, 0x02 | 0x10 | 0x20 | 0x80)
    vol = struct.pack('<IIII', 0x16, 2, 0x1A2B3C4D, 0x10) + b'STICK\0'
    base = target.encode('ascii') + b'\0'
    vo = 0x1C; bo = vo + len(vol); so = bo + len(base)
    li = struct.pack('<IIIIIII', so + 1, 0x1C, 1, vo, bo, 0, so) + vol + base + b'\0'
    wd = struct.pack('<H', 1000) + ('C:\\' + ' ' * 257).encode('utf-16-le')
    sd = wd + struct.pack('<H', len(args)) + args.encode('utf-16-le')
    droid = bytes(6) + b'\x00\x11' + bytes(2) + bytes.fromhex(mac.replace(':', ''))
    tr = struct.pack('<II', 0x60, 0xA0000003) + struct.pack('<II', 0x58, 0)
    tr += machine.encode('ascii').ljust(16, b'\0') + bytes(16) + droid + bytes(32)
    return bytes(hdr) + li + sd + tr + b'\0' * 4
users = os.path.join(pfx, 'drive_c', 'users')
uname = [u for u in os.listdir(users) if u.lower() not in ('public',)][0]
roam = os.path.join(users, uname, 'AppData', 'Roaming', 'Microsoft', 'Windows')
startup = os.path.join(roam, 'Start Menu', 'Programs', 'Startup')
recent = os.path.join(roam, 'Recent')
os.makedirs(startup, exist_ok=True); os.makedirs(recent, exist_ok=True)
with open(os.path.join(startup, 'Updater.lnk'), 'wb') as f:
    f.write(make_lnk(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-nop -w hidden -enc AAAA'))
with open(os.path.join(recent, 'secret.docx.lnk'), 'wb') as f:
    f.write(make_lnk(r'E:\loot\secret.docx', ''))
with open(os.path.join(recent, 'invoice.lnk'), 'wb') as f:
    f.write(make_lnk_crafted(r'F:\invoice.pdf', '/c start payload.exe', 'ws-hr-07', 'aa:bb:cc:00:11:22'))
with open(os.path.join(startup, 'Helper.lnk'), 'wb') as f:
    f.write(make_lnk_crafted(r'F:\helper.pdf', '/c helper.cmd', 'ws-hr-07', 'aa:bb:cc:00:11:22'))

# --- jump lists: an automatic (compound file) and a custom (back-to-back) one ---
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfbwrite
auto = os.path.join(recent, 'AutomaticDestinations'); os.makedirs(auto, exist_ok=True)
cust = os.path.join(recent, 'CustomDestinations'); os.makedirs(cust, exist_ok=True)
with open(os.path.join(auto, '5f7b5f1e01b83767.automaticDestinations-ms'), 'wb') as f:
    f.write(cfbwrite.build([('1', make_lnk(r'F:\usb\plans.pdf', '')),
                            ('2', make_lnk(r'C:\Users\Public\Downloads\tool.exe', '-x')),
                            ('DestList', make_destlist([(1, 'F:\\usb\\plans.pdf', True, 5)]))]))
with open(os.path.join(cust, 'abcdef0123456789.customDestinations-ms'), 'wb') as f:
    f.write(b'\xab' * 24 + make_lnk(r'C:\Windows\System32\mshta.exe', 'http://x/y.hta') +
            b'\x00' * 8 + make_lnk(r'D:\docs\report.docx', ''))

# --- posture: weak settings + an AutoLogon password that must never be printed --
reg(HK + r'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', '/v', 'UseLogonCredential', '/t', 'REG_DWORD', '/d', '1')
reg(HK + r'SOFTWARE\Policies\Microsoft\Windows\Installer', '/v', 'AlwaysInstallElevated', '/t', 'REG_DWORD', '/d', '1')
reg(HK + r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', '/v', 'AutoAdminLogon', '/t', 'REG_SZ', '/d', '1')
reg(HK + r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', '/v', 'DefaultPassword', '/t', 'REG_SZ', '/d', 'hunter2-SECRET')

# --- hosts: one block entry (fine) and one redirect (flagged) -------------------
etc = os.path.join(pfx, 'drive_c', 'windows', 'system32', 'drivers', 'etc')
os.makedirs(etc, exist_ok=True)
with open(os.path.join(etc, 'hosts'), 'w') as f:
    f.write('# test hosts\r\n127.0.0.1 localhost\r\n0.0.0.0 ads.example\r\n'
            '6.6.6.6 update.vendor.example   # diverted\r\n')

# --- userassist: a ROT13-encoded GUI launch of a program in Temp ----------------
import codecs as _codecs
ua = bytearray(72)
struct.pack_into('<I', ua, 4, 3)
struct.pack_into('<Q', ua, 60, 133500000000000000)
reg(r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count',
    '/v', _codecs.encode(r'C:\Users\Public\AppData\Local\Temp\dropper.exe', 'rot13'),
    '/t', 'REG_BINARY', '/d', ua.hex())

# --- mru: an encoded PowerShell typed into Run, two recent documents ---------------
E = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer'
reg(E + r'\RunMRU', '/v', 'a', '/t', 'REG_SZ', '/d', 'notepad\\1')
reg(E + r'\RunMRU', '/v', 'b', '/t', 'REG_SZ', '/d', 'powershell -nop -w hidden -enc SQBFAFgA\\1')
reg(E + r'\RunMRU', '/v', 'MRUList', '/t', 'REG_SZ', '/d', 'ba')
def rdoc(name):
    return (name.encode('utf-16-le') + b'\0\0' + b'\x14\x00').hex()
reg(E + r'\RecentDocs', '/v', '0', '/t', 'REG_BINARY', '/d', rdoc('old.docx'))
reg(E + r'\RecentDocs', '/v', '1', '/t', 'REG_BINARY', '/d', rdoc('new.xlsx'))
reg(E + r'\RecentDocs', '/v', 'MRUListEx', '/t', 'REG_BINARY', '/d', '0100000000000000ffffffff')

# --- programs: a remote-access tool among installed software -------------------
U = HK + r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
reg(U + r'\AnyDesk', '/v', 'DisplayName', '/t', 'REG_SZ', '/d', 'AnyDesk')
reg(U + r'\AnyDesk', '/v', 'Publisher', '/t', 'REG_SZ', '/d', 'AnyDesk Software GmbH')
reg(U + r'\NotepadPP', '/v', 'DisplayName', '/t', 'REG_SZ', '/d', 'Notepad++ (64-bit x64)')

# --- rdp: outgoing Remote Desktop history ---------------------------------------
T = r'HKCU\Software\Microsoft\Terminal Server Client'
reg(T + r'\Default', '/v', 'MRU0', '/t', 'REG_SZ', '/d', '10.10.5.21')
reg(T + r'\Default', '/v', 'MRU1', '/t', 'REG_SZ', '/d', 'fileserver01.corp.example')
reg(T + r'\Servers\10.10.5.21', '/v', 'UsernameHint', '/t', 'REG_SZ', '/d', r'CORP\svc_backup')
reg(T + r'\Servers\10.10.5.21', '/v', 'CertHash', '/t', 'REG_BINARY', '/d', 'a1b2c3d4')

# --- service with an unquoted path ---------------------------------------------
svc = HK + r'SYSTEM\CurrentControlSet\Services\WsTestSvc'
reg(svc, '/v', 'ImagePath', '/t', 'REG_EXPAND_SZ', '/d', r'C:\Program Files\My App\svc.exe -k test')
reg(svc, '/v', 'Type', '/t', 'REG_DWORD', '/d', '16')
reg(svc, '/v', 'Start', '/t', 'REG_DWORD', '/d', '3')
reg(svc, '/v', 'ObjectName', '/t', 'REG_SZ', '/d', 'LocalSystem')
# services.exe caches the registry: restart the prefix so SCM sees the new one.
subprocess.run([WINESERVER, '-k'], env=env)

checks = [
    (['autoruns', '--json'], [('Updater', 'user-writable path'), ('sethc.exe', 'rarely legitimate location'),
                               ('evilboot.exe', 'non-default value'), ('passfilt_x', 'non-default value'),
                               ('nshelper.dll', 'non-default value')], ['scecli']),
    (['autoruns', '--json'], [('init.bat', 'user-writable path'), ('logon.cmd', 'user-writable path'),
                               ('msuac', 'rarely legitimate location'), ('perf.dll', 'user-writable path'),
                               ('certx.dll', 'rarely legitimate location'), ('tp.dll', 'non-default value'),
                               ('as.exe', 'user-writable path')], ['w32time.dll', '%1']),
    (['firewall', '--json'], [('Test Listener', 'true')], ['Benign Block"']),
    (['programs', '--json'], [('"name":"AnyDesk"', 'remote-access (RMM) tool'), ('"rmm_tool":"AnyDesk"', None)], ['Notepad++']),
    (['rdp', '--json'], [('"source":"Default","position":0', '"host":"10.10.5.21"'),
                         ('fileserver01.corp.example', '"position":1'),
                         ('"source":"Servers"', 'CORP\\\\svc_backup'), ('"certificate_accepted":true', None)], []),
    (['defender', '--json'], [('C:\\\\Temp\\\\drop', None), ('DisableRealtimeMonitoring', None)], []),
    (['usb', '--json'], [('SanDisk', None), ('"generated_serial":true', None)], []),
    (['bam', '--json'], [('a.exe', '"location":"State"'), ('"user_writable_dir":true', None),
                          ('oldtool.exe', '"location":"legacy"')], ['"path":"Version"']),
    (['shimcache', '--json'], [('tool.exe', None), ('notepad.exe', None)], []),
    (['taskcache', '--json'], [('HiddenOne', 'no SD value'), ('GoodOne', None)], []),
    (['tasks', '--json'], [('GoodOne', 'hidden task outside')], []),
    (['services', '--json', '--flagged'], [('WsTestSvc', 'unquoted path with spaces')], []),
    (['autoruns', '--json'], [('Updater.lnk', 'shortcut launches a script host')], []),
    (['lnk', '--json'], [('E:\\\\loot\\\\secret.docx', None),
                          ('/c start payload.exe', 'string count > 260'), ('"machine_id":"ws-hr-07"', '"mac":"aa:bb:cc:00:11:22"'),
                          ('"drive_type":"removable"', '"volume_serial":"1A2B3C4D"'), ('"volume_label":"STICK"', None)], ['secret.docx']),
    (['autoruns', '--json'], [('Helper.lnk', 'string count > 260')], []),
    (['hosts', '--json'], [('update.vendor.example', '"suspicious":true'), ('ads.example', '"kind":"block"')], ['ads.example', 'localhost']),
    (['userassist', '--json'], [('dropper.exe', 'user-writable'), ('"runs":3', None)], []),
    (['mru', '--json'], [('powershell -nop -w hidden -enc SQBFAFgA', 'encoded PowerShell'), ('new.xlsx', '"position":0')], ['notepad']),
    (['jumplist', '--json'], [('F:\\\\usb\\\\plans.pdf', '"mru":0,"last_used":"2024-01-17 21:20:00","pinned":true,"interactions":5'),
                              ('tool.exe', '"mru":null'), ('tool.exe', 'user-writable'), ('mshta.exe', 'script host'), ('report.docx', None)], ['plans.pdf', 'report.docx']),
    (['prefetch', '--json'], [('EVIL.EXE', None), ('"run_count":3', None), ('DEADBEEF', None),
                               ('DOWNLOADS\\\\EVIL.EXE', 'ran from a user-writable dir'),
                               ('SYSTEM32\\\\NOTEPAD.EXE', None)], ['NOTEPAD']),
    (['prefetch', r'C:\windows\Prefetch\EVIL.EXE-DEADBEEF.pf', '--files', '--json'],
     [('PAYLOAD.DLL', None), ('"user_writable_dir":true', None), ('CAFE1234', None)], []),
]
fails = 0
for args, must, mustnot in checks:
    rc, out, err = wine([exe] + args)
    try:
        data = json.loads(out)
    except Exception as e:
        print(f'FAIL {args}: bad json ({e}) rc={rc} err={err.strip()[:200]} out={out[:200]!r}')
        fails += 1
        continue
    flat = json.dumps(data, separators=(',',':'))
    for needle, reason in must:
        # The needle must appear, and if a reason is given it must be on the
        # same record (look at each record's JSON).
        recs = data if isinstance(data, list) else [v for vs in data.values() if isinstance(vs, list) for v in vs]
        hit = [r for r in recs if needle in json.dumps(r, separators=(',',':'))] if recs else []
        if needle not in flat and not hit:
            print(f'FAIL {args}: missing {needle!r}'); fails += 1; continue
        if reason and not any(reason in json.dumps(r, separators=(',',':')) for r in hit):
            print(f'FAIL {args}: {needle!r} present but not flagged with {reason!r}: {hit[:1]}'); fails += 1
    for bad in mustnot:
        recs = data if isinstance(data, list) else []
        for r in recs:
            if bad in json.dumps(r, separators=(',',':')) and r.get('suspicious'):
                print(f'FAIL {args}: {bad!r} should not be flagged: {r}'); fails += 1
    print(f'checked {" ".join(args)}  rc={rc}')
# hunt: a process named svchost.exe running from outside System32. A tiny
# sleeper is cross-compiled for this (MinGW is needed for the build anyway).
fake = os.path.join(pfx, 'drive_c', 'fake'); os.makedirs(fake, exist_ok=True)
import shutil as _sh, time
sleeper_c = os.path.join(fake, 'sleeper.c')
with open(sleeper_c, 'w') as f:
    f.write('#include <windows.h>\nint main(void){Sleep(30000);return 0;}\n')
cc = _sh.which('x86_64-w64-mingw32-gcc')
if cc:
    subprocess.run([cc, sleeper_c, '-o', os.path.join(fake, 'svchost.exe')], check=True)
imp = subprocess.Popen([WINE, r'C:\fake\svchost.exe'], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
time.sleep(3)
rc, out, err = wine([exe, 'hunt', '--json'])
try:
    found = [r for r in json.loads(out) if r.get('path', '').lower().startswith('c:\\fake')]
    if not found or 'outside System32' not in found[0].get('finding', '') and 'unexpected parent' not in found[0].get('finding', ''):
        print(f'FAIL hunt: impostor svchost not flagged: {found}'); fails += 1
    else:
        print('checked hunt --json  (impostor flagged:', found[0]['finding'] + ')')
    # wine runs EVERY process as the logged-on user, so its services.exe really
    # does break the "core process runs as SYSTEM" rule: a true positive here
    # (on Windows it runs as S-1-5-18). Any other finding on a real system
    # binary would be a false positive.
    rows = json.loads(out)
    acct = [r for r in rows if r.get('name', '').lower() == 'services.exe' and 'expected SYSTEM' in r.get('finding', '')]
    if not acct:
        print('FAIL hunt: services.exe running as a user SID not flagged'); fails += 1
    real = [r for r in rows if r.get('path', '').lower().startswith('c:\\windows\\system32') and r.get('suspicious')
            and 'expected SYSTEM' not in r.get('finding', '')]
    if real:
        print(f'FAIL hunt: genuine system process flagged: {real}'); fails += 1
except Exception as e:
    print('FAIL hunt check:', e, out[:200]); fails += 1
# handles --find: a helper keeps C:\users\Public\wsfind_marker.txt open (read +
# write, the access value older tools never name) and blocks on a pipe read;
# --find must name the file with the helper's pid, and the per-pid listing
# must finish despite the pending pipe read.
if cc:
    here = os.path.dirname(os.path.abspath(__file__))
    subprocess.run([cc, os.path.join(here, '..', 'holder.c'), '-o', os.path.join(fake, 'holder.exe')], check=True)
    hold = subprocess.Popen([WINE, r'C:\fake\holder.exe', r'C:\users\Public\wsfind_marker.txt', 'block'], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    time.sleep(3)
    rc, out, err = wine([exe, 'handles', '--find', 'wsfind_marker', '--json'], timeout=120)
    try:
        hits = [r for r in json.loads(out) if r.get('process', '').lower() == 'holder.exe' and r.get('type') == 'File']
        if not hits:
            print(f'FAIL handles --find: marker file not found: {out[:300]}'); fails += 1
        else:
            rc2, out2, err2 = wine([exe, 'handles', str(hits[0]['pid']), '--json'], timeout=60)
            if rc2 == 'TIMEOUT':
                print('FAIL handles <pid>: hung on the blocked pipe'); fails += 1
            elif not any('wsfind_marker' in r.get('name', '') for r in json.loads(out2)):
                print('FAIL handles <pid>: read/write file handle has no name'); fails += 1
            else:
                print('checked handles --find + <pid>  (file named, no hang)')
    except Exception as e:
        print('FAIL handles check:', e, out[:200]); fails += 1
    hold.kill()
# (pipes: wine cannot enumerate \\.\pipe\, so the known-name matcher is
# covered by the unit tests instead.)
imp.kill()

# posture: weak settings are WARN, and the stored password never appears.
for fmt in ([], ['--json'], ['--csv']):
    rc, out, err = wine([exe, 'posture'] + fmt)
    if 'hunter2' in out or 'hunter2' in err:
        print(f'FAIL posture {fmt}: SECRET LEAKED into output'); fails += 1
rc, out, err = wine([exe, 'posture', '--json'])
try:
    rows = {r['check']: r for r in json.loads(out)}
    for chk in ('WDigest cleartext', 'AlwaysInstallElevated (HKLM)', 'AutoLogon password'):
        if rows.get(chk, {}).get('status') != 'WARN':
            print(f'FAIL posture: {chk} should be WARN: {rows.get(chk)}'); fails += 1
    # An unset value with a safe Windows default must not raise a WARN.
    # (Wine itself ships EnableLUA=0, so UAC is a real WARN there.)
    if rows.get('NTLM level', {}).get('status') != 'OK':
        print('FAIL posture: unset NTLM level must be OK (default is NTLMv2)'); fails += 1
    print('checked posture --json (+ no secret in any format)')
except Exception as e:
    print('FAIL posture check:', e, out[:200]); fails += 1

# net: every port must be a real 16-bit port (regression for an unmasked byte
# swap that printed values like 0.0.0.0:15206376).
rc, out, err = wine([exe, 'net', '--json'])
try:
    bad_ports = []
    for r in json.loads(out):
        for fld in ('local', 'remote'):
            v = r.get(fld)
            if v:
                port = int(v.rsplit(':', 1)[1])
                if not 0 <= port <= 65535:
                    bad_ports.append(v)
    if bad_ports:
        print(f'FAIL net: impossible port numbers: {bad_ports[:3]}'); fails += 1
    else:
        print('checked net --json  (all ports within 0..65535)')
except Exception as e:
    print('FAIL net check:', e, out[:200]); fails += 1

# pe: a UPX-packed file is recognised (once), when upx is installed.
upx = _sh.which('upx')
if upx and cc:
    up = os.path.join(pfx, 'drive_c', 'upxtest'); os.makedirs(up, exist_ok=True)
    tgt = os.path.join(up, 'packed.exe')
    _sh.copy(os.path.join(fake, 'svchost.exe'), tgt)
    subprocess.run([upx, '-q', '-f', tgt], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rc, out, err = wine([exe, 'pe', r'C:\upxtest\packed.exe', '--json'])
    if not out.strip():   # wine occasionally returns nothing right after a prefix restart
        rc, out, err = wine([exe, 'pe', r'C:\upxtest\packed.exe', '--json'])
    try:
        an = [a for a in json.loads(out).get('anomalies', []) if a.get('type') == 'packer']
        if len(an) != 1 or 'UPX' not in an[0].get('detail', ''):
            print(f'FAIL pe: UPX packer not reported exactly once: {an}'); fails += 1
        else:
            print('checked pe --json  (UPX packer recognised once)')
    except Exception as e:
        print('FAIL pe upx check:', e, out[:200]); fails += 1
else:
    print('skipped pe UPX check (upx or mingw not installed)')

# hidden: a service key written straight into the registry (after the SCM has
# started) is unknown to the SCM - the cross-view must report it. A unique name
# per run, deleted afterwards, keeps re-runs independent.
sneaky = f'WsSneaky{os.getpid()}'
skey = HK + r'SYSTEM\CurrentControlSet\Services' + '\\' + sneaky
reg(skey, '/v', 'ImagePath', '/t', 'REG_EXPAND_SZ', '/d', r'C:\ProgramData\sneaky.exe')
reg(skey, '/v', 'Type', '/t', 'REG_DWORD', '/d', '16')
rc, out, err = wine([exe, 'hidden', '--json'])
try:
    rows = json.loads(out)
    hit = [r for r in rows if r.get('id') == sneaky]
    procs = [r for r in rows if r.get('kind') == 'process']
    if not hit:
        print(f'FAIL hidden: registry-only service {sneaky} not reported: {rows[:3]}'); fails += 1
    elif procs:
        print(f'FAIL hidden: false hidden-process report: {procs[:2]}'); fails += 1
    else:
        print('checked hidden --json  (registry-only service found, no false process hits)')
except Exception as e:
    print('FAIL hidden check:', e, out[:200]); fails += 1
wine(['reg', 'delete', skey, '/f'])

# sweep: one valid JSON document with every check as a key; checks that
# cannot run under wine (WMI, event logs) must be null or empty, not broken.
rc, out, err = wine([exe, 'sweep', '--json'], timeout=600)
try:
    d = json.loads(out)
    want = ['posture', 'hunt', 'hidden', 'net', 'autoruns', 'services', 'tasks', 'taskcache',
            'firewall', 'prefetch', 'defender', 'wmi', 'events']
    missing = [k for k in want if k not in d]
    if missing:
        print(f'FAIL sweep: missing keys {missing}'); fails += 1
    elif not d.get('autoruns') or any(not r.get('suspicious') for r in d['autoruns']):
        print(f"FAIL sweep: autoruns should hold only flagged entries: {d.get('autoruns')}"); fails += 1
    else:
        print('checked sweep --json  (all keys present, findings-only sections)')
except Exception as e:
    print('FAIL sweep check:', e, out[:200]); fails += 1

# --sig: every autoruns entry carries a signature verdict; a missing image is
# "missing" (Autoruns' "File not found"), never silently "trusted".
rc, out, err = wine([exe, 'autoruns', '--sig', '--json'], timeout=300)
try:
    rows = json.loads(out)
    allowed = {'embedded', 'catalog', 'untrusted', 'unresolved', 'missing', 'none'}
    bad = [r for r in rows if r.get('signature') not in allowed]
    upd = [r for r in rows if r.get('name') == 'Updater']
    if bad:
        print(f'FAIL autoruns --sig: unexpected signature values {bad[:2]}'); fails += 1
    elif not upd or upd[0]['signature'] != 'missing' or upd[0]['reason'] != 'user-writable path':
        print(f'FAIL autoruns --sig: missing image should be "missing": {upd}'); fails += 1
    elif not [r for r in rows if r.get('name') == 'certx' and r.get('signature') == 'missing']:
        print('FAIL autoruns --sig: missing AppCertDll not reported as missing'); fails += 1
    else:
        print('checked autoruns --sig --json  (verdict on every entry)')
except Exception as e:
    print('FAIL autoruns --sig check:', e, out[:200]); fails += 1

# A key shared between the 64-bit view and Wow6432Node must be reported once.
rc, out, err = wine([exe, 'autoruns', '--json'])
try:
    n = sum(1 for r in json.loads(out) if r.get('name') == 'sethc.exe')
    if n != 1:
        print(f'FAIL autoruns: sethc.exe reported {n} times, expected 1'); fails += 1
except Exception as e:
    print('FAIL autoruns dedupe check:', e); fails += 1
print(f'\n{fails} failure(s)')
sys.exit(1 if fails else 0)
