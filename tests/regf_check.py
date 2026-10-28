#!/usr/bin/env python3
# Check winspect's hive reader (tests/regf_dump) against real Windows hives
# from the regipy project's test data (only the .xz data files are used; no
# regipy code runs). Expected values are facts regipy's own tests assert
# about those files: header fields, root key, key/value totals and value-type
# histograms for a full walk, specific keys and values (inline data, UTF-16
# emoji key names, device-property values), and a partial (exported) hive.
# Usage: python3 tests/regf_check.py ./regf_dump <regipy_tests/data dir>
import json, lzma, os, subprocess, sys, tempfile
dump, data = sys.argv[1:3]
fails = 0
tmp = tempfile.mkdtemp()

def hive(name):
    out = os.path.join(tmp, name)
    if not os.path.exists(out):
        with open(out, 'wb') as f:
            f.write(lzma.open(os.path.join(data, name + '.xz')).read())
    return out

def run(*args):
    r = subprocess.run([dump] + list(args), capture_output=True, text=True)
    return json.loads(r.stdout)

def check(cond, msg):
    global fails
    print(('ok   ' if cond else 'FAIL ') + msg)
    if not cond:
        fails += 1

TYPES = {'REG_NONE': 0, 'REG_SZ': 1, 'REG_EXPAND_SZ': 2, 'REG_BINARY': 3, 'REG_DWORD': 4,
         'REG_MULTI_SZ': 7, 'REG_QWORD': 11}

h = run(hive('NTUSER.DAT'), 'header')
check((h['seq1'], h['seq2'], h['last_written'], h['major'], h['minor'], h['root']) ==
      (749, 749, 129782982453388850, 1, 3, 32), 'NTUSER header fields')
check(h['file_name'] == '?\\C:\\Users\\vibranium\\ntuser.dat' and h['checksum_ok'] == 1, 'NTUSER file name + checksum')
check(h['root_name'] == 'CMI-CreateHive{6A1C4018-979D-4291-A7DC-7AED1C75B67C}' and h['root_subkeys'] == 11, 'NTUSER root key')

for name, keys, vals, hist in (
        ('NTUSER.DAT', 1812, 4094, {'REG_BINARY': 531, 'REG_DWORD': 1336, 'REG_EXPAND_SZ': 93,
                                    'REG_MULTI_SZ': 303, 'REG_NONE': 141, 'REG_QWORD': 54, 'REG_SZ': 1636}),
        ('amcache.hve', 2105, 17539, {'REG_BINARY': 56, 'REG_DWORD': 1656, 'REG_EXPAND_SZ': 0,
                                      'REG_MULTI_SZ': 140, 'REG_NONE': 0, 'REG_QWORD': 1254, 'REG_SZ': 14433})):
    s = run(hive(name), 'stats')
    check(s['keys'] == keys and s['values'] == vals, f'{name}: {s["keys"]} keys / {s["values"]} values')
    check(all(s['types'][str(TYPES[t])] == c for t, c in hist.items()), f'{name}: value-type histogram')

k = run(hive('NTUSER.DAT'), 'key', r'\Software\Microsoft\Windows\CurrentVersion\Run')
check(k['name'] == 'Run' and k['last_written'] == 129779615948377168, 'NTUSER Run key + last write')
check(k['values'][0]['name'] == 'Sidebar' and k['values'][0]['type'] == 2, 'NTUSER Run first value Sidebar REG_EXPAND_SZ')

k = run(hive('NTUSER.DAT'), 'key', r'\Control Panel\Appearance')
v = {x['name']: x for x in k['values']}
check(v['SchemeLangID']['hex'] == '0904', 'inline REG_BINARY value')

k = run(hive('SYSTEM'), 'key', r'\ControlSet001\Control\Class\{0475BB51-5A02-4EE0-B36C-29040FAD2650}')
v = {x['name']: bytes.fromhex(x['hex']).decode('utf-16-le').rstrip('\0') for x in k['values']}
check(v.get('NoDisplayClass') == '1' and v.get('Class') == 'vm3dmp', 'inline REG_SZ values')

k = run(hive('transactions_NTUSER.DAT'), 'key', r'\Control Panel\International')
check(k['subkeys'] == ['Geo', 'User Profile', 'User Profile System Backup', '\U0001F30E\U0001F30F\U0001F30D'],
      'UTF-16 (emoji) key names')

k = run(hive('SYSTEM_2'), 'key',
        r'\ControlSet001\Enum\ACPI\ACPI0003\0\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0003')
val = k['values'][0] if k.get('values') else {}
check(len(k.get('values', [])) == 1 and val.get('name') == '' and (val.get('type', 0) & 0xFFFF) == 18 and
      bytes.fromhex(val['hex']).decode('utf-16-le').rstrip('\0') ==
      'cmbatt.inf:db04a16c09a7808a:AcAdapter_Inst:6.3.9600.16384:ACPI\\ACPI0003', 'device-property value')

s = run(hive('ntuser_software_partial'), 'stats')
check(s['keys'] == 6396, f'partial hive: {s["keys"]} keys (root + 6395)')

print(f'\n{fails} failure(s)')
sys.exit(1 if fails else 0)
