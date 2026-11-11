#!/usr/bin/env python3
# Defender Detection History reader vs plaso's test files (data only, no code
# run). Expected values:
#  - FC380697-...: the values plaso's own parser test asserts (threat name
#    and id, file, user, process, SHA-256, initial detection and last status
#    change times, no remediation, the web resource);
#  - every file: the detection GUID inside equals the file's name, which is
#    how Defender names these files (an independent check of the GUID decode);
#  - the EICAR files: SHA-256 of the EICAR test string, a published constant.
# Usage: defhist_check.py <defhist_dump> <dir with the three files>
import subprocess, sys, os, datetime

dump, src = sys.argv[1], sys.argv[2]
fails = 0


def check(cond, msg):
    global fails
    print(('ok   ' if cond else 'FAIL ') + msg)
    fails += 0 if cond else 1


def read(name):
    out = subprocess.run([dump, os.path.join(src, name)], capture_output=True, text=True).stdout
    d, res = {}, []
    for line in out.splitlines():
        p = line.split('\t')
        if p[0] == 'resource':
            res.append(tuple(p[1:]))
        else:
            d[p[0]] = p[1] if len(p) > 1 else ''
    return d, res


def ft(v):
    t = int(v)
    whole = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=t // 10**7)
    return whole.strftime('%Y-%m-%dT%H:%M:%S') + '.%07d' % (t % 10**7)


EICAR = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
names = ['6AFE33A0-19BA-4FFF-892F-B700539D7D63', '7C66C39C-49DD-42D7-9822-4039C98CC246', 'FC380697-A68D-4C94-B67F-9B6449039463']
for n in names:
    d, res = read(n)
    check(d.get('guid') == n, f'{n}: detection GUID equals the file name')

d, res = read('FC380697-A68D-4C94-B67F-9B6449039463')
check(d['threat'] == 'PUA:Win32/EICAR_Test_File' and d['threat_id'] == '224688', 'threat name and id (plaso)')
check(d['primary'] == r'C:\Users\testuser\Downloads\PotentiallyUnwanted.exe', 'file (plaso)')
check(d['user'] == r'FRYPTOP\testuser' and d['process'] == r'C:\Windows\explorer.exe', 'user and process (plaso)')
check(ft(d['detect_time']) == '2022-07-22T05:32:27.6558959', 'initial detection time (plaso)')
check(ft(d['status_time']) == '2022-07-22T05:32:28.5123912', 'last threat status change time (plaso)')
check(d['remediation_time'] == '0' and d['remediation_user'] == '', 'no remediation (plaso)')
check(any(t == 'file' and s == 'd6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad' for t, _, s in res), 'SHA-256 (plaso)')
check(any(t == 'webfile' and l == r'C:\Users\testuser\Downloads\PotentiallyUnwanted.exe|http://amtso.eicar.org/PotentiallyUnwanted.exe|'
          'pid:19588,ProcessStart:133029415464710822' for t, l, _ in res), 'web resource (plaso)')

d, res = read('6AFE33A0-19BA-4FFF-892F-B700539D7D63')
check([t for t, _, _ in res] == ['containerfile', 'file', 'webfile'], 'container detection: three resources in order')
check(d['primary'] == r'C:\Users\testuser\Downloads\eicar_com.zip->eicar.com' and res[0][1] == r'C:\Users\testuser\Downloads\eicar_com.zip',
      'container detection: file inside the archive, archive as container')
check(res[1][2] == EICAR, 'container detection: SHA-256 of the EICAR test file')
check(d['process'] == '' and d['remediation_user'] == r'NT AUTHORITY\SYSTEM' and d['remediation_time'] != '0',
      'container detection: "Unknown" process left empty, remediated by SYSTEM')

d, res = read('7C66C39C-49DD-42D7-9822-4039C98CC246')
check(d['threat'] == 'Virus:DOS/EICAR_Test_File' and d['primary'] == r'C:\wmilab\eicar\eicar1.com' and res[0][2] == EICAR,
      'file detection: threat, path, EICAR SHA-256')
check(d['process'].lower().endswith('powershell.exe') and int(d['detect_time']) < int(d['remediation_time']),
      'file detection: process, detection before remediation')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
