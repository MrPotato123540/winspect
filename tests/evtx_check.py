#!/usr/bin/env python3
# Compare tests/evtx_dump (our .evtx reader, src/evtx.c) against values
# published in plaso's tests/parsers/winevtx.py for its test files
# test_data/evtx/System.evtx and System2.evtx (data only, no third-party code
# runs), and require every rendered record to be well-formed XML.
# Usage: evtx_check.py <evtx_dump> <dir with System.evtx and System2.evtx>
import os, re, subprocess, sys, xml.dom.minidom

dump, d = sys.argv[1], sys.argv[2]
fails = 0


def records(path):
    out = subprocess.run([dump, path], capture_output=True).stdout.decode('utf-8')
    recs, cur = {}, None
    for line in out.splitlines(keepends=True):
        m = re.match(r'^(\d+)\t(\d+)\t(.*)', line, re.S)
        if m:
            cur = int(m.group(1))
            recs[cur] = [int(m.group(2)), m.group(3)]
        elif cur is not None:
            recs[cur][1] += line
    return recs


def check(cond, msg):
    global fails
    print(('ok   ' if cond else 'FAIL ') + msg)
    fails += 0 if cond else 1


# plaso's expected XML for record 1, compared without the pretty-printing.
want1 = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
         '<Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" '
         'EventSourceName="Service Control Manager"/><EventID Qualifiers="16384">7036</EventID>'
         '<Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode>'
         '<Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime="2010-11-21T03:55:59.626427100Z"/>'
         '<EventRecordID>1</EventRecordID><Correlation/><Execution ProcessID="492" ThreadID="1188"/>'
         '<Channel>System</Channel><Computer>37L4247F27-26</Computer><Security/></System><EventData>'
         '<Data Name="param1">Windows Event Log</Data><Data Name="param2">stopped</Data>'
         '<Binary>6500760065006E0074006C006F0067002F0031000000</Binary></EventData></Event>')
r = records(os.path.join(d, 'System.evtx'))
check(len(r) == 5009, f'System.evtx: {len(r)} records (plaso: 5009)')
check(1 in r and r[1][1].strip() == want1, 'System.evtx record 1: XML identical to plaso expected_xml_string')
check(1 in r and r[1][0] == 129347853596264271, 'System.evtx record 1: written time 2010-11-21 03:55:59.6264271')
bad = 0
for k, (_, x) in r.items():
    try:
        xml.dom.minidom.parseString(x.strip())
    except Exception:
        bad += 1
check(bad == 0, f'System.evtx: all records well-formed XML ({bad} bad)')

# System2.evtx was cut short by hand: plaso reads the 194 records of the two
# complete chunks; we also keep the complete records of the cut chunk.
r2 = records(os.path.join(d, 'System2.evtx'))
x179 = r2.get(179, [0, ''])[1]
check(len(r2) >= 194 and all(i in r2 for i in range(1, 195)), f'System2.evtx: records 1..194 present ({len(r2)} read)')
check('<EventID>4624</EventID>' in x179 and 'SystemTime="2015-08-09T09:15:48.434125000Z"' in x179,
      'System2.evtx record 179: 4624 at 2015-08-09 09:15:48.4341250 (plaso)')
bad = 0
for k, (_, x) in r2.items():
    try:
        xml.dom.minidom.parseString(x.strip())
    except Exception:
        bad += 1
check(bad == 0, f'System2.evtx: all records well-formed XML ({bad} bad)')
print(f'{fails} failure(s)')
sys.exit(1 if fails else 0)
