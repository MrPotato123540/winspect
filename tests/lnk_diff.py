#!/usr/bin/env python3
# Differential test for src/lnkparse.c: for every sample .lnk in <samples>,
# compare winspect's parse (tests/lnk_dump) with an independent parser's
# expected output stored as JSON in <expected> (the LnkParse3 project's
# tests/samples + tests/json; only its data files are used, no code is run).
# Samples may be raw .lnk bytes or base64 text (LnkParse3 stores them so).
# Fields compared: local/network target path, relative path, working dir,
# arguments, drive type / serial / label, machine id, MAC (from a v1 droid),
# environment-variable target. ANSI strings: our parser maps non-ASCII bytes
# to '?', so '?' matches any single non-ASCII character.
# Usage: python3 tests/lnk_diff.py ./lnk_dump <samples dir> <json dir>
import base64, json, os, subprocess, sys, tempfile
dump, sdir, jdir = sys.argv[1:4]

def same(ours, theirs):
    theirs = theirs or ''
    if len(ours) == len(theirs) and all(a == b or (a == '?' and ord(b) > 127) for a, b in zip(ours, theirs)):
        return True
    return ours == theirs

fails = checked = 0
for name in sorted(os.listdir(sdir)):
    jp = os.path.join(jdir, name + '.json')
    if not os.path.exists(jp):
        continue
    exp = json.load(open(jp, encoding='utf-8'))
    raw = open(os.path.join(sdir, name), 'rb').read()
    if not raw.startswith(b'L\0\0\0'):
        raw = base64.b64decode(raw)
    with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as tf:
        tf.write(raw)
    out = subprocess.run([dump, tf.name], capture_output=True, text=True)
    os.unlink(tf.name)
    try:
        got = json.loads(out.stdout)
    except Exception:
        print(f'FAIL {name}: dump crashed / bad output rc={out.returncode}'); fails += 1; continue
    data, li, ex = exp.get('data', {}), exp.get('link_info', {}) or {}, exp.get('extra', {}) or {}
    cmp = []
    if li.get('location') == 'Local' and li.get('local_base_path') is not None:
        base = li.get('local_base_path_unicode') or li['local_base_path']
        cmp.append(('target', base + (li.get('common_path_suffix') or '')))
    if li.get('location') == 'Network':
        net = li['location_info'].get('net_name') or ''
        suf = li.get('common_path_suffix') or ''
        cmp.append(('target', net + ('\\' if suf and not net.endswith('\\') else '') + suf))
    loc = li.get('location_info') or {}
    if 'r_drive_type' in loc:
        cmp.append(('drive_type', loc['r_drive_type']))
        cmp.append(('drive_serial', int(loc['drive_serial_number'], 16)))
        cmp.append(('volume_label', loc.get('volume_label_unicode') or loc.get('volume_label') or ''))
    for k, ours in (('relative_path', 'relative'), ('working_directory', 'workdir'),
                    ('command_line_arguments', 'arguments')):
        if k in data:
            cmp.append((ours, data[k]))
    t = ex.get('DISTRIBUTED_LINK_TRACKER_BLOCK')
    if t:
        cmp.append(('machine_id', t.get('machine_identifier', '')))
        g = t.get('droid_file_identifier', '')
        mac = ''
        if len(g) == 36 and g[14] == '1':
            h = g[-12:].lower()
            mac = ':'.join(h[i:i + 2] for i in range(0, 12, 2))
        cmp.append(('mac', mac))
    e = ex.get('ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK')
    if e:
        cmp.append(('env_target', e.get('target_unicode') or e.get('target_ansi') or ''))
    bad = [(k, got.get(k), v) for k, v in cmp
           if not (same(got.get(k), v) if isinstance(v, str) else got.get(k) == v)]
    checked += 1
    if bad:
        fails += 1
        print(f'FAIL {name}:')
        for k, a, b in bad:
            print(f'    {k}: ours={a!r} expected={b!r}')
    else:
        print(f'ok   {name} ({len(cmp)} fields)')
print(f'\n{checked} sample(s), {fails} failure(s)')
sys.exit(1 if fails or not checked else 0)
