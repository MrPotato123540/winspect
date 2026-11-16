#!/usr/bin/env python3
# Robustness fuzz under wine: a security tool must never crash on a file an
# attacker prepared. Mutates (1) a real PE (targeted header corruptions +
# random byte flips) and (2) a shortcut (.lnk) file, then runs the parsers on
# every variant. Pass = exit code 0/1 every time and --json always parses.
# Usage: python3 tests/wine/fuzz.py <winspect.exe> [n_pe_random] [n_lnk]
# Variants are written into the THROW-AWAY prefix (WINEPREFIX, default ./wpfx).
import subprocess, os, sys, json, tempfile, random, struct, shutil
exe = sys.argv[1]
n_random = int(sys.argv[2]) if len(sys.argv) > 2 else 150
n_lnk = int(sys.argv[3]) if len(sys.argv) > 3 else 300
pfx = os.path.abspath(os.environ.get('WINEPREFIX', 'wpfx'))
# UTF-8 unix locale: wine maps non-ASCII file names through it.
env = dict(os.environ, WINEPREFIX=pfx, WINEDEBUG='-all', LC_ALL='C.UTF-8')
WINE = os.environ.get('WINE') or shutil.which('wine64') or shutil.which('wine') or '/usr/lib/wine/wine64'
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from winepaths import WINESERVER  # noqa: E402
subprocess.Popen([WINESERVER, '-p'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run(args, timeout=600):
    with tempfile.TemporaryFile() as o, tempfile.TemporaryFile() as e:
        try:
            rc = subprocess.run([WINE, exe] + args, env=env, stdout=o, stderr=e,
                                stdin=subprocess.DEVNULL, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            rc = 'TIMEOUT'
        o.seek(0); e.seek(0)
        return rc, o.read().decode('utf-8', 'replace'), e.read().decode('utf-8', 'replace')

def check(args):
    rc, out, err = run(args)
    if rc not in (0, 1):
        print('BAD rc', rc, ' '.join(args), err[:160].strip()); return 1
    if '--json' in args and rc == 0:
        try: json.loads(out)
        except Exception as ex: print('BAD json', ' '.join(args), ex, repr(out[:100])); return 1
    return 0

# Make sure the prefix exists (first wine run creates it).
run(['--help'], timeout=300)

# ---- PE ---------------------------------------------------------------------
src = open(os.path.join(pfx, 'drive_c/windows/system32/notepad.exe'), 'rb').read()
outdir = os.path.join(pfx, 'drive_c/fuzz'); os.makedirs(outdir, exist_ok=True)
lfanew = struct.unpack_from('<I', src, 0x3C)[0]
opt = lfanew + 24
magic = struct.unpack_from('<H', src, opt)[0]
dd = opt + (112 if magic == 0x20b else 96)          # data directories
nsec_off = lfanew + 6
sohdr = struct.unpack_from('<H', src, lfanew + 20)[0]
sect = opt + sohdr
variants = {}
for cut in (0, 2, 63, 64, lfanew, lfanew + 4, lfanew + 23, opt + 10, dd, dd + 64, sect, sect + 39, sect + 40, len(src) // 2, len(src) - 1):
    variants[f'trunc_{cut}'] = src[:cut]
def patch(name, off, fmt, val):
    b = bytearray(src); struct.pack_into(fmt, b, off, val); variants[name] = bytes(b)
patch('lfanew_huge', 0x3C, '<I', 0x7FFFFFF0)
patch('lfanew_neg', 0x3C, '<I', 0xFFFFFFFF)
patch('nsec_ffff', nsec_off, '<H', 0xFFFF)
patch('nsec_0', nsec_off, '<H', 0)
patch('sohdr_ffff', lfanew + 20, '<H', 0xFFFF)
patch('sohdr_0', lfanew + 20, '<H', 0)
for i in range(16):
    patch(f'dd{i}_rva_huge', dd + i * 8, '<I', 0xFFFFFFF0)
    patch(f'dd{i}_size_huge', dd + i * 8 + 4, '<I', 0xFFFFFFF0)
patch('numrva_huge', dd - 4, '<I', 0xFFFFFFFF)
# Section headers: raw pointer/size past EOF, VA overlaps
patch('sec0_raw_huge', sect + 20, '<I', 0xFFFFFF00)
patch('sec0_rawsize_huge', sect + 16, '<I', 0xFFFFFF00)
patch('sec0_vsize_0', sect + 8, '<I', 0)
# Import dir pointing at the header (self-referencing junk)
patch('imp_at_header', dd + 8, '<I', 0)
patch('imp_at_dd', dd + 8, '<I', dd)
rnd = random.Random(1337)
for k in range(n_random):
    b = bytearray(src)
    for _ in range(rnd.randint(1, 24)):
        pos = rnd.randrange(0, min(len(b), 4096)) if rnd.random() < 0.8 else rnd.randrange(0, len(b))
        b[pos] = rnd.randrange(256)
    variants[f'rand_{k}'] = bytes(b)
for name, data in variants.items():
    open(os.path.join(outdir, name + '.bin'), 'wb').write(data)
bad = 0
for name in variants:
    wp = 'C:\\fuzz\\' + name + '.bin'
    for args in (['pe', wp, '--json'], ['pe', wp], ['strings', wp, '--json'], ['hash', wp]):
        bad += check(args)
print(f'pe: {len(variants)} variants checked')

# ---- .lnk -------------------------------------------------------------------
def make_lnk(target, args):
    clsid = bytes([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46])
    hdr = bytearray(0x4C); struct.pack_into('<I', hdr, 0, 0x4C); hdr[4:20] = clsid
    struct.pack_into('<I', hdr, 0x14, 0x02 | 0x04 | 0x10 | 0x20 | 0x40 | 0x80)
    base = target.encode('ascii') + b'\0'
    li = bytearray(0x24); total = 0x24 + len(base) + 1
    struct.pack_into('<IIIIIIIII', li, 0, total, 0x24, 1, 0, 0x24, 0, 0x24 + len(base), 0, 0)
    li += base + b'\0'
    sd = b''
    for t in ('desc', 'C:\\work', args, 'C:\\icon.ico'):
        sd += struct.pack('<H', len(t)) + t.encode('utf-16-le')
    return bytes(hdr) + bytes(li) + sd
lsrc = make_lnk(r'C:\Windows\System32\cmd.exe', '/c echo hi')
d = os.path.join(pfx, 'drive_c', 'lnkfuzz'); os.makedirs(d, exist_ok=True)
rnd2 = random.Random(7)
for k in range(n_lnk):
    b = bytearray(lsrc)
    if k % 5 == 0:
        b = b[:rnd2.randrange(0, len(b))]
    else:
        for _ in range(rnd2.randint(1, 12)):
            b[rnd2.randrange(0, len(b))] = rnd2.randrange(256)
    open(os.path.join(d, f'f{k}.lnk'), 'wb').write(bytes(b))
for args in (['lnk', 'C:\\lnkfuzz', '--json'], ['lnk', 'C:\\lnkfuzz'], ['lnk', 'C:\\lnkfuzz', '--csv']):
    bad += check(args)
print(f'lnk: {n_lnk} variants checked')
print(f'{bad} problem(s)')
sys.exit(1 if bad else 0)
