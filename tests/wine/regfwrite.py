# regfwrite - TEST-ONLY writer for registry hive files ("regf"), so offline
# commands (certstore --software, users --sam, comhijack --usrclass ...) can be
# exercised with hand-made, known-content hives. Written from the public format
# notes (base block, hbin, nk / vk / lh / sk cells); no code reused. It writes
# what Windows itself would: one hive bin per 4 KiB multiple, 8-byte aligned
# allocated cells, an "lh" subkey index (with name hashes), value lists, one
# shared security cell, inline data for values of 4 bytes or less, and a base
# block checksum. Big-data ("db") values are not supported (max 16344 bytes).
#
#   k = Key('ROOT', values=[Value('Name', REG_SZ, sz('x'))], subkeys=[...])
#   open('test.hiv', 'wb').write(build(k))
import struct

REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD = 0, 1, 2, 3, 4
FILETIME_2024 = 133485408000000000          # 2024-01-01 00:00:00 UTC


class Value:
    def __init__(self, name, vtype, data):
        self.name, self.type, self.data = name, vtype, data


class Key:
    def __init__(self, name, values=(), subkeys=(), last_written=FILETIME_2024):
        self.name, self.values, self.subkeys = name, list(values), list(subkeys)
        self.last_written = last_written


def sz(s):
    return (s + '\0').encode('utf-16-le')


def dword(v):
    return struct.pack('<I', v)


def _name_bytes(name):
    # Latin-1 ("compressed") when possible, as Windows does; else UTF-16.
    try:
        return name.encode('latin-1'), True
    except UnicodeEncodeError:
        return name.encode('utf-16-le'), False


def _lh_hash(name):
    h = 0
    for ch in name.upper():
        h = (h * 37 + ord(ch)) & 0xFFFFFFFF
    return h


class _Bin:
    def __init__(self):
        self.data = bytearray()

    def alloc(self, payload):
        """Allocate a cell (8-byte aligned) and return its offset (relative to
        the first hive bin, i.e. hbin header included)."""
        size = (4 + len(payload) + 7) & ~7
        off = 32 + len(self.data)                # after the hbin header
        self.data += struct.pack('<i', -size) + payload + b'\0' * (size - 4 - len(payload))
        return off

    def patch(self, off, pos, fmt, *vals):
        struct.pack_into(fmt, self.data, off - 32 + 4 + pos, *vals)


def build(root, file_name='\\??\\C:\\test.hiv'):
    b = _Bin()
    # One security cell shared by every key: minimal self-relative SD.
    sd = struct.pack('<BBHIIII', 1, 0, 0x8000, 0, 0, 0, 0)
    sk = b.alloc(b'sk' + b'\0\0' + struct.pack('<IIII', 0, 0, 1, len(sd)) + sd)
    b.patch(sk, 4, '<II', sk, sk)                # flink / blink: itself

    def write_key(k, parent, is_root):
        nb, latin = _name_bytes(k.name)
        flags = (0x2C if is_root else 0x20) if latin else (0x0C if is_root else 0)
        nk = bytearray(76) + nb
        nk[0:2] = b'nk'
        struct.pack_into('<HQIIIIIIIIIIIIIIIHH', nk, 2, flags, k.last_written, 0, parent,
                         len(k.subkeys), 0, 0xFFFFFFFF, 0xFFFFFFFF, len(k.values), 0xFFFFFFFF,
                         sk, 0xFFFFFFFF, 0, 0, 0, 0, 0, len(nb), 0)
        off = b.alloc(bytes(nk))
        # Values.
        if k.values:
            vks = []
            for v in k.values:
                vn, vlatin = _name_bytes(v.name)
                if len(v.data) <= 4:
                    inline = v.data.ljust(4, b'\0')
                    vk = b'vk' + struct.pack('<HI', len(vn), 0x80000000 | len(v.data)) + inline + \
                         struct.pack('<IHH', v.type, 1 if vlatin else 0, 0) + vn
                else:
                    if len(v.data) > 16344:
                        raise ValueError('big-data values are not supported')
                    doff = b.alloc(v.data)
                    vk = b'vk' + struct.pack('<HII', len(vn), len(v.data), doff) + \
                         struct.pack('<IHH', v.type, 1 if vlatin else 0, 0) + vn
                vks.append(b.alloc(vk))
            vl = b.alloc(b''.join(struct.pack('<I', x) for x in vks))
            b.patch(off, 40, '<I', vl)
        # Subkeys, then their index sorted by upper-case name as Windows keeps it.
        if k.subkeys:
            kids = sorted(((write_key(s, off, False), s.name) for s in k.subkeys), key=lambda t: t[1].upper())
            lh = b'lh' + struct.pack('<H', len(kids)) + b''.join(struct.pack('<II', o, _lh_hash(n)) for o, n in kids)
            b.patch(off, 28, '<I', b.alloc(lh))
            mx = max(len(_name_bytes(n)[0]) for _, n in kids)
            b.patch(off, 52, '<I', mx)
        return off

    root_off = write_key(root, 0xFFFFFFFF, True)
    # Pad the bin to a 4 KiB multiple with one free cell.
    total = 32 + len(b.data)
    size = (total + 4095) & ~4095
    if size - total >= 8:
        b.data += struct.pack('<i', size - total) + b'\0' * (size - total - 4)
    elif size > total:
        size += 4096
        b.data += struct.pack('<i', size - total) + b'\0' * (size - total - 4)
    hbin = b'hbin' + struct.pack('<III', 0, size, 0) + struct.pack('<IQI', 0, FILETIME_2024, 0)
    base = bytearray(4096)
    base[0:4] = b'regf'
    struct.pack_into('<IIQIIIIIII', base, 4, 1, 1, FILETIME_2024, 1, 5, 0, 1, root_off, size, 1)
    fn = file_name.encode('utf-16-le')[:64]
    base[48:48 + len(fn)] = fn
    x = 0
    for i in range(127):
        x ^= struct.unpack_from('<I', base, 4 * i)[0]
    x = 1 if x == 0 else 0xFFFFFFFE if x == 0xFFFFFFFF else x
    struct.pack_into('<I', base, 508, x)
    return bytes(base) + hbin + bytes(b.data)
