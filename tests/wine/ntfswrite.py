# ntfswrite - TEST-ONLY builders for NTFS metadata files, so the usn / mft
# commands can be exercised with known content:
#   mft(entries)  -> bytes of a $MFT: 1024-byte FILE records with fixups,
#                    $STANDARD_INFORMATION and $FILE_NAME attributes
#   usn(records)  -> bytes of a $UsnJrnl:$J: a sparse run of zeros, then
#                    USN_RECORD_V2 records
# Written from the public structure descriptions (see src/mft.c, src/usn.c);
# checked by the C readers in tests (round trip).
import struct


def _attr(atype, content):
    hdr_len = 24
    total = (hdr_len + len(content) + 7) & ~7
    a = bytearray(total)
    struct.pack_into('<IIBBHHH', a, 0, atype, total, 0, 0, 0, 0, 0)
    struct.pack_into('<IH', a, 16, len(content), hdr_len)
    a[hdr_len:hdr_len + len(content)] = content
    return bytes(a)


def mft(entries, count=None):
    """entries: dict recno -> dict(name, parent, parent_seq, seq, dir, in_use, si, fn)."""
    count = count or (max(entries) + 1)
    entries = dict(entries)
    entries.setdefault(0, dict(name='$MFT', parent=5, parent_seq=5, seq=1, size=count * 1024))   # as on a real volume
    out = bytearray()
    for i in range(count):
        rec = bytearray(1024)
        e = entries.get(i)
        if e is None:
            out += rec
            continue
        rec[0:4] = b'FILE'
        struct.pack_into('<HH', rec, 4, 48, 3)                 # fixup array: 3 entries at 48
        usn_val = 0x0042
        struct.pack_into('<H', rec, 16, e.get('seq', 1))
        struct.pack_into('<H', rec, 20, 56)
        struct.pack_into('<H', rec, 22, (1 if e.get('in_use', True) else 0) | (2 if e.get('dir') else 0))
        struct.pack_into('<II', rec, 24, 0, 1024)
        si = e.get('si', [130000000000000000] * 4)
        fn = e.get('fn', si)
        attrs = _attr(0x10, struct.pack('<QQQQI', *si, 0x20) + b'\0' * 44)
        name = e['name'].encode('utf-16-le')
        fnc = struct.pack('<QQQQQQQII', e.get('parent', 5) | (e.get('parent_seq', 1) << 48), *fn,
                          e.get('size', 0), e.get('size', 0), 0x20, 0) + bytes([len(e['name']), 1]) + name
        attrs += _attr(0x30, fnc)
        attrs += b'\xff\xff\xff\xff\0\0\0\0'
        rec[56:56 + len(attrs)] = attrs
        struct.pack_into('<I', rec, 24, 56 + len(attrs))        # used size
        # Fixups: save the sector tails, write the USN there.
        struct.pack_into('<H', rec, 48, usn_val)
        for k in (1, 2):
            end = k * 512 - 2
            rec[48 + 2 * k:48 + 2 * k + 2] = rec[end:end + 2]
            struct.pack_into('<H', rec, end, usn_val)
        out += rec
    return bytes(out)


def usn(records, sparse=4096):
    """records: list of (file_ref, parent_ref, filetime, reason, name)."""
    out = bytearray(sparse)
    u = sparse
    for fref, pref, ft, reason, name in records:
        nb = name.encode('utf-16-le')
        ln = (60 + len(nb) + 7) & ~7
        r = bytearray(ln)
        struct.pack_into('<IHHQQqQIIII', r, 0, ln, 2, 0, fref, pref, u, ft, reason, 0, 0, 0x20)
        struct.pack_into('<HH', r, 56, len(nb), 60)
        r[60:60 + len(nb)] = nb
        out += r
        u += ln
    return bytes(out)
