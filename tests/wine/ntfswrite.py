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
    """records: list of (file_ref, parent_ref, filetime, reason, name[, attributes])."""
    out = bytearray(sparse)
    u = sparse
    for rec_ in records:
        fref, pref, ft, reason, name = rec_[:5]
        attrs = rec_[5] if len(rec_) > 5 else 0x20
        nb = name.encode('utf-16-le')
        ln = (60 + len(nb) + 7) & ~7
        r = bytearray(ln)
        struct.pack_into('<IHHQQqQIIII', r, 0, ln, 2, 0, fref, pref, u, ft, reason, 0, 0, attrs)
        struct.pack_into('<HH', r, 56, len(nb), 60)
        r[60:60 + len(nb)] = nb
        out += r
        u += ln
    return bytes(out)


def _fixups(rec, usn_val=0x0042):
    struct.pack_into('<H', rec, 48, usn_val)
    for k in (1, 2):
        end = k * 512 - 2
        rec[48 + 2 * k:48 + 2 * k + 2] = rec[end:end + 2]
        struct.pack_into('<H', rec, end, usn_val)


def _record(attrs, flags=1, seq=1, base=0):
    """One 1024-byte FILE record holding the given attribute bytes."""
    rec = bytearray(1024)
    rec[0:4] = b'FILE'
    struct.pack_into('<HH', rec, 4, 48, 3)
    struct.pack_into('<H', rec, 16, seq)
    struct.pack_into('<H', rec, 20, 56)
    struct.pack_into('<H', rec, 22, flags)
    attrs = attrs + b'\xff\xff\xff\xff\0\0\0\0'
    struct.pack_into('<II', rec, 24, 56 + len(attrs), 1024)
    struct.pack_into('<Q', rec, 32, base)
    rec[56:56 + len(attrs)] = attrs
    _fixups(rec)
    return bytes(rec)


def _runlist(frags):
    """frags: list of (lcn, clusters) -> NTFS run list (relative, signed offsets)."""
    out = bytearray()
    prev = 0
    for lcn, n in frags:
        d = lcn - prev
        prev = lcn
        nl = max(1, (n.bit_length() + 7) // 8)
        ol = 1
        while not -(1 << (8 * ol - 1)) <= d < (1 << (8 * ol - 1)):
            ol += 1
        out += bytes([(ol << 4) | nl]) + n.to_bytes(nl, 'little') + d.to_bytes(ol, 'little', signed=True)
    return bytes(out) + b'\0'


def _nonres(atype, start_vcn, frags, real):
    runs = _runlist(frags)
    total = (64 + len(runs) + 7) & ~7
    a = bytearray(total)
    clusters = sum(n for _, n in frags)
    struct.pack_into('<IIBBHHH', a, 0, atype, total, 1, 0, 0, 0, 0)
    struct.pack_into('<QQHH', a, 16, start_vcn, start_vcn + clusters - 1, 64, 0)
    struct.pack_into('<QQQ', a, 40, real, real, real)
    a[64:64 + len(runs)] = runs
    return bytes(a)


def _alist(entries):
    """entries: list of (type, start_vcn, recno) -> $ATTRIBUTE_LIST content."""
    out = bytearray()
    for atype, vcn, recno in entries:
        e = bytearray(32)
        struct.pack_into('<IHBBQQH', e, 0, atype, 32, 0, 26, vcn, recno | (1 << 48), 0)
        out += e
    return bytes(out)


def volume(mft_bytes, frags, split=None, ext_rec=16, cluster=4096, attr_list=True):
    """A raw NTFS volume image holding only what `mft --image` reads: a boot
    sector and the $MFT, stored in the given fragments [(lcn, clusters)].
    split = number of leading fragments described by record 0 itself; the
    rest go to extension record ext_rec, reached through record 0's
    $ATTRIBUTE_LIST (how a fragmented $MFT really looks). attr_list=False
    leaves the list out, i.e. a volume whose later extents cannot be found."""
    m = bytearray(mft_bytes)
    assert sum(n for _, n in frags) * cluster == len(m)
    split = len(frags) if split is None else split
    first, rest = frags[:split], frags[split:]
    si = _attr(0x10, struct.pack('<QQQQI', *([130000000000000000] * 4), 6) + b'\0' * 44)
    name = '$MFT'.encode('utf-16-le')
    fn = _attr(0x30, struct.pack('<QQQQQQQII', 5 | (5 << 48), *([130000000000000000] * 4), len(m), len(m), 6, 0)
               + bytes([4, 3]) + name)
    data0 = _nonres(0x80, 0, first, len(m))
    attrs = si
    if rest and attr_list:
        vcn = sum(n for _, n in first)
        attrs += _attr(0x20, _alist([(0x10, 0, 0), (0x30, 0, 0), (0x80, 0, 0), (0x80, vcn, ext_rec)]))
    attrs += fn + data0
    m[0:1024] = _record(attrs)
    if rest:
        vcn = sum(n for _, n in first)
        m[ext_rec * 1024:(ext_rec + 1) * 1024] = _record(_nonres(0x80, vcn, rest, 0), base=0 | (1 << 48))
    size = (max(l + n for l, n in frags) + 4) * cluster
    img = bytearray(size)
    boot = bytearray(512)
    boot[3:11] = b'NTFS    '
    struct.pack_into('<H', boot, 11, 512)
    boot[13] = cluster // 512
    struct.pack_into('<Q', boot, 40, size // 512)
    struct.pack_into('<Q', boot, 48, frags[0][0])
    boot[64] = 0xF6                                   # 2^10 = 1024-byte records
    boot[510:512] = b'\x55\xaa'
    img[0:512] = boot
    off = 0
    for lcn, n in frags:
        img[lcn * cluster:(lcn + n) * cluster] = m[off:off + n * cluster]
        off += n * cluster
    return bytes(img)
