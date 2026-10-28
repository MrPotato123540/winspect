# Minimal Compound File (v3, 512-byte sectors) WRITER, used only to build test
# inputs (jump lists) for the reader in src/cfb.c. Streams < 4096 bytes go to
# the mini stream, like real jump-list files. Flat layout: every stream is a
# child of the root, linked as a simple right-sibling chain (valid per spec).
import struct

ENDOFCHAIN, FREESECT, FATSECT = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
SEC, MINI, CUTOFF = 512, 64, 4096

def build(streams):
    """streams: list of (name, bytes). Returns the compound file bytes."""
    sectors = []                       # list of 512-byte blocks (regular sectors)
    fat = []

    def alloc_chain(data):
        if not data:
            return ENDOFCHAIN
        n = (len(data) + SEC - 1) // SEC
        start = len(sectors)
        for i in range(n):
            sectors.append(data[i * SEC:(i + 1) * SEC].ljust(SEC, b'\0'))
            fat.append(start + i + 1 if i < n - 1 else ENDOFCHAIN)
        return start

    # Mini stream + mini FAT for small streams.
    ministream, minifat, entries = b'', [], []
    for name, data in streams:
        if len(data) < CUTOFF:
            n = max(1, (len(data) + MINI - 1) // MINI)
            start = len(ministream) // MINI
            ministream += data.ljust(n * MINI, b'\0')
            minifat += [start + i + 1 if i < n - 1 else ENDOFCHAIN for i in range(n)]
            entries.append((name, start if data else ENDOFCHAIN, len(data)))
        else:
            entries.append((name, None, len(data), data))
    big = []
    for e in entries:
        if len(e) == 4:
            big.append((e[0], alloc_chain(e[3]), e[2]))
        else:
            big.append(e)
    entries = big
    root_start = alloc_chain(ministream) if ministream else ENDOFCHAIN
    minifat_bytes = b''.join(struct.pack('<I', x) for x in minifat)
    minifat_start = alloc_chain(minifat_bytes) if minifat else ENDOFCHAIN
    nminifat = (len(minifat_bytes) + SEC - 1) // SEC

    # Directory: root + streams (right-sibling chain).
    def dirent(name, typ, start, size, child=FREESECT, right=FREESECT):
        nm = name.encode('utf-16-le') + b'\0\0'
        e = nm.ljust(64, b'\0') + struct.pack('<HBB', len(nm), typ, 1)
        e += struct.pack('<III', FREESECT, right, child) + b'\0' * 16 + b'\0' * 4 + b'\0' * 16
        e += struct.pack('<II', start, size) + b'\0' * 4
        assert len(e) == 128
        return e
    d = dirent('Root Entry', 5, root_start, len(ministream), child=1 if entries else FREESECT)
    for i, (name, start, size) in enumerate(entries):
        d += dirent(name, 2, start, size, right=(i + 2) if i + 1 < len(entries) else FREESECT)
    dir_start = alloc_chain(d.ljust(((len(d) + SEC - 1) // SEC) * SEC, b'\0'))

    # FAT sectors (they describe themselves too): iterate until it fits.
    nfat = 1
    while True:
        total = len(sectors) + nfat
        if nfat * (SEC // 4) >= total:
            break
        nfat += 1
    fat_start = len(sectors)
    fat += [FATSECT] * nfat
    fat += [FREESECT] * (nfat * (SEC // 4) - len(fat))
    fat_bytes = b''.join(struct.pack('<I', x) for x in fat)
    for i in range(nfat):
        sectors.append(fat_bytes[i * SEC:(i + 1) * SEC])

    hdr = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) + b'\0' * 16
    hdr += struct.pack('<HHHHH', 0x3E, 3, 0xFFFE, 9, 6) + b'\0' * 6
    hdr += struct.pack('<IIIIIIIII', 0, nfat, dir_start, 0, CUTOFF, minifat_start, nminifat, ENDOFCHAIN, 0)
    difat = [fat_start + i for i in range(nfat)] + [FREESECT] * (109 - nfat)
    hdr += b''.join(struct.pack('<I', x) for x in difat)
    assert len(hdr) == 512
    return hdr + b''.join(sectors)
