// cfb - Compound File Binary reader ([MS-CFB]), portable and read-only
//
// Layout in brief:
//   Header (512 bytes): signature D0 CF 11 E0 A1 B1 1A E1, sector shift @0x1E
//   (9 = 512-byte sectors, 12 = 4096), mini sector shift @0x20 (6 = 64),
//   FAT sector count @0x2C, first directory sector @0x30, mini stream cutoff
//   @0x38 (4096), first mini FAT sector @0x3C + count @0x40, first DIFAT
//   sector @0x44 + count @0x48, and the first 109 DIFAT entries @0x4C.
//   Sector k lives at file offset (k + 1) * sector_size.
//   The FAT is a chain table: fat[k] = next sector of the same stream, or
//   ENDOFCHAIN (0xFFFFFFFE). The DIFAT lists which sectors hold the FAT.
//   Directory: 128-byte entries - name (UTF-16, 64 bytes) @0, name length
//   @64, type @66 (2 = stream, 5 = root), start sector @116, size @120.
//   Streams smaller than the cutoff live in the "mini stream" (the root
//   entry's own stream), in 64-byte mini sectors chained by the mini FAT.
// Every chain walk is bounded by the table size, so a cyclic or forged chain
// ends instead of looping; every read is checked against the buffer.

#include "cfb.h"

#include <stdlib.h>
#include <string.h>

#define ENDOFCHAIN 0xFFFFFFFEu
#define FREESECT   0xFFFFFFFFu

static const unsigned char SIG[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

static uint32_t rd16(const unsigned char *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Pointer to regular sector k and how many of its bytes the file actually
// holds (*avail < sector_size only for a truncated last sector - real files,
// e.g. some MSIs, end mid-sector). NULL if the sector starts beyond the file.
static const unsigned char *sector_at(const cfb_file *f, uint32_t k, size_t *avail)
{
    size_t off = ((size_t)k + 1) * f->sector_size;
    if (k >= 0xFFFFFFF0u || off / f->sector_size != (size_t)k + 1 || off >= f->n) {
        return NULL;
    }
    size_t left = f->n - off;
    *avail = left < f->sector_size ? left : f->sector_size;
    return f->d + off;
}

// Whole sector or NULL (for header-like structures that must be complete).
static const unsigned char *sector(const cfb_file *f, uint32_t k)
{
    size_t avail = 0;
    const unsigned char *s = sector_at(f, k, &avail);
    return (s != NULL && avail == f->sector_size) ? s : NULL;
}

// Read a regular-sector chain into a new buffer of `want` bytes (or the whole
// chain if want == 0). Returns malloc'd data and its length, or NULL.
static unsigned char *read_chain(const cfb_file *f, uint32_t start, size_t want, size_t *outlen)
{
    size_t cap = want ? want : f->sector_size * 4, len = 0;
    unsigned char *buf = (unsigned char *)malloc(cap ? cap : 1);
    if (buf == NULL) return NULL;
    uint32_t k = start;
    for (size_t steps = 0; k != ENDOFCHAIN && steps <= f->nfat; steps++) {
        size_t avail = 0;
        const unsigned char *s = sector_at(f, k, &avail);
        if (s == NULL || k >= f->nfat) { free(buf); return NULL; }
        size_t take = f->sector_size;
        if (want && len + take > want) take = want - len;
        if (avail < take) { free(buf); return NULL; }   // the bytes we need are not in the file
        if (len + take > cap) {
            size_t nc = cap * 2;
            unsigned char *nb = (unsigned char *)realloc(buf, nc);
            if (nb == NULL) { free(buf); return NULL; }
            buf = nb;
            cap = nc;
        }
        memcpy(buf + len, s, take);
        len += take;
        if (want && len >= want) break;
        k = f->fat[k];
    }
    if (want && len < want) { free(buf); return NULL; }     // chain shorter than size
    *outlen = len;
    return buf;
}

static unsigned char *read_mini_chain(const cfb_file *f, uint32_t start, size_t want)
{
    unsigned char *buf = (unsigned char *)malloc(want ? want : 1);
    if (buf == NULL) return NULL;
    size_t len = 0;
    uint32_t k = start;
    for (size_t steps = 0; len < want && steps <= f->nminifat; steps++) {
        if (k >= f->nminifat) { free(buf); return NULL; }
        size_t off = (size_t)k * f->mini_size;
        if (off > f->ministream_len || f->ministream_len - off < f->mini_size) { free(buf); return NULL; }
        size_t take = f->mini_size;
        if (len + take > want) take = want - len;
        memcpy(buf + len, f->ministream + off, take);
        len += take;
        k = f->minifat[k];
    }
    if (len < want) { free(buf); return NULL; }
    return buf;
}

int cfb_open(cfb_file *f, const unsigned char *d, size_t n)
{
    memset(f, 0, sizeof *f);
    if (n < 512 || memcmp(d, SIG, 8) != 0) return -1;
    f->d = d;
    f->n = n;
    unsigned shift = rd16(d + 0x1E), mshift = rd16(d + 0x20);
    if ((shift != 9 && shift != 12) || mshift != 6) return -2;
    f->sector_size = 1u << shift;
    f->mini_size = 1u << mshift;
    f->mini_cutoff = rd32(d + 0x38);
    uint32_t nfatsec = rd32(d + 0x2C);
    f->dir_start = rd32(d + 0x30);
    uint32_t minifat_start = rd32(d + 0x3C), nminifatsec = rd32(d + 0x40);
    uint32_t difat_start = rd32(d + 0x44), ndifat = rd32(d + 0x48);

    // Never trust counts beyond what the file could physically hold.
    size_t max_sectors = n / f->sector_size;
    if (nfatsec > max_sectors || nminifatsec > max_sectors || ndifat > max_sectors) return -2;

    // Collect the FAT sector numbers: 109 in the header, the rest in DIFAT sectors.
    uint32_t *fatsecs = (uint32_t *)malloc((nfatsec ? nfatsec : 1) * sizeof *fatsecs);
    if (fatsecs == NULL) return -2;
    size_t got = 0;
    for (unsigned i = 0; i < 109 && got < nfatsec; i++) fatsecs[got++] = rd32(d + 0x4C + 4 * i);
    uint32_t ds = difat_start;
    unsigned per = f->sector_size / 4 - 1;      // last slot links to the next DIFAT sector
    for (uint32_t j = 0; j < ndifat && got < nfatsec && ds != ENDOFCHAIN; j++) {
        const unsigned char *s = sector(f, ds);
        if (s == NULL) { free(fatsecs); return -2; }
        for (unsigned i = 0; i < per && got < nfatsec; i++) fatsecs[got++] = rd32(s + 4 * i);
        ds = rd32(s + 4 * per);
    }
    if (got < nfatsec) { free(fatsecs); return -2; }

    f->nfat = (size_t)nfatsec * (f->sector_size / 4);
    f->fat = (uint32_t *)malloc((f->nfat ? f->nfat : 1) * sizeof *f->fat);
    if (f->fat == NULL) { free(fatsecs); return -2; }
    for (uint32_t i = 0; i < nfatsec; i++) {
        const unsigned char *s = sector(f, fatsecs[i]);
        if (s == NULL) { free(fatsecs); cfb_close(f); return -2; }
        for (unsigned j = 0; j < f->sector_size / 4; j++) {
            f->fat[(size_t)i * (f->sector_size / 4) + j] = rd32(s + 4 * j);
        }
    }
    free(fatsecs);

    // Mini FAT (optional: only present when small streams exist).
    if (nminifatsec > 0 && minifat_start != ENDOFCHAIN) {
        size_t len = 0;
        unsigned char *raw = read_chain(f, minifat_start, (size_t)nminifatsec * f->sector_size, &len);
        if (raw == NULL) { cfb_close(f); return -2; }
        f->nminifat = len / 4;
        f->minifat = (uint32_t *)malloc((f->nminifat ? f->nminifat : 1) * sizeof *f->minifat);
        if (f->minifat == NULL) { free(raw); cfb_close(f); return -2; }
        for (size_t i = 0; i < f->nminifat; i++) f->minifat[i] = rd32(raw + 4 * i);
        free(raw);
    }

    // The root directory entry (first entry) owns the mini stream.
    const unsigned char *dir0 = sector(f, f->dir_start);
    if (dir0 == NULL || rd16(dir0 + 66) % 256 != 5) { cfb_close(f); return -2; }
    uint32_t root_start = rd32(dir0 + 116);
    uint32_t root_size = rd32(dir0 + 120);
    if (root_size > 0 && root_start != ENDOFCHAIN) {
        if (root_size > n) { cfb_close(f); return -2; }
        size_t len = 0;
        f->ministream = read_chain(f, root_start, root_size, &len);
        if (f->ministream == NULL) { cfb_close(f); return -2; }
        f->ministream_len = len;
    }
    return 0;
}

void cfb_close(cfb_file *f)
{
    free(f->fat);
    free(f->minifat);
    free(f->ministream);
    f->fat = f->minifat = NULL;
    f->ministream = NULL;
}

int cfb_streams(const cfb_file *f, cfb_stream_cb cb, void *ctx)
{
    size_t dirlen = 0;
    unsigned char *dir = read_chain(f, f->dir_start, 0, &dirlen);
    if (dir == NULL) return -2;
    int visited = 0;
    for (size_t off = 0; off + 128 <= dirlen; off += 128) {
        const unsigned char *e = dir + off;
        if (e[66] != 2) continue;                               // streams only
        unsigned nlen = rd16(e + 64);
        if (nlen < 2 || nlen > 64) continue;
        char name[96];
        size_t o = 0;
        for (unsigned i = 0; i + 1 < nlen && i < 62 && o + 4 < sizeof name; i += 2) {
            uint32_t c = rd16(e + i);
            if (c == 0) break;
            if (c < 0x80) name[o++] = (char)c;
            else if (c < 0x800) { name[o++] = (char)(0xC0 | (c >> 6)); name[o++] = (char)(0x80 | (c & 0x3F)); }
            else { name[o++] = (char)(0xE0 | (c >> 12)); name[o++] = (char)(0x80 | ((c >> 6) & 0x3F));
                   name[o++] = (char)(0x80 | (c & 0x3F)); }
        }
        name[o] = '\0';
        uint32_t start = rd32(e + 116), size = rd32(e + 120);
        if (size > f->n) continue;                              // impossible size
        unsigned char *data = NULL;
        size_t len = size;
        if (size == 0) {
            data = (unsigned char *)malloc(1);
        } else if (size < f->mini_cutoff) {
            if (f->ministream != NULL) data = read_mini_chain(f, start, size);
        } else {
            data = read_chain(f, start, size, &len);
        }
        if (data == NULL) continue;                             // broken chain: skip the stream
        cb(name, data, size, ctx);
        free(data);
        visited++;
    }
    free(dir);
    return visited;
}
