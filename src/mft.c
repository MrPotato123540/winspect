// mft - NTFS $MFT record reader (see mft.h)

#include "mft.h"

#include <stdio.h>
#include <string.h>

static uint16_t rd16(const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const unsigned char *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const unsigned char *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

size_t mft_record_size(const unsigned char *rec, size_t n)
{
    if (n < 48 || memcmp(rec, "FILE", 4) != 0) return 0;
    uint32_t s = rd32(rec + 28);
    return (s >= 512 && s <= 65536 && (s & (s - 1)) == 0) ? s : 0;
}

static void u16_to_u8(const unsigned char *s, size_t nchars, char *out, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < nchars; i++) {
        uint32_t c = rd16(s + 2 * i);
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < nchars) {
            uint32_t lo = rd16(s + 2 * i + 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) { c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); i++; }
            else c = '?';
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            c = '?';
        }
        unsigned char b[4];
        size_t len;
        if (c < 0x80) { b[0] = (unsigned char)c; len = 1; }
        else if (c < 0x800) { b[0] = (unsigned char)(0xC0 | (c >> 6)); b[1] = (unsigned char)(0x80 | (c & 0x3F)); len = 2; }
        else if (c < 0x10000) { b[0] = (unsigned char)(0xE0 | (c >> 12)); b[1] = (unsigned char)(0x80 | ((c >> 6) & 0x3F)); b[2] = (unsigned char)(0x80 | (c & 0x3F)); len = 3; }
        else { b[0] = (unsigned char)(0xF0 | (c >> 18)); b[1] = (unsigned char)(0x80 | ((c >> 12) & 0x3F)); b[2] = (unsigned char)(0x80 | ((c >> 6) & 0x3F)); b[3] = (unsigned char)(0x80 | (c & 0x3F)); len = 4; }
        if (o + len + 1 > n) break;
        memcpy(out + o, b, len);
        o += len;
    }
    out[o] = 0;
}

int mft_parse(unsigned char *rec, size_t n, uint32_t recno, mft_entry *e)
{
    memset(e, 0, sizeof *e);
    e->recno = recno;
    e->name_ns = -1;
    if (n < 48 || memcmp(rec, "FILE", 4) != 0) return -1;
    // Fixups: array at usa_off, usa_cnt entries of 2 bytes; entry 0 is the
    // update sequence number every sector end must hold.
    uint16_t usa_off = rd16(rec + 4), usa_cnt = rd16(rec + 6);
    if (usa_cnt < 1 || (size_t)usa_off + (size_t)usa_cnt * 2 > n || (size_t)(usa_cnt - 1) * 512 > n) return -1;
    uint16_t usn = rd16(rec + usa_off);
    for (uint16_t i = 1; i < usa_cnt; i++) {
        size_t end = (size_t)i * 512 - 2;
        if (end + 2 > n) return -1;
        if (rd16(rec + end) != usn) return -1;          // torn / corrupt record
        rec[end] = rec[usa_off + 2 * i];
        rec[end + 1] = rec[usa_off + 2 * i + 1];
    }
    e->seq = rd16(rec + 16);
    uint16_t first = rd16(rec + 20), flags = rd16(rec + 22);
    e->in_use = (flags & 1) != 0;
    e->dir = (flags & 2) != 0;
    e->extension = rd64(rec + 32) != 0;
    size_t off = first;
    int guard = 0;
    while (off + 16 <= n && guard++ < 256) {
        uint32_t type = rd32(rec + off);
        if (type == 0xFFFFFFFF) break;
        uint32_t len = rd32(rec + off + 4);
        if (len < 16 || off + len > n) break;
        const unsigned char *a = rec + off;
        int nonres = a[8];
        const unsigned char *c = NULL;
        uint32_t csize = 0;
        if (!nonres && len >= 24) {
            csize = rd32(a + 16);
            uint16_t coff = rd16(a + 20);
            if ((size_t)coff + csize <= len) c = a + coff;
        }
        if (type == 0x10 && c && csize >= 32) {
            for (int i = 0; i < 4; i++) e->si[i] = rd64(c + 8 * i);
            e->has_si = 1;
        } else if (type == 0x30 && c && csize >= 66) {
            uint8_t nl = c[64], ns = c[65];
            if ((size_t)66 + (size_t)nl * 2 <= csize) {
                // Prefer the Win32 (or Win32+DOS) name over the 8.3 DOS one.
                int better = e->name_ns < 0 || (e->name_ns == 2 && ns != 2) || (e->name_ns == 0 && (ns == 1 || ns == 3));
                if (better) {
                    e->parent = rd64(c);
                    for (int i = 0; i < 4; i++) e->fn[i] = rd64(c + 8 + 8 * i);
                    if (e->size == 0) e->size = rd64(c + 48);
                    u16_to_u8(c + 66, nl, e->name, sizeof e->name);
                    e->name_ns = ns;
                    e->has_fn = 1;
                }
            }
        } else if (type == 0x40 && c && csize >= 16) {
            memcpy(e->objid, c, 16);
            e->has_objid = 1;
        } else if (type == 0x80 && a[9] == 0) {                  // unnamed $DATA
            if (!nonres && c) e->size = csize;
            else if (nonres && len >= 56) e->size = rd64(a + 48);
        }
        off += len;
    }
    e->valid = 1;
    return 0;
}

int mft_path(const mft_node *tab, size_t count, uint32_t i, char *out, size_t n)
{
    // Collect names leaf -> root, then write them root -> leaf.
    const char *parts[64];
    int np = 0, orphan = 0;
    uint32_t cur = i;
    for (int depth = 0; depth < 64; depth++) {
        if (cur >= count || !tab[cur].valid) { orphan = 1; break; }
        const mft_node *e = &tab[cur];
        if (cur == MFT_ROOT) break;
        parts[np++] = e->name;
        uint32_t p = (uint32_t)(e->parent & 0xFFFFFFFFFFFFULL);
        uint16_t pseq = (uint16_t)(e->parent >> 48);
        // The parent must still be that directory: same sequence number, or -
        // when it was deleted afterwards - exactly one more (NTFS bumps the
        // sequence when a record is freed). A reused record is someone else.
        const mft_node *pe = p < count ? &tab[p] : NULL;
        int same = pe && pe->valid && (pseq == 0 || pe->seq == pseq || (!pe->in_use && pe->seq == (uint16_t)(pseq + 1)));
        if (p == cur || !same || (!pe->dir && p != MFT_ROOT)) {
            orphan = 1;
            break;
        }
        cur = p;
        if (depth == 63) orphan = 1;
    }
    size_t o = 0;
    out[0] = 0;
    if (orphan) o += (size_t)snprintf(out, n, "$Orphan");
    for (int k = np - 1; k >= 0 && o + 2 < n; k--) {
        int w = snprintf(out + o, n - o, "%s%s", (o == 0 && !orphan) ? "\\" : "\\", parts[k]);
        if (w < 0) break;
        o += (size_t)w;
        if (o >= n) { out[n - 1] = 0; break; }
    }
    if (np == 0 && !orphan) snprintf(out, n, "\\");
    return 0;
}

const char *mft_timestomp_reason(const uint64_t si[4], const uint64_t fn[4])
{
    if (si[0] == 0 || fn[0] == 0) return NULL;
    if (si[0] + 10000000ULL >= fn[0]) return NULL;              // not earlier by more than 1 s
    int si_whole = si[0] % 10000000ULL == 0 && si[1] % 10000000ULL == 0;
    int fn_whole = fn[0] % 10000000ULL == 0;
    if (si_whole && !fn_whole)
        return "created earlier in $STANDARD_INFORMATION than in $FILE_NAME, with whole-second times (timestomped?)";
    return "created earlier in $STANDARD_INFORMATION than in $FILE_NAME (backdated? some installers do this)";
}
