// usn - NTFS change journal records (see usn.h)

#include "usn.h"

#include <stdio.h>
#include <string.h>

static uint16_t rd16(const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const unsigned char *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const unsigned char *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

static void name_u8(const unsigned char *s, size_t bytes, char *out, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i + 1 < bytes; i += 2) {
        uint32_t c = rd16(s + i);
        if (c >= 0xD800 && c <= 0xDBFF && i + 3 < bytes) {
            uint32_t lo = rd16(s + i + 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) { c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); i += 2; }
            else c = '?';
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            c = '?';
        }
        unsigned char b[4] = { 0, 0, 0, 0 };
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

int usn_next(const unsigned char *d, size_t n, size_t *off, usn_rec *r)
{
    size_t o = (*off + 7) & ~(size_t)7;
    while (o + 8 <= n) {
        uint32_t len = rd32(d + o);
        if (len == 0) {                                  // sparse / unused: skip zero runs
            o += 8;
            continue;
        }
        uint16_t major = rd16(d + o + 4);
        size_t fixed = major == 2 ? 60 : major == 3 ? 76 : 0;
        if (fixed == 0 || len < fixed || len > 65536 || len % 8 || o + len > n) {
            o += 8;                                      // not a record here: resynchronise
            continue;
        }
        const unsigned char *p = d + o;
        memset(r, 0, sizeof *r);
        r->major = major;
        size_t t;
        if (major == 2) {
            r->file_ref = rd64(p + 8);
            r->parent_ref = rd64(p + 16);
            t = 24;
        } else {
            r->file_ref = rd64(p + 8);
            r->parent_ref = rd64(p + 24);
            t = 40;
        }
        r->usn = rd64(p + t);
        r->time = rd64(p + t + 8);
        r->reason = rd32(p + t + 16);
        r->attributes = rd32(p + t + 28);
        uint16_t nlen = rd16(p + t + 32), noff = rd16(p + t + 34);
        if ((size_t)noff + nlen > len || noff < fixed - 2) {
            o += 8;
            continue;
        }
        name_u8(p + noff, nlen, r->name, sizeof r->name);
        *off = o + len;
        return 1;
    }
    *off = n;
    return 0;
}

void usn_reason_str(uint32_t reason, char *out, size_t n)
{
    static const struct { uint32_t bit; const char *name; } names[] = {
        { 0x00000001, "DATA_OVERWRITE" }, { 0x00000002, "DATA_EXTEND" }, { 0x00000004, "DATA_TRUNCATION" },
        { 0x00000010, "NAMED_DATA_OVERWRITE" }, { 0x00000020, "NAMED_DATA_EXTEND" },
        { 0x00000040, "NAMED_DATA_TRUNCATION" }, { 0x00000100, "FILE_CREATE" }, { 0x00000200, "FILE_DELETE" },
        { 0x00000400, "EA_CHANGE" }, { 0x00000800, "SECURITY_CHANGE" }, { 0x00001000, "RENAME_OLD_NAME" },
        { 0x00002000, "RENAME_NEW_NAME" }, { 0x00004000, "INDEXABLE_CHANGE" }, { 0x00008000, "BASIC_INFO_CHANGE" },
        { 0x00010000, "HARD_LINK_CHANGE" }, { 0x00020000, "COMPRESSION_CHANGE" }, { 0x00040000, "ENCRYPTION_CHANGE" },
        { 0x00080000, "OBJECT_ID_CHANGE" }, { 0x00100000, "REPARSE_POINT_CHANGE" }, { 0x00200000, "STREAM_CHANGE" },
        { 0x00400000, "TRANSACTED_CHANGE" }, { 0x00800000, "INTEGRITY_CHANGE" }, { 0x80000000, "CLOSE" },
    };
    size_t o = 0;
    out[0] = 0;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (!(reason & names[i].bit)) continue;
        int w = snprintf(out + o, n - o, "%s%s", o ? "|" : "", names[i].name);
        if (w < 0 || (size_t)w >= n - o) break;
        o += (size_t)w;
    }
}

const char *usn_flag(uint32_t reason, const char *name, const char *old_name, int (*is_program)(const char *))
{
    if ((reason & 0x00000200) && is_program(name)) return "program or script deleted";
    if ((reason & 0x00002000) && old_name && old_name[0] && is_program(name) && !is_program(old_name))
        return "renamed into a program or script";
    return NULL;
}
