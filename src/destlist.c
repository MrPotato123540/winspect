// destlist - Jump List DestList stream parser, portable C (see destlist.h)

#include "destlist.h"

#include <string.h>

static uint32_t rd16(const unsigned char *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const unsigned char *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

// Days between the UUID epoch (1582-10-15) and the FILETIME epoch (1601-01-01),
// in 100 ns units.
#define UUID_TO_FILETIME 5748192000000000ULL

uint64_t uuid1_info(const unsigned char g[16], char mac[18])
{
    static const char hex[] = "0123456789abcdef";
    mac[0] = '\0';
    uint32_t d3 = rd16(g + 6);
    if ((d3 >> 12) != 1) return 0;
    for (int i = 0; i < 6; i++) {
        mac[i * 3]     = hex[g[10 + i] >> 4];
        mac[i * 3 + 1] = hex[g[10 + i] & 15];
        mac[i * 3 + 2] = i < 5 ? ':' : '\0';
    }
    uint64_t ts = ((uint64_t)(d3 & 0x0FFF) << 48) | ((uint64_t)rd16(g + 4) << 32) | rd32(g);
    return ts > UUID_TO_FILETIME ? ts - UUID_TO_FILETIME : 0;
}

// UTF-16LE -> UTF-8 (BMP + surrogate pairs; lone surrogates become '?').
static void u16_to_u8(const unsigned char *s, size_t nchars, char *out, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < nchars; i++) {
        uint32_t c = rd16(s + 2 * i);
        if (c == 0) break;
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < nchars) {
            uint32_t lo = rd16(s + 2 * i + 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) { c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); i++; }
            else c = '?';
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            c = '?';
        }
        unsigned char b[4] = { 0, 0, 0, 0 }; size_t len;
        if (c < 0x80)         { b[0] = (unsigned char)c; len = 1; }
        else if (c < 0x800)   { b[0] = (unsigned char)(0xC0 | (c >> 6)); b[1] = (unsigned char)(0x80 | (c & 0x3F)); len = 2; }
        else if (c < 0x10000) { b[0] = (unsigned char)(0xE0 | (c >> 12)); b[1] = (unsigned char)(0x80 | ((c >> 6) & 0x3F));
                                b[2] = (unsigned char)(0x80 | (c & 0x3F)); len = 3; }
        else                  { b[0] = (unsigned char)(0xF0 | (c >> 18)); b[1] = (unsigned char)(0x80 | ((c >> 12) & 0x3F));
                                b[2] = (unsigned char)(0x80 | ((c >> 6) & 0x3F)); b[3] = (unsigned char)(0x80 | (c & 0x3F)); len = 4; }
        if (o + len + 1 > n) break;
        memcpy(out + o, b, len);
        o += len;
    }
    out[o] = '\0';
}

int destlist_parse(const unsigned char *d, size_t n, uint32_t *version, uint32_t *pinned_hdr,
                   dl_cb cb, void *ctx)
{
    if (n < 32) return -1;
    uint32_t ver = rd32(d);
    *version = ver;
    *pinned_hdr = rd32(d + 8);
    size_t fixed, trailer;
    if (ver == 1)                 { fixed = 114; trailer = 0; }
    else if (ver == 3 || ver == 4) { fixed = 130; trailer = 4; }
    else return -1;
    uint32_t declared = rd32(d + 4);
    size_t pos = 32;
    int count = 0;
    while ((uint32_t)count < declared && pos + fixed <= n) {
        const unsigned char *e = d + pos;
        size_t plen = rd16(e + fixed - 2);
        if (plen * 2 + trailer > n - pos - fixed) break;     // path runs past the stream
        dl_entry x;
        memset(&x, 0, sizeof x);
        x.mru = (unsigned)count;
        x.entry = rd32(e + 88);
        x.last_used = rd64(e + 100);
        x.pinned = (int32_t)rd32(e + 108) != -1;
        if (ver >= 3) {
            x.has_interactions = 1;
            x.interactions = rd32(e + 116);
        }
        size_t h = 0;
        while (h < 16 && e[72 + h] != 0) {
            x.host[h] = (e[72 + h] < 0x80) ? (char)e[72 + h] : '?';
            h++;
        }
        x.host[h] = '\0';
        x.droid_time = uuid1_info(e + 24, x.mac);
        u16_to_u8(e + fixed, plen, x.path, sizeof x.path);
        cb(&x, ctx);
        count++;
        pos += fixed + plen * 2 + trailer;
    }
    return count;
}
