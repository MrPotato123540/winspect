// Defender Detection History files (see defhist.h). Portable C.

#include "defhist.h"

#include <stdio.h>
#include <string.h>

static uint32_t u32(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t u64(const unsigned char *p) { return (uint64_t)u32(p) | (uint64_t)u32(p + 4) << 32; }

// UTF-16LE (len bytes) -> UTF-8, stopping at NUL. Unpaired surrogates become '?'.
static void utf16(const unsigned char *d, size_t len, char *out, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i + 1 < len && o + 5 < n; i += 2) {
        uint32_t c = (uint32_t)(d[i] | d[i + 1] << 8);
        if (c == 0) break;
        if (c >= 0xD800 && c <= 0xDBFF && i + 3 < len) {
            uint32_t lo = (uint32_t)(d[i + 2] | d[i + 3] << 8);
            if (lo >= 0xDC00 && lo <= 0xDFFF) { c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); i += 2; }
            else c = '?';
        } else if (c >= 0xD800 && c <= 0xDFFF) c = '?';
        if (c < 0x80) out[o++] = (char)c;
        else if (c < 0x800) { out[o++] = (char)(0xC0 | c >> 6); out[o++] = (char)(0x80 | (c & 0x3F)); }
        else if (c < 0x10000) { out[o++] = (char)(0xE0 | c >> 12); out[o++] = (char)(0x80 | ((c >> 6) & 0x3F)); out[o++] = (char)(0x80 | (c & 0x3F)); }
        else { out[o++] = (char)(0xF0 | c >> 18); out[o++] = (char)(0x80 | ((c >> 12) & 0x3F)); out[o++] = (char)(0x80 | ((c >> 6) & 0x3F)); out[o++] = (char)(0x80 | (c & 0x3F)); }
    }
    out[o] = '\0';
}

// Finds the string property `key` inside a resource's property blob:
//   key (UTF-16, NUL-terminated) | u32 type (6 = string) | u32 byte length | UTF-16 value
// and copies it when it is exactly `want` hex digits.
static void blob_hex_prop(const unsigned char *b, size_t n, const char *key, size_t want, char *out)
{
    out[0] = '\0';
    unsigned char k16[96];
    size_t kl = strlen(key);
    if (kl * 2 + 2 > sizeof k16) return;
    for (size_t i = 0; i <= kl; i++) { k16[i * 2] = (unsigned char)key[i]; k16[i * 2 + 1] = 0; }
    size_t klen = kl * 2 + 2;
    for (size_t i = 0; i + klen + 8 <= n; i += 2) {
        if (memcmp(b + i, k16, klen) != 0) continue;
        size_t p = i + klen;
        uint32_t type = u32(b + p), len = u32(b + p + 4);
        if (type != 6 || len < want * 2 || len > n - (p + 8)) return;
        char v[80];
        utf16(b + p + 8, len, v, sizeof v);
        if (strlen(v) != want) return;
        for (size_t h = 0; h < want; h++) {
            char c = v[h];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return;
        }
        memcpy(out, v, want + 1);
        return;
    }
}

// Bounded copy (the source can be longer than the field; cutting is intended).
static void put(char *dst, size_t n, const char *src)
{
    snprintf(dst, n, "%.*s", (int)(n - 1), src);
}

int dh_parse(const unsigned char *d, size_t n, dh_record *r)
{
    memset(r, 0, sizeof *r);
    enum { ST_HEAD, ST_THREAT, ST_COUNTERS, ST_RES_TYPE, ST_RES_LOC, ST_RES_BODY, ST_TAIL } st = ST_HEAD;
    int have_id = 0, have_guid = 0, tail_times = 0, tail_strings = 0, got_threat = 0;
    dh_resource scratch;                    // receives resources beyond DH_MAX_RES
    dh_resource *cur = NULL;
    size_t off = 0;
    unsigned guard = 0;
    while (off + 8 <= n && guard++ < 100000) {
        uint32_t size = u32(d + off), type = u32(d + off + 4);
        const unsigned char *v = d + off + 8;
        if (size > n - (off + 8)) break;    // value runs past the file: stop, keep what we have
        switch (type) {
        case 0x08:
            if (!have_id && size >= 8) { r->threat_id = u64(v); have_id = 1; }
            break;
        case 0x1E:
            if (!have_guid && size >= 16) {
                snprintf(r->guid, sizeof r->guid, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", u32(v),
                         (unsigned)(v[4] | v[5] << 8), (unsigned)(v[6] | v[7] << 8), v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
                have_guid = 1;
            }
            break;
        case 0x15: {
            char s[1024];
            utf16(v, size, s, sizeof s);
            if (st != ST_TAIL && strncmp(s, "Magic.Version:", 14) == 0) {
                st = got_threat ? ST_RES_TYPE : ST_THREAT;
            } else if (st == ST_THREAT) {
                put(r->threat, sizeof r->threat, s);
                got_threat = 1;
                st = ST_COUNTERS;
            } else if (st == ST_RES_TYPE) {
                cur = r->nres < DH_MAX_RES ? &r->res[r->nres++] : &scratch;
                memset(cur, 0, sizeof *cur);
                put(cur->type, sizeof cur->type, s);
                st = ST_RES_LOC;
            } else if (st == ST_RES_LOC) {
                put(cur->location, sizeof cur->location, s);
                st = ST_RES_BODY;
            } else if (st == ST_TAIL) {
                if (tail_strings == 0) put(r->user, sizeof r->user, s);
                else if (tail_strings == 1) put(r->process, sizeof r->process, strcmp(s, "Unknown") == 0 ? "" : s);
                else if (tail_strings == 2) put(r->remediation_user, sizeof r->remediation_user, s);
                tail_strings++;
            }
            break;
        }
        case 0x28:
            if (st == ST_RES_BODY && cur != NULL && cur->sha256[0] == '\0')
                blob_hex_prop(v, size, "ThreatTrackingSha256", 64, cur->sha256);
            break;
        case 0x0A:
            if (size >= 8 && got_threat) {
                st = ST_TAIL;
                uint64_t t = u64(v);
                if (tail_times == 0) r->status_time = t;
                else if (tail_times == 1) r->detect_time = t;
                else if (tail_times == 2) r->remediation_time = t;
                tail_times++;
            }
            break;
        default:
            break;
        }
        size_t step = 8 + (size_t)size;
        step = (step + 7) & ~(size_t)7;
        off += step;
    }
    return got_threat ? 0 : -1;
}

const dh_resource *dh_primary(const dh_record *r)
{
    for (int i = 0; i < r->nres; i++) if (strcmp(r->res[i].type, "file") == 0) return &r->res[i];
    return r->nres ? &r->res[0] : NULL;
}

void dh_web_url(const char *location, char *out, size_t n)
{
    out[0] = '\0';
    const char *a = strchr(location, '|');
    if (a == NULL) return;
    a++;
    const char *b = strchr(a, '|');
    size_t len = b ? (size_t)(b - a) : strlen(a);
    if (len >= n) len = n - 1;
    memcpy(out, a, len);
    out[len] = '\0';
}
