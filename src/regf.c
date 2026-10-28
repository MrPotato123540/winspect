// regf - registry hive file reader, portable C (see regf.h for the layout)

#include "regf.h"

#include <stdlib.h>
#include <string.h>

#define BASE_BLOCK     4096u
#define BIG_DATA_SEG   16344u
#define MAX_LIST_DEPTH 4

static uint32_t rd16(const unsigned char *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const unsigned char *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

// Data of the cell at a cell offset, with its usable length; NULL if the
// offset or the cell size points outside the hive bins.
static const unsigned char *cell(const regf_hive *h, uint32_t off, size_t *len)
{
    if (off == 0xFFFFFFFFu || (size_t)off + 4 > h->bins) return NULL;
    const unsigned char *raw = h->d + BASE_BLOCK + off;
    int32_t sz = (int32_t)rd32(raw);
    uint32_t abs = sz < 0 ? (uint32_t)(-(int64_t)sz) : (uint32_t)sz;
    if (abs < 8 || (size_t)off + abs > h->bins) return NULL;
    *len = abs - 4;
    return raw + 4;
}

static size_t put_utf8(uint32_t c, char *out, size_t o, size_t n)
{
    unsigned char b[4] = { 0, 0, 0, 0 };
    size_t len;
    if (c < 0x80)         { b[0] = (unsigned char)c; len = 1; }
    else if (c < 0x800)   { b[0] = (unsigned char)(0xC0 | (c >> 6)); b[1] = (unsigned char)(0x80 | (c & 0x3F)); len = 2; }
    else if (c < 0x10000) { b[0] = (unsigned char)(0xE0 | (c >> 12)); b[1] = (unsigned char)(0x80 | ((c >> 6) & 0x3F));
                            b[2] = (unsigned char)(0x80 | (c & 0x3F)); len = 3; }
    else                  { b[0] = (unsigned char)(0xF0 | (c >> 18)); b[1] = (unsigned char)(0x80 | ((c >> 12) & 0x3F));
                            b[2] = (unsigned char)(0x80 | ((c >> 6) & 0x3F)); b[3] = (unsigned char)(0x80 | (c & 0x3F)); len = 4; }
    if (o + len + 1 > n) return o;
    memcpy(out + o, b, len);
    return o + len;
}

// Name bytes -> UTF-8: Latin-1 when latin1 is set, else UTF-16LE.
static void name_to_utf8(const unsigned char *s, size_t bytes, int latin1, char *out, size_t n)
{
    size_t o = 0;
    if (latin1) {
        for (size_t i = 0; i < bytes; i++) o = put_utf8(s[i], out, o, n);
    } else {
        size_t units = bytes / 2;
        for (size_t i = 0; i < units; i++) {
            uint32_t c = rd16(s + 2 * i);
            if (c >= 0xD800 && c <= 0xDBFF && i + 1 < units) {
                uint32_t lo = rd16(s + 2 * i + 2);
                if (lo >= 0xDC00 && lo <= 0xDFFF) { c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); i++; }
                else c = '?';
            } else if (c >= 0xD800 && c <= 0xDFFF) {
                c = '?';
            }
            o = put_utf8(c, out, o, n);
        }
    }
    out[o] = '\0';
}

int regf_open(regf_hive *h, const unsigned char *d, size_t n)
{
    memset(h, 0, sizeof *h);
    if (n < 512 || memcmp(d, "regf", 4) != 0) return -1;
    if (n < BASE_BLOCK + 32) return -2;
    h->d = d;
    h->n = n;
    h->seq1 = rd32(d + 4);
    h->seq2 = rd32(d + 8);
    h->last_written = rd64(d + 12);
    h->major = rd32(d + 20);
    h->minor = rd32(d + 24);
    h->root = rd32(d + 36);
    size_t declared = rd32(d + 40);
    h->bins = n - BASE_BLOCK;
    if (declared < h->bins) h->bins = declared;
    // Checksum: XOR of the first 127 dwords (0 -> 1, 0xFFFFFFFF -> 0xFFFFFFFE).
    uint32_t x = 0;
    for (int i = 0; i < 127; i++) x ^= rd32(d + 4 * i);
    if (x == 0) x = 1;
    if (x == 0xFFFFFFFFu) x = 0xFFFFFFFEu;
    h->checksum_ok = (x == rd32(d + 508));
    name_to_utf8(d + 48, 64, 0, h->file_name, sizeof h->file_name);
    regf_key_info ki;
    return regf_key(h, h->root, &ki) == 0 ? 0 : -2;
}

// The nk record of a key cell, or NULL.
static const unsigned char *nk(const regf_hive *h, uint32_t key, size_t *len)
{
    const unsigned char *c = cell(h, key, len);
    if (c == NULL || *len < 76 || c[0] != 'n' || c[1] != 'k') return NULL;
    if (rd16(c + 72) > *len - 76) return NULL;
    return c;
}

int regf_key(const regf_hive *h, uint32_t key, regf_key_info *out)
{
    size_t len;
    const unsigned char *c = nk(h, key, &len);
    if (c == NULL) return -1;
    out->last_written = rd64(c + 4);
    out->subkeys = rd32(c + 20);
    out->values = rd32(c + 36);
    name_to_utf8(c + 76, rd16(c + 72), (rd16(c + 2) & 0x20) != 0, out->name, sizeof out->name);
    return 0;
}

static int walk_list(const regf_hive *h, uint32_t off, int depth, regf_key_cb cb, void *ctx)
{
    size_t len;
    const unsigned char *c = cell(h, off, &len);
    if (c == NULL || len < 4 || depth > MAX_LIST_DEPTH) return -1;
    size_t count = rd16(c + 2);
    int total = 0;
    if ((c[0] == 'l' && (c[1] == 'f' || c[1] == 'h'))) {
        if (4 + count * 8 > len) return -1;
        for (size_t i = 0; i < count; i++) { cb(rd32(c + 4 + i * 8), ctx); total++; }
    } else if (c[0] == 'l' && c[1] == 'i') {
        if (4 + count * 4 > len) return -1;
        for (size_t i = 0; i < count; i++) { cb(rd32(c + 4 + i * 4), ctx); total++; }
    } else if (c[0] == 'r' && c[1] == 'i') {
        if (4 + count * 4 > len) return -1;
        for (size_t i = 0; i < count; i++) {
            int r = walk_list(h, rd32(c + 4 + i * 4), depth + 1, cb, ctx);
            if (r > 0) total += r;
        }
    } else {
        return -1;
    }
    return total;
}

int regf_subkeys(const regf_hive *h, uint32_t key, regf_key_cb cb, void *ctx)
{
    size_t len;
    const unsigned char *c = nk(h, key, &len);
    if (c == NULL) return -1;
    if (rd32(c + 20) == 0) return 0;
    return walk_list(h, rd32(c + 28), 0, cb, ctx);
}

int regf_values(const regf_hive *h, uint32_t key, regf_value_cb cb, void *ctx)
{
    size_t len;
    const unsigned char *c = nk(h, key, &len);
    if (c == NULL) return -1;
    size_t count = rd32(c + 36);
    if (count == 0) return 0;
    size_t llen;
    const unsigned char *list = cell(h, rd32(c + 40), &llen);
    if (list == NULL || count > llen / 4) return -1;
    int total = 0;
    for (size_t i = 0; i < count; i++) {
        size_t vlen;
        const unsigned char *vk = cell(h, rd32(list + 4 * i), &vlen);
        if (vk == NULL || vlen < 20 || vk[0] != 'v' || vk[1] != 'k') continue;
        size_t nlen = rd16(vk + 2);
        if (nlen > vlen - 20) continue;
        regf_value v;
        memset(&v, 0, sizeof v);
        name_to_utf8(vk + 20, nlen, (rd16(vk + 16) & 1) != 0, v.name, sizeof v.name);
        v.type = rd32(vk + 12);
        uint32_t dsize = rd32(vk + 4), doff = rd32(vk + 8);
        unsigned char *big = NULL;
        if (dsize & 0x80000000u) {
            // Small values (<= 4 bytes) live in the data-offset field itself.
            v.len = dsize & 0x7FFFFFFFu;
            if (v.len > 4) v.len = 4;
            v.data = vk + 8;
        } else if (dsize > BIG_DATA_SEG && h->minor >= 4) {
            size_t dblen;
            const unsigned char *db = cell(h, doff, &dblen);
            if (db != NULL && dblen >= 8 && db[0] == 'd' && db[1] == 'b') {
                size_t segs = rd16(db + 2), sllen;
                const unsigned char *sl = cell(h, rd32(db + 4), &sllen);
                big = (sl != NULL && segs <= sllen / 4 && dsize <= h->bins)
                      ? (unsigned char *)malloc(dsize) : NULL;
                size_t got = 0;
                for (size_t s = 0; big != NULL && s < segs && got < dsize; s++) {
                    size_t seglen;
                    const unsigned char *seg = cell(h, rd32(sl + 4 * s), &seglen);
                    if (seg == NULL) break;
                    size_t take = dsize - got;
                    if (take > BIG_DATA_SEG) take = BIG_DATA_SEG;
                    if (take > seglen) take = seglen;
                    memcpy(big + got, seg, take);
                    got += take;
                }
                v.data = big;
                v.len = big ? got : 0;
            }
        } else if (dsize > 0) {
            size_t dlen;
            const unsigned char *data = cell(h, doff, &dlen);
            if (data != NULL) {
                v.data = data;
                v.len = dsize < dlen ? dsize : dlen;
            }
        }
        cb(&v, ctx);
        free(big);
        total++;
    }
    return total;
}

// Case-insensitive (ASCII) equality of two UTF-8 strings.
static int name_eq(const char *a, const char *b, size_t blen)
{
    size_t i = 0;
    for (; i < blen && a[i]; i++) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y) return 0;
    }
    return i == blen && a[i] == '\0';
}

struct find_ctx {
    const regf_hive *h;
    const char *want;
    size_t wlen;
    uint32_t found;
    int ok;
};

static void find_cb(uint32_t sub, void *vctx)
{
    struct find_ctx *f = (struct find_ctx *)vctx;
    regf_key_info ki;
    if (f->ok || regf_key(f->h, sub, &ki) != 0) return;
    if (name_eq(ki.name, f->want, f->wlen)) {
        f->found = sub;
        f->ok = 1;
    }
}

int regf_find(const regf_hive *h, const char *path, uint32_t *key)
{
    uint32_t cur = h->root;
    const char *p = path;
    while (*p) {
        while (*p == '\\') p++;
        if (*p == '\0') break;
        const char *e = p;
        while (*e && *e != '\\') e++;
        struct find_ctx f = { h, p, (size_t)(e - p), 0, 0 };
        if (regf_subkeys(h, cur, find_cb, &f) < 0 || !f.ok) return -1;
        cur = f.found;
        p = e;
    }
    *key = cur;
    return 0;
}

struct get_ctx {
    const char *name;
    uint32_t *type;
    unsigned char *out;
    size_t n;
    long len;
};

static void get_cb(const regf_value *v, void *vctx)
{
    struct get_ctx *g = (struct get_ctx *)vctx;
    if (g->len >= 0 || !name_eq(v->name, g->name, strlen(g->name))) return;
    if (g->type) *g->type = v->type;
    size_t take = v->len < g->n ? v->len : g->n;
    if (take && v->data) memcpy(g->out, v->data, take);
    g->len = (long)v->len;
}

long regf_get(const regf_hive *h, uint32_t key, const char *name, uint32_t *type,
              unsigned char *out, size_t n)
{
    struct get_ctx g = { name, type, out, n, -1 };
    regf_values(h, key, get_cb, &g);
    return g.len;
}
