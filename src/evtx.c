// evtx - Windows XML event log file reader (see evtx.h for the layout)
//
// The binary XML is turned back into text with a recursive renderer:
//   * element start (0x01/0x41) writes "<name", attributes follow (0x06/0x46),
//     then close-start (0x02) ">" or close-empty (0x03) "/>"; end (0x04)
//     writes "</name>"
//   * value text (0x05), CDATA (0x07), character / entity references
//     (0x08/0x09) become escaped text
//   * a template instance (0x0C) names a template definition (a fragment
//     with numbered substitution tokens 0x0D/0x0E) and carries the values;
//     the definition is rendered with those values filled in. A value can be
//     another binary XML fragment (type 0x21), rendered recursively.
// An attribute whose value is an empty OPTIONAL substitution is left out, as
// Windows does (<Correlation/> rather than <Correlation ActivityID=""/>).

#include "evtx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK       65536u
#define HDR_SIZE    4096u
#define MAX_DEPTH   48

static uint16_t rd16(const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const unsigned char *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const unsigned char *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

// ---- growable output -----------------------------------------------------------

typedef struct { char *s; size_t n, cap; int oom; } sbuf;

static void sb_put(sbuf *b, const char *s, size_t n)
{
    if (b->oom) return;
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 1024;
        while (nc < b->n + n + 1) nc *= 2;
        char *ns = (char *)realloc(b->s, nc);
        if (ns == NULL) { b->oom = 1; return; }
        b->s = ns;
        b->cap = nc;
    }
    memcpy(b->s + b->n, s, n);
    b->n += n;
    b->s[b->n] = 0;
}

static void sb_str(sbuf *b, const char *s) { sb_put(b, s, strlen(s)); }

static void sb_fmt(sbuf *b, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

#include <stdarg.h>
static void sb_fmt(sbuf *b, const char *fmt, ...)
{
    char tmp[128];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n > 0) sb_put(b, tmp, (size_t)n < sizeof tmp ? (size_t)n : sizeof tmp - 1);
}

// UTF-16LE (nchars units) -> escaped UTF-8 text. escape: 1 = XML-escape.
static void sb_u16(sbuf *b, const unsigned char *s, size_t nchars, int escape)
{
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
        if (escape) {
            if (c == '<') { sb_str(b, "&lt;"); continue; }
            if (c == '>') { sb_str(b, "&gt;"); continue; }
            if (c == '&') { sb_str(b, "&amp;"); continue; }
            if (c == '"') { sb_str(b, "&quot;"); continue; }
        }
        char o[4];
        size_t n;
        if (c < 0x80)         { o[0] = (char)c; n = 1; }
        else if (c < 0x800)   { o[0] = (char)(0xC0 | (c >> 6)); o[1] = (char)(0x80 | (c & 0x3F)); n = 2; }
        else if (c < 0x10000) { o[0] = (char)(0xE0 | (c >> 12)); o[1] = (char)(0x80 | ((c >> 6) & 0x3F));
                                o[2] = (char)(0x80 | (c & 0x3F)); n = 3; }
        else                  { o[0] = (char)(0xF0 | (c >> 18)); o[1] = (char)(0x80 | ((c >> 12) & 0x3F));
                                o[2] = (char)(0x80 | ((c >> 6) & 0x3F)); o[3] = (char)(0x80 | (c & 0x3F)); n = 4; }
        sb_put(b, o, n);
    }
}

// ---- renderer ------------------------------------------------------------------

typedef struct {
    const unsigned char *data;  // value bytes (inside the chunk)
    uint16_t size;
    uint8_t type;
} subst;

typedef struct {
    const unsigned char *chunk; // chunk base: all name / template offsets are relative to it
    int fail;
} rctx;

// A name structure at chunk offset off: u32 next | u16 hash | u16 chars | UTF-16 | NUL.
static void put_name(rctx *r, sbuf *b, uint32_t off)
{
    if (off > CHUNK - 8) { r->fail = 1; return; }
    uint16_t nch = rd16(r->chunk + off + 6);
    if ((size_t)off + 8 + (size_t)nch * 2 > CHUNK) { r->fail = 1; return; }
    sb_u16(b, r->chunk + off + 8, nch, 0);
}

// Bytes a name structure at off occupies (to skip an inline one).
static size_t name_size(rctx *r, uint32_t off)
{
    if (off > CHUNK - 8) { r->fail = 1; return 0; }
    return 8 + (size_t)rd16(r->chunk + off + 6) * 2 + 2;
}

static int render(rctx *r, sbuf *b, const unsigned char *p, const unsigned char *end,
                  const subst *sv, unsigned nsv, int depth);

static void put_filetime(sbuf *b, uint64_t ft)
{
    // 100 ns ticks since 1601 -> ISO 8601 with 9 fraction digits (as EvtRender).
    uint64_t secs = ft / 10000000ULL, frac = ft % 10000000ULL;
    int64_t days = (int64_t)(secs / 86400) - 134774;     // days since 1970-01-01
    uint64_t rem = secs % 86400;
    int64_t z = days + 719468, era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = yoe + era * 400, doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153, d = doy - (153 * mp + 2) / 5 + 1, m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y++;
    sb_fmt(b, "%04d-%02d-%02dT%02d:%02d:%02d.%07llu00Z", (int)y, (int)m, (int)d,
           (int)(rem / 3600), (int)(rem / 60 % 60), (int)(rem % 60), (unsigned long long)frac);
}

// One typed value (substitution or array element) as text.
static void put_value(rctx *r, sbuf *b, uint8_t type, const unsigned char *v, size_t n, int depth)
{
    switch (type) {
    case 0x00: break;                                               // null
    case 0x01: sb_u16(b, v, n / 2, 1); break;                       // UTF-16 string
    case 0x02:                                                      // ANSI string
        for (size_t i = 0; i < n && v[i]; i++) {
            char c = (char)v[i];
            if (c == '<') sb_str(b, "&lt;"); else if (c == '>') sb_str(b, "&gt;");
            else if (c == '&') sb_str(b, "&amp;"); else if (c == '"') sb_str(b, "&quot;");
            else sb_put(b, &c, 1);
        }
        break;
    case 0x03: if (n >= 1) sb_fmt(b, "%d", (int)(signed char)v[0]); break;
    case 0x04: if (n >= 1) sb_fmt(b, "%u", (unsigned)v[0]); break;
    case 0x05: if (n >= 2) sb_fmt(b, "%d", (int)(int16_t)rd16(v)); break;
    case 0x06: if (n >= 2) sb_fmt(b, "%u", (unsigned)rd16(v)); break;
    case 0x07: if (n >= 4) sb_fmt(b, "%ld", (long)(int32_t)rd32(v)); break;
    case 0x08: if (n >= 4) sb_fmt(b, "%lu", (unsigned long)rd32(v)); break;
    case 0x09: if (n >= 8) sb_fmt(b, "%lld", (long long)(int64_t)rd64(v)); break;
    case 0x0A: if (n >= 8) sb_fmt(b, "%llu", (unsigned long long)rd64(v)); break;
    case 0x0B: if (n >= 4) { float f; memcpy(&f, v, 4); sb_fmt(b, "%g", (double)f); } break;
    case 0x0C: if (n >= 8) { double dd; memcpy(&dd, v, 8); sb_fmt(b, "%g", dd); } break;
    case 0x0D: if (n >= 4) sb_str(b, rd32(v) ? "true" : "false"); break;
    case 0x0E: for (size_t i = 0; i < n; i++) sb_fmt(b, "%02X", v[i]); break;   // binary
    case 0x0F:                                                      // GUID
        if (n >= 16)
            sb_fmt(b, "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", (unsigned long)rd32(v),
                   rd16(v + 4), rd16(v + 6), v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
        break;
    case 0x10:                                                      // size_t (hex)
        if (n >= 8) sb_fmt(b, "0x%016llx", (unsigned long long)rd64(v));
        else if (n >= 4) sb_fmt(b, "0x%08lx", (unsigned long)rd32(v));
        break;
    case 0x11: if (n >= 8) put_filetime(b, rd64(v)); break;
    case 0x12:                                                      // SYSTEMTIME
        if (n >= 16)
            sb_fmt(b, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", rd16(v), rd16(v + 2), rd16(v + 6),
                   rd16(v + 8), rd16(v + 10), rd16(v + 12), rd16(v + 14));
        break;
    case 0x13:                                                      // SID
        if (n >= 8 && (size_t)8 + (size_t)v[1] * 4 <= n) {
            uint64_t auth = 0;
            for (int i = 2; i < 8; i++) auth = (auth << 8) | v[i];
            sb_fmt(b, "S-%u-%llu", v[0], (unsigned long long)auth);
            for (unsigned i = 0; i < v[1]; i++) sb_fmt(b, "-%lu", (unsigned long)rd32(v + 8 + 4 * i));
        }
        break;
    case 0x14: if (n >= 4) sb_fmt(b, "0x%08lx", (unsigned long)rd32(v)); break;
    case 0x15: if (n >= 8) sb_fmt(b, "0x%016llx", (unsigned long long)rd64(v)); break;
    case 0x21:                                                      // embedded binary XML
        if (depth < MAX_DEPTH) render(r, b, v, v + n, NULL, 0, depth + 1);
        break;
    case 0x81: {                                                    // array of UTF-16 strings
        size_t units = n / 2, i = 0;
        int first = 1;
        while (i < units) {
            size_t j = i;
            while (j < units && rd16(v + 2 * j)) j++;
            if (!first) sb_str(b, " ");
            sb_u16(b, v + 2 * i, j - i, 1);
            first = 0;
            i = j + 1;
        }
        break;
    }
    default:
        if (type & 0x80) {                                          // array of fixed-size items
            static const unsigned char sz[0x16] = { 0,0,0,1,1,2,2,4,4,8,8,4,8,4,0,16,8,8,16,0,4,8 };
            uint8_t base = (uint8_t)(type & 0x7F);
            size_t es = base < sizeof sz ? sz[base] : 0;
            for (size_t i = 0; es && i + es <= n; i += es) {
                if (i) sb_str(b, " ");
                put_value(r, b, base, v + i, es, depth);
            }
        } else {
            for (size_t i = 0; i < n; i++) sb_fmt(b, "%02X", v[i]);
        }
        break;
    }
}

// Renders a template definition at chunk offset def with the given values.
static void render_template(rctx *r, sbuf *b, uint32_t def, const subst *sv, unsigned nsv, int depth)
{
    if (def > CHUNK - 24) { r->fail = 1; return; }
    uint32_t size = rd32(r->chunk + def + 20);
    if ((size_t)def + 24 + size > CHUNK) { r->fail = 1; return; }
    render(r, b, r->chunk + def + 24, r->chunk + def + 24 + size, sv, nsv, depth + 1);
}

// Main token loop over [p, end). Returns the number of bytes consumed only
// through r->fail; output goes to b.
static int render(rctx *r, sbuf *b, const unsigned char *p, const unsigned char *end,
                  const subst *sv, unsigned nsv, int depth)
{
    if (depth > MAX_DEPTH) { r->fail = 1; return -1; }
    // Names of open elements for the end tags.
    uint32_t stack[MAX_DEPTH + 2];
    int sp = 0;
    int in_attr = 0;            // inside an attribute's value
    size_t attr_mark = 0;       // output position before " name=\""
    int attr_empty_opt = 0;     // attribute value so far is only empty optional substitutions
    int attr_has_text = 0;
    size_t elem_start = 0;      // output position of the innermost open tag's '<'
    size_t elem_gt = 0;         // ... and just after its '>' (0 = not inside one)
#define NEED(k) do { if ((size_t)(end - p) < (size_t)(k)) { r->fail = 1; return -1; } } while (0)
#define POS(q) ((uint32_t)((q) - r->chunk))
    while (p < end && !r->fail) {
        uint8_t tok = p[0];
        uint8_t base = tok & 0x0F;
        // An attribute value ends at the next attribute or at the element close.
        if (in_attr && (base == 0x06 || base == 0x02 || base == 0x03 || base == 0x01 || base == 0x04 || base == 0x00)) {
            if (attr_empty_opt && !attr_has_text) {
                b->n = attr_mark;                               // drop: empty optional value
                if (b->s) b->s[b->n] = 0;
            } else {
                sb_str(b, "\"");
            }
            in_attr = 0;
        }
        switch (base) {
        case 0x00:                                              // end of fragment
            return 0;
        case 0x01: {                                            // open start element
            NEED(11);
            uint32_t name = rd32(p + 7);
            const unsigned char *q = p + 11;
            if (name == POS(q)) q += name_size(r, name);        // inline name
            if (tok & 0x40) q += 4;                             // attribute list size
            if (q > end) { r->fail = 1; return -1; }
            elem_start = b->n;
            elem_gt = 0;
            sb_str(b, "<");
            put_name(r, b, name);
            if (sp < MAX_DEPTH) stack[sp++] = name; else { r->fail = 1; return -1; }
            p = q;
            break;
        }
        case 0x02:                                              // close start element
            sb_str(b, ">");
            elem_gt = b->n;
            p++;
            break;
        case 0x03:                                              // close empty element
            sb_str(b, "/>");
            if (sp > 0) sp--;
            p++;
            break;
        case 0x04:                                              // end element
            if (sp > 0) {
                sb_str(b, "</");
                put_name(r, b, stack[--sp]);
                sb_str(b, ">");
            }
            p++;
            break;
        case 0x05: {                                            // value text
            NEED(4);
            uint16_t nch = rd16(p + 2);
            NEED(4 + (size_t)nch * 2);
            if (p[1] == 0x01) sb_u16(b, p + 4, nch, 1);
            if (in_attr && nch) attr_has_text = 1;
            p += 4 + (size_t)nch * 2;
            break;
        }
        case 0x06: {                                            // attribute
            NEED(5);
            uint32_t name = rd32(p + 1);
            const unsigned char *q = p + 5;
            if (name == POS(q)) q += name_size(r, name);
            if (q > end) { r->fail = 1; return -1; }
            attr_mark = b->n;
            sb_str(b, " ");
            put_name(r, b, name);
            sb_str(b, "=\"");
            in_attr = 1;
            attr_empty_opt = 0;
            attr_has_text = 0;
            p = q;
            break;
        }
        case 0x07: {                                            // CDATA
            NEED(3);
            uint16_t nch = rd16(p + 1);
            NEED(3 + (size_t)nch * 2);
            sb_str(b, "<![CDATA[");
            sb_u16(b, p + 3, nch, 0);
            sb_str(b, "]]>");
            p += 3 + (size_t)nch * 2;
            break;
        }
        case 0x08:                                              // character reference
            NEED(3);
            sb_fmt(b, "&#%u;", rd16(p + 1));
            if (in_attr) attr_has_text = 1;
            p += 3;
            break;
        case 0x09: {                                            // entity reference
            NEED(5);
            sb_str(b, "&");
            put_name(r, b, rd32(p + 1));
            sb_str(b, ";");
            if (in_attr) attr_has_text = 1;
            uint32_t name = rd32(p + 1);
            p += 5;
            if (name == POS(p)) p += name_size(r, name);
            break;
        }
        case 0x0A: case 0x0B:                                   // processing instructions: skip
            r->fail = 1;
            return -1;
        case 0x0C: {                                            // template instance
            NEED(10);
            uint32_t def = rd32(p + 6);
            const unsigned char *q = p + 10;
            if (def == POS(q)) {                                // definition stored inline
                if ((size_t)(end - q) < 24) { r->fail = 1; return -1; }
                uint32_t dsize = rd32(q + 20);
                if ((size_t)(end - q) < 24 + (size_t)dsize) { r->fail = 1; return -1; }
                q += 24 + dsize;
            }
            if ((size_t)(end - q) < 4) { r->fail = 1; return -1; }
            uint32_t count = rd32(q);
            q += 4;
            if (count > 1024 || (size_t)(end - q) < (size_t)count * 4) { r->fail = 1; return -1; }
            subst *vals = (subst *)calloc(count ? count : 1, sizeof *vals);
            if (vals == NULL) { r->fail = 1; return -1; }
            const unsigned char *data = q + (size_t)count * 4;
            for (uint32_t i = 0; i < count; i++) {
                vals[i].size = rd16(q + 4 * i);
                vals[i].type = q[4 * i + 2];
                if ((size_t)(end - data) < vals[i].size) { free(vals); r->fail = 1; return -1; }
                vals[i].data = data;
                data += vals[i].size;
            }
            render_template(r, b, def, vals, count, depth);
            free(vals);
            p = data;
            break;
        }
        case 0x0D: case 0x0E: {                                 // (optional) substitution
            NEED(4);
            uint16_t id = rd16(p + 1);
            uint8_t vt = p[3];
            (void)vt;
            if (id < nsv && sv != NULL) {
                const subst *s = &sv[id];
                size_t before = b->n;
                if (!in_attr && s->type == 0x81 && sp > 0 && elem_gt != 0 && b->n == elem_gt && !b->oom) {
                    // An array of strings as the content of an element: the
                    // event API writes the ELEMENT once per string
                    // (<Data>a</Data><Data>b</Data>), which is how classic
                    // events carry their insertion strings. Repeat the open
                    // tag, attributes included, for every string after the first.
                    size_t ol = elem_gt - elem_start;
                    char *open = (char *)malloc(ol ? ol : 1);
                    if (open == NULL) { r->fail = 1; return -1; }
                    memcpy(open, b->s + elem_start, ol);
                    size_t units = s->size / 2, i = 0;
                    int first = 1;
                    while (i < units) {
                        size_t j = i;
                        while (j < units && rd16(s->data + 2 * j)) j++;
                        if (!first) {
                            sb_str(b, "</");
                            put_name(r, b, stack[sp - 1]);
                            sb_str(b, ">");
                            sb_put(b, open, ol);
                        }
                        sb_u16(b, s->data + 2 * i, j - i, 1);
                        first = 0;
                        i = j + 1;
                    }
                    free(open);
                } else {
                    put_value(r, b, s->type, s->data, s->size, depth);
                }
                if (in_attr) {
                    if (b->n > before) attr_has_text = 1;
                    else if (base == 0x0E) attr_empty_opt = 1;
                }
            } else if (in_attr && base == 0x0E) {
                attr_empty_opt = 1;
            }
            p += 4;
            break;
        }
        case 0x0F:                                              // fragment header
            NEED(4);
            p += 4;
            break;
        default:
            r->fail = 1;
            return -1;
        }
    }
#undef NEED
#undef POS
    if (in_attr) {
        if (attr_empty_opt && !attr_has_text) { b->n = attr_mark; if (b->s) b->s[b->n] = 0; }
        else sb_str(b, "\"");
    }
    return r->fail ? -1 : 0;
}

int evtx_render(const unsigned char *chunk, size_t off, size_t len, char **out, size_t *outlen)
{
    *out = NULL;
    *outlen = 0;
    if (off > CHUNK || len > CHUNK - off) return -1;
    rctx r = { chunk, 0 };
    sbuf b = { NULL, 0, 0, 0 };
    render(&r, &b, chunk + off, chunk + off + len, NULL, 0, 0);
    if (r.fail || b.oom || b.s == NULL) {
        free(b.s);
        return -1;
    }
    *out = b.s;
    *outlen = b.n;
    return 0;
}

int evtx_open(evtx_file *f, const unsigned char *d, size_t n)
{
    memset(f, 0, sizeof *f);
    if (n < HDR_SIZE || memcmp(d, "ElfFile", 8) != 0) return -1;
    f->d = d;
    f->n = n;
    f->chunks = (unsigned)((n - HDR_SIZE) / CHUNK + ((n - HDR_SIZE) % CHUNK ? 1 : 0));
    f->dirty = (rd32(d + 120) & 1) != 0;
    return 0;
}

unsigned long evtx_records(const evtx_file *f, evtx_cb cb, void *ctx)
{
    unsigned long total = 0;
    for (unsigned c = 0; c < f->chunks; c++) {
        size_t base = HDR_SIZE + (size_t)c * CHUNK;
        if (base + 512 > f->n || memcmp(f->d + base, "ElfChnk", 8) != 0) continue;
        // A truncated last chunk: work on a zero-padded copy so every offset
        // check against CHUNK stays valid.
        const unsigned char *chunk = f->d + base;
        unsigned char *copy = NULL;
        size_t avail = f->n - base;
        if (avail < CHUNK) {
            copy = (unsigned char *)calloc(1, CHUNK);
            if (copy == NULL) break;
            memcpy(copy, chunk, avail);
            chunk = copy;
        }
        uint32_t free_off = rd32(chunk + 48);
        if (free_off < 512 || free_off > CHUNK) free_off = CHUNK;
        size_t off = 512;
        while (off + 28 <= free_off && off + 28 <= (avail < CHUNK ? avail : CHUNK)) {
            if (rd32(chunk + off) != 0x00002a2a) break;
            uint32_t size = rd32(chunk + off + 4);
            if (size < 28 || off + size > CHUNK || off + size > avail) break;
            uint64_t id = rd64(chunk + off + 8);
            uint64_t written = rd64(chunk + off + 16);
            char *xml = NULL;
            size_t xl = 0;
            if (evtx_render(chunk, off + 24, size - 28, &xml, &xl) == 0) {
                cb(id, written, xml, ctx);
                total++;
            }
            free(xml);
            off += size;
        }
        free(copy);
    }
    return total;
}
