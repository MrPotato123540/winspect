// jsonmini - small strict JSON reader (see jsonmini.h)
//
// Recursive descent over a length-bounded buffer: every read checks the end,
// so truncated or hostile input cannot run past it (fuzzed under ASan/UBSan
// in tests/fuzz_parsers.c). Strings are unescaped into fresh allocations.

#include "jsonmini.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define JM_MAX_DEPTH 64

typedef struct { const char *p, *end; int fail; } jp;

static void ws(jp *j)
{
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n')) j->p++;
}

static jm_node *node(jm_type t)
{
    jm_node *n = (jm_node *)calloc(1, sizeof *n);
    if (n) n->type = t;
    return n;
}

static int hex4(jp *j, uint32_t *v)
{
    if (j->end - j->p < 4) return 0;
    *v = 0;
    for (int i = 0; i < 4; i++) {
        char c = j->p[i];
        *v <<= 4;
        if (c >= '0' && c <= '9') *v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') *v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') *v |= (uint32_t)(c - 'A' + 10);
        else return 0;
    }
    j->p += 4;
    return 1;
}

static size_t put_utf8(char *o, uint32_t c)
{
    if (c < 0x80)    { o[0] = (char)c; return 1; }
    if (c < 0x800)   { o[0] = (char)(0xC0 | (c >> 6)); o[1] = (char)(0x80 | (c & 0x3F)); return 2; }
    if (c < 0x10000) { o[0] = (char)(0xE0 | (c >> 12)); o[1] = (char)(0x80 | ((c >> 6) & 0x3F));
                       o[2] = (char)(0x80 | (c & 0x3F)); return 3; }
    o[0] = (char)(0xF0 | (c >> 18)); o[1] = (char)(0x80 | ((c >> 12) & 0x3F));
    o[2] = (char)(0x80 | ((c >> 6) & 0x3F)); o[3] = (char)(0x80 | (c & 0x3F));
    return 4;
}

// At the opening quote. The unescaped text is never longer than the escaped.
static char *string(jp *j)
{
    if (j->p >= j->end || *j->p != '"') { j->fail = 1; return NULL; }
    j->p++;
    const char *q = j->p;
    while (q < j->end && *q != '"') q += (*q == '\\' && q + 1 < j->end) ? 2 : 1;
    if (q >= j->end) { j->fail = 1; return NULL; }
    char *out = (char *)malloc((size_t)(q - j->p) + 1);
    if (out == NULL) { j->fail = 1; return NULL; }
    size_t o = 0;
    while (j->p < j->end && *j->p != '"') {
        unsigned char c = (unsigned char)*j->p++;
        if (c < 0x20) { j->fail = 1; break; }           // raw control character
        if (c != '\\') { out[o++] = (char)c; continue; }
        if (j->p >= j->end) { j->fail = 1; break; }
        char e = *j->p++;
        switch (e) {
        case '"': out[o++] = '"'; break;
        case '\\': out[o++] = '\\'; break;
        case '/': out[o++] = '/'; break;
        case 'b': out[o++] = '\b'; break;
        case 'f': out[o++] = '\f'; break;
        case 'n': out[o++] = '\n'; break;
        case 'r': out[o++] = '\r'; break;
        case 't': out[o++] = '\t'; break;
        case 'u': {
            uint32_t cp;
            if (!hex4(j, &cp)) { j->fail = 1; break; }
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                // A pair needs a low surrogate escape right after. Anything
                // else leaves a lone surrogate ('?'); a following escape that
                // is not a low surrogate is then decoded on its own.
                uint32_t lo;
                const char *save = j->p;
                if (j->end - j->p >= 6 && j->p[0] == '\\' && j->p[1] == 'u') {
                    j->p += 2;
                    if (!hex4(j, &lo)) { j->fail = 1; break; }
                    if (lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else {
                        cp = '?';
                        j->p = save;
                    }
                } else {
                    cp = '?';
                }
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                cp = '?';
            }
            // NUL cannot live inside a C string: everything after it would be
            // lost. It becomes '?', like a lone surrogate.
            if (cp == 0) cp = '?';
            // "\uXXXX" is 6 input bytes for at most 3 output bytes (4 for a pair of 12).
            o += put_utf8(out + o, cp);
            break;
        }
        default: j->fail = 1; break;
        }
        if (j->fail) break;
    }
    out[o] = 0;
    if (j->fail || j->p >= j->end) { free(out); j->fail = 1; return NULL; }
    j->p++;                                              // closing quote
    return out;
}

static jm_node *value(jp *j, int depth);

static jm_node *container(jp *j, int depth, int obj)
{
    jm_node *n = node(obj ? JM_OBJ : JM_ARR), *last = NULL;
    if (n == NULL) { j->fail = 1; return NULL; }
    j->p++;                                              // '{' or '['
    ws(j);
    if (j->p < j->end && *j->p == (obj ? '}' : ']')) { j->p++; return n; }
    for (;;) {
        char *key = NULL;
        if (obj) {
            ws(j);
            key = string(j);
            ws(j);
            if (j->fail || j->p >= j->end || *j->p != ':') { free(key); j->fail = 1; break; }
            j->p++;
        }
        jm_node *v = value(j, depth + 1);
        if (v == NULL) { free(key); j->fail = 1; break; }
        v->key = key;
        if (last) last->next = v; else n->child = v;
        last = v;
        ws(j);
        if (j->p >= j->end) { j->fail = 1; break; }
        if (*j->p == ',') { j->p++; continue; }
        if (*j->p == (obj ? '}' : ']')) { j->p++; return n; }
        j->fail = 1;
        break;
    }
    jm_free(n);
    return NULL;
}

static int lit(jp *j, const char *w)
{
    size_t L = strlen(w);
    if ((size_t)(j->end - j->p) < L || memcmp(j->p, w, L) != 0) return 0;
    j->p += L;
    return 1;
}

static jm_node *value(jp *j, int depth)
{
    if (depth > JM_MAX_DEPTH) { j->fail = 1; return NULL; }
    ws(j);
    if (j->p >= j->end) { j->fail = 1; return NULL; }
    char c = *j->p;
    if (c == '{' || c == '[') return container(j, depth, c == '{');
    if (c == '"') {
        char *s = string(j);
        if (s == NULL) return NULL;
        jm_node *n = node(JM_STR);
        if (n == NULL) { free(s); j->fail = 1; return NULL; }
        n->str = s;
        return n;
    }
    if (lit(j, "true") || lit(j, "false")) {
        jm_node *n = node(JM_BOOL);
        if (n) n->boolean = j->p[-1] == 'e' && j->p[-2] == 'u';
        else j->fail = 1;
        return n;
    }
    if (lit(j, "null")) {
        jm_node *n = node(JM_NULL);
        if (n == NULL) j->fail = 1;
        return n;
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        // Validate the RFC 8259 number grammar, then convert a bounded copy.
        const char *s = j->p, *q = j->p;
        if (q < j->end && *q == '-') q++;
        if (q >= j->end || !(*q >= '0' && *q <= '9')) { j->fail = 1; return NULL; }
        if (*q == '0') q++; else while (q < j->end && *q >= '0' && *q <= '9') q++;
        if (q < j->end && *q == '.') {
            q++;
            if (q >= j->end || !(*q >= '0' && *q <= '9')) { j->fail = 1; return NULL; }
            while (q < j->end && *q >= '0' && *q <= '9') q++;
        }
        if (q < j->end && (*q == 'e' || *q == 'E')) {
            q++;
            if (q < j->end && (*q == '+' || *q == '-')) q++;
            if (q >= j->end || !(*q >= '0' && *q <= '9')) { j->fail = 1; return NULL; }
            while (q < j->end && *q >= '0' && *q <= '9') q++;
        }
        char buf[64];
        size_t L = (size_t)(q - s);
        if (L >= sizeof buf) L = sizeof buf - 1;
        memcpy(buf, s, L);
        buf[L] = 0;
        jm_node *n = node(JM_NUM);
        if (n == NULL) { j->fail = 1; return NULL; }
        n->num = strtod(buf, NULL);
        j->p = q;
        return n;
    }
    j->fail = 1;
    return NULL;
}

jm_node *jm_parse(const char *text, size_t len)
{
    jp j = { text, text + len, 0 };
    jm_node *n = value(&j, 0);
    if (n == NULL) return NULL;
    ws(&j);
    if (j.fail || j.p != j.end) { jm_free(n); return NULL; }
    return n;
}

void jm_free(jm_node *n)
{
    while (n) {
        jm_node *next = n->next;
        jm_free(n->child);
        free(n->key);
        free(n->str);
        free(n);
        n = next;
    }
}

const jm_node *jm_get(const jm_node *obj, const char *key)
{
    if (obj == NULL || obj->type != JM_OBJ) return NULL;
    for (const jm_node *c = obj->child; c; c = c->next)
        if (c->key && strcmp(c->key, key) == 0) return c;
    return NULL;
}

const char *jm_gets(const jm_node *obj, const char *key)
{
    const jm_node *v = jm_get(obj, key);
    return v && v->type == JM_STR ? v->str : NULL;
}
