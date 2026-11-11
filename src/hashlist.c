// Known-hash list (see hashlist.h). Portable C.

#include "hashlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int by_hex(const void *a, const void *b)
{
    return strcmp(((const hl_entry *)a)->hex, ((const hl_entry *)b)->hex);
}

long hashlist_parse(char *text, hashlist *l)
{
    l->v = NULL;
    l->n = 0;
    size_t cap = 0;
    char *p = text;
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) p += 3;
    while (*p) {
        char *e = strchr(p, '\n');
        if (e) *e = '\0';
        char *s = p;
        while (*s == ' ' || *s == '\t' || *s == '"') s++;
        size_t h = 0;
        while (hexval(s[h])) h++;
        char after = s[h];
        if ((h == 32 || h == 40 || h == 64) &&
                (after == '\0' || after == ' ' || after == '\t' || after == ',' || after == '\r' || after == '"' || after == ';')) {
            if (l->n == cap) {
                size_t nc = cap ? cap * 2 : 256;
                hl_entry *nv = (hl_entry *)realloc(l->v, nc * sizeof *nv);
                if (nv == NULL) { hashlist_free(l); return -1; }
                l->v = nv;
                cap = nc;
            }
            hl_entry *en = &l->v[l->n++];
            for (size_t i = 0; i < h; i++) en->hex[i] = (char)(s[i] >= 'A' && s[i] <= 'F' ? s[i] + 32 : s[i]);
            en->hex[h] = '\0';
            // Label: what follows the separator, up to a comma / line end.
            char *t = s + h;
            while (*t == ' ' || *t == '\t' || *t == ',' || *t == ';' || *t == '"' || *t == '*') t++;
            size_t k = 0;
            while (t[k] && t[k] != '\r' && t[k] != ',' && t[k] != '"' && k + 1 < sizeof en->label) { en->label[k] = t[k]; k++; }
            while (k && (en->label[k - 1] == ' ' || en->label[k - 1] == '\t')) k--;
            en->label[k] = '\0';
        }
        if (!e) break;
        p = e + 1;
    }
    if (l->n > 1) qsort(l->v, l->n, sizeof *l->v, by_hex);
    return (long)l->n;
}

void hashlist_free(hashlist *l)
{
    free(l->v);
    l->v = NULL;
    l->n = 0;
}

const hl_entry *hashlist_find(const hashlist *l, const char *hex)
{
    char key[65];
    size_t n = strlen(hex);
    if (n >= sizeof key || l->n == 0) return NULL;
    for (size_t i = 0; i <= n; i++) key[i] = (char)(hex[i] >= 'A' && hex[i] <= 'F' ? hex[i] + 32 : hex[i]);
    size_t lo = 0, hi = l->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(l->v[mid].hex, key);
        if (c == 0) return &l->v[mid];
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return NULL;
}
