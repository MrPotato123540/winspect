// winspect hive - offline registry hive browser
//
// The same idea as Registry Explorer / regipy (concept only): open the hive
// FILE and walk its keys yourself, instead of asking the running registry.
// That is the only way to look at another user's NTUSER.DAT, a SYSTEM hive
// from a disk image or a triage collection, or Amcache.hve. The format work
// is done by the portable reader in src/regf.c (verified against real hives);
// this file only prints.
//
// Values are decoded by type: REG_SZ / REG_EXPAND_SZ / REG_LINK as text,
// REG_MULTI_SZ as " | "-joined text, REG_DWORD / REG_QWORD as numbers, other
// types (REG_BINARY, device properties 0xFFFF00xx, ...) as hex (first 64
// bytes, with the length). Read-only.

#include "hive.h"
#include "regf.h"
#include "regsrc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 64

typedef struct {
    regf_hive *h;
    int json, recurse, first;
    unsigned keys, values;
    char path[4096];
} hctx;

static void ft_str(uint64_t t, char *out, size_t n)
{
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = (DWORD)t;
    ft.dwHighDateTime = (DWORD)(t >> 32);
    if (t == 0 || !FileTimeToSystemTime(&ft, &st)) { snprintf(out, n, "-"); return; }
    snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

static const char *type_name(uint32_t t)
{
    static const char *const names[] = { "REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY",
        "REG_DWORD", "REG_DWORD_BE", "REG_LINK", "REG_MULTI_SZ", "REG_RESOURCE_LIST",
        "REG_FULL_RESOURCE_DESCRIPTOR", "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD" };
    if (t < sizeof names / sizeof names[0]) return names[t];
    if ((t & 0xFFFF0000u) == 0xFFFF0000u) return "DEVPROP";
    return "?";
}

// Decoded, printable form of a value's data.
static void decode(const regf_value *v, char *out, size_t n)
{
    out[0] = '\0';
    if (v->data == NULL || v->len == 0) return;
    switch (v->type) {
    case REG_SZ: case REG_EXPAND_SZ: case REG_LINK:
        regsrc_u16(v->data, v->len, out, n);
        return;
    case REG_MULTI_SZ: {
        size_t o = 0;
        for (size_t i = 0; i + 1 < v->len && o + 4 < n; ) {
            size_t j = i;
            while (j + 1 < v->len && (v->data[j] | v->data[j + 1])) j += 2;
            if (j == i) break;                       // empty string = end of list
            char part[1024];
            regsrc_u16(v->data + i, j - i, part, sizeof part);
            int w = snprintf(out + o, n - o, "%s%s", o ? " | " : "", part);
            if (w < 0 || (size_t)w >= n - o) break;
            o += (size_t)w;
            i = j + 2;
        }
        return;
    }
    case REG_DWORD:
        if (v->len >= 4) {
            uint32_t x = (uint32_t)v->data[0] | ((uint32_t)v->data[1] << 8) |
                         ((uint32_t)v->data[2] << 16) | ((uint32_t)v->data[3] << 24);
            snprintf(out, n, "%lu (0x%08lX)", (unsigned long)x, (unsigned long)x);
            return;
        }
        break;
    case REG_QWORD:
        if (v->len >= 8) {
            uint64_t x = 0;
            for (int i = 7; i >= 0; i--) x = (x << 8) | v->data[i];
            snprintf(out, n, "%llu (0x%016llX)", (unsigned long long)x, (unsigned long long)x);
            return;
        }
        break;
    default:
        break;
    }
    size_t o = 0;
    for (size_t i = 0; i < v->len && i < 64 && o + 3 < n; i++) o += (size_t)snprintf(out + o, n - o, "%02x", v->data[i]);
    if (v->len > 64 && o + 4 < n) snprintf(out + o, n - o, "...");
}

static void on_value(const regf_value *v, void *vctx)
{
    hctx *c = (hctx *)vctx;
    char text[4096];
    decode(v, text, sizeof text);
    c->values++;
    if (!c->json) {
        printf("    %-28s %-14s %s\n", v->name[0] ? v->name : "(default)", type_name(v->type), text);
    } else {
        printf("%s{\"name\":", c->first ? "" : ",");
        json_str(v->name);
        printf(",\"type\":%lu,\"type_name\":", (unsigned long)v->type);
        json_str(type_name(v->type));
        printf(",\"size\":%lu,\"data\":", (unsigned long)v->len);
        json_str(text);
        putchar('}');
        c->first = 0;
    }
}

static void show_key(hctx *c, uint32_t key, int depth);

typedef struct { regf_hive *h; int first; } subname;
static void json_name(uint32_t sub, void *vctx)
{
    subname *s = (subname *)vctx;
    regf_key_info ki;
    if (regf_key(s->h, sub, &ki) != 0) return;
    if (!s->first) putchar(',');
    json_str(ki.name);
    s->first = 0;
}

typedef struct { hctx *c; int depth; size_t plen; } subctx;

static void on_subkey(uint32_t sub, void *vctx)
{
    subctx *s = (subctx *)vctx;
    regf_key_info ki;
    if (regf_key(s->c->h, sub, &ki) != 0) return;
    if (!s->c->recurse) {
        if (!s->c->json) printf("    [%s]\n", ki.name);
        return;
    }
    // Extend the path, recurse, restore.
    int w = snprintf(s->c->path + s->plen, sizeof s->c->path - s->plen, "\\%s", ki.name);
    if (w > 0 && (size_t)w < sizeof s->c->path - s->plen) show_key(s->c, sub, s->depth + 1);
    s->c->path[s->plen] = '\0';
}

static void show_key(hctx *c, uint32_t key, int depth)
{
    regf_key_info ki;
    if (depth > MAX_DEPTH || c->keys > 5000000 || regf_key(c->h, key, &ki) != 0) return;
    c->keys++;
    char ts[32];
    ft_str(ki.last_written, ts, sizeof ts);
    if (!c->json) {
        printf("\n%s\n  last write %s, %lu subkey(s), %lu value(s)\n", c->path[0] ? c->path : "\\",
               ts, (unsigned long)ki.subkeys, (unsigned long)ki.values);
    } else {
        printf("%s{\"path\":", c->keys > 1 ? "," : "");
        json_str(c->path[0] ? c->path : "\\");
        fputs(",\"last_write\":", stdout);
        json_str(ts);
        printf(",\"subkey_count\":%lu,\"values\":[", (unsigned long)ki.subkeys);
        c->first = 1;
    }
    regf_values(c->h, key, on_value, c);
    if (c->json) {
        fputs("]", stdout);
        if (!c->recurse) {
            fputs(",\"subkeys\":[", stdout);
            subname sn = { c->h, 1 };
            regf_subkeys(c->h, key, json_name, &sn);
            fputs("]", stdout);
        }
        putchar('}');
    } else if (!c->recurse && ki.subkeys) {
        puts("  subkeys:");
    }
    subctx s = { c, depth, strlen(c->path) };
    if (!c->json || c->recurse) regf_subkeys(c->h, key, on_subkey, &s);
}

int cmd_hive(int argc, char **argv)
{
    const char *file = NULL, *keypath = "";
    hctx c;
    memset(&c, 0, sizeof c);
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)          c.json = 1;
        else if (strcmp(argv[a], "--recurse") == 0)  c.recurse = 1;
        else if (file == NULL)                       file = argv[a];
        else if (keypath[0] == '\0')                 keypath = argv[a];
        else {
            fprintf(stderr, "hive: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (file == NULL) {
        fputs("usage: winspect hive <file> [<key\\path>] [--recurse] [--json]\n", stderr);
        return 1;
    }
    regsrc src;
    char err[512];
    if (regsrc_open_hive(&src, file, err, sizeof err) != 0) {
        fprintf(stderr, "hive: %s\n", err);
        return 1;
    }
    c.h = &src.h;
    uint32_t key;
    if (regf_find(&src.h, keypath, &key) != 0) {
        fprintf(stderr, "hive: key '%s' not found\n", keypath);
        regsrc_close(&src);
        return 1;
    }
    snprintf(c.path, sizeof c.path, "%s%s", keypath[0] && keypath[0] != '\\' ? "\\" : "", keypath);
    while (strlen(c.path) > 1 && c.path[strlen(c.path) - 1] == '\\') c.path[strlen(c.path) - 1] = '\0';
    if (strcmp(c.path, "\\") == 0) c.path[0] = '\0';

    char ts[32];
    ft_str(src.h.last_written, ts, sizeof ts);
    int dirty = regsrc_dirty(&src);
    if (!c.json) {
        printf("hive  %s\n", file);
        printf("  format %lu.%lu, last written %s, checksum %s, original path %s\n",
               (unsigned long)src.h.major, (unsigned long)src.h.minor, ts,
               src.h.checksum_ok ? "ok" : "MISMATCH", src.h.file_name[0] ? src.h.file_name : "-");
        if (dirty)
            printf("  [!] dirty: sequence %lu != %lu - changes in .LOG1/.LOG2 are NOT applied\n",
                   (unsigned long)src.h.seq1, (unsigned long)src.h.seq2);
    } else {
        fputs("{\"file\":", stdout);
        json_str(file);
        printf(",\"format\":\"%lu.%lu\",\"last_written\":", (unsigned long)src.h.major, (unsigned long)src.h.minor);
        json_str(ts);
        printf(",\"checksum_ok\":%s,\"dirty\":%s,\"original_path\":", src.h.checksum_ok ? "true" : "false",
               dirty ? "true" : "false");
        json_str(src.h.file_name);
        fputs(",\"keys\":[", stdout);
    }
    show_key(&c, key, 0);
    if (c.json) {
        puts("]}");
    } else {
        printf("\n%u key(s), %u value(s) shown\n", c.keys, c.values);
    }
    regsrc_close(&src);
    return 0;
}
