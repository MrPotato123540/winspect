// winspect strings - printable strings + indicator flagging (static triage)
//
// The first thing an analyst does with an unknown binary is run `strings` on it:
// URLs, IP addresses, registry paths, file paths and command fragments embedded
// in the file are a cheap, honest first look at what it touches. winspect does
// the same, reading the file's bytes and pulling out runs of printable
// characters - both 8-bit (ASCII) and UTF-16LE (the wide strings Windows code is
// full of) - then tagging the ones that match a known indicator shape.
//
// This is pure static reading: the file never runs. The indicator tags are
// shape heuristics (does it look like a URL / IP / registry path), not a verdict.

#include "strings.h"
#include "jsonutil.h"
#include "ioc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define STR_MAX_FILE (256u * 1024u * 1024u)
#define STR_CAP      500000u     // hard cap on how many strings we emit
#define STR_MAXLEN   1024        // longest run we keep (truncate beyond)

// Reads the whole file into a heap buffer; caller frees. 0 on failure.
static int load_file(const char *path, unsigned char **buf, size_t *size)
{
    *buf = NULL;
    *size = 0;
    HANDLE f = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        return 0;
    }
    LARGE_INTEGER sz;
    int ok = 0;
    if (GetFileSizeEx(f, &sz) && sz.QuadPart > 0 && sz.QuadPart <= (LONGLONG)STR_MAX_FILE) {
        unsigned char *p = (unsigned char *)malloc((size_t)sz.QuadPart);
        if (p != NULL) {
            DWORD got = 0;
            if (ReadFile(f, p, (DWORD)sz.QuadPart, &got, NULL) && got == sz.QuadPart) {
                *buf = p; *size = (size_t)sz.QuadPart; ok = 1;
            } else {
                free(p);
            }
        }
    }
    CloseHandle(f);
    return ok;
}

static int printable(unsigned char c)
{
    return c >= 0x20 && c <= 0x7E;
}

// Indicator classification now lives in the portable, unit-tested ioc module
// (inc/ioc.h); see tests/test_util.c.

// Output context for one run of strings so each mode manages its own framing.
struct sctx { int mode; int ioc_only; int first; unsigned count; };
#define STR_TEXT 0
#define STR_JSON 1
#define STR_CSV  2

static void emit(struct sctx *c, size_t off, const char *enc, const char *str)
{
    const char *tag = ioc_classify(str);
    if (c->ioc_only && tag[0] == '\0') {
        return;
    }
    if (c->count >= STR_CAP) {
        return;
    }
    c->count++;
    if (c->mode == STR_TEXT) {
        printf("  0x%08zX  %-5s %-9s %s\n", off, enc, tag[0] ? tag : "-", str);
    } else if (c->mode == STR_CSV) {
        printf("0x%08zX,%s,%s,", off, enc, tag);
        csv_str(str);
        putchar('\n');
    } else {
        printf("%s{\"offset\":\"0x%08zX\",\"encoding\":\"%s\",\"tag\":",
               c->first ? "" : ",", off, enc);
        if (tag[0]) { json_str(tag); } else { fputs("null", stdout); }
        fputs(",\"text\":", stdout);
        json_str(str);
        putchar('}');
        c->first = 0;
    }
}

int cmd_strings(int argc, char **argv)
{
    const char *path = NULL;
    int mode = STR_TEXT, ioc_only = 0;
    unsigned minlen = 4;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = STR_JSON;
        else if (strcmp(argv[a], "--csv") == 0)  mode = STR_CSV;
        else if (strcmp(argv[a], "--ioc") == 0)  ioc_only = 1;
        else if (strcmp(argv[a], "-n") == 0) {
            if (a + 1 >= argc) { fputs("strings: -n needs a length\n", stderr); return 1; }
            minlen = (unsigned)strtoul(argv[++a], NULL, 10);
            if (minlen < 1) { minlen = 1; }
        }
        else if (path == NULL)                   path = argv[a];
        else {
            fprintf(stderr, "strings: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (path == NULL) {
        fputs("usage: winspect strings <path> [-n <minlen>] [--ioc] [--json | --csv]\n", stderr);
        return 1;
    }

    unsigned char *d = NULL;
    size_t n = 0;
    if (!load_file(path, &d, &n)) {
        fprintf(stderr, "strings: cannot read '%s'\n", path);
        return 1;
    }

    struct sctx c;
    c.mode = mode; c.ioc_only = ioc_only; c.first = 1; c.count = 0;

    if (mode == STR_TEXT) {
        printf("strings  %s%s\n\n", path, ioc_only ? "  (indicators only)" : "");
        printf("  %-10s %-5s %-9s %s\n", "offset", "enc", "tag", "text");
    } else if (mode == STR_CSV) {
        puts("offset,encoding,tag,text");
    } else {
        putchar('[');
    }

    char run[STR_MAXLEN];

    // --- ASCII pass -----------------------------------------------------------
    {
        size_t len = 0, start = 0;
        for (size_t i = 0; i <= n; i++) {
            int ch = (i < n) ? d[i] : -1;
            if (ch >= 0 && printable((unsigned char)ch)) {
                if (len == 0) { start = i; }
                if (len < STR_MAXLEN - 1) { run[len++] = (char)ch; }
            } else {
                if (len >= minlen) {
                    run[len] = '\0';
                    emit(&c, start, "ascii", run);
                }
                len = 0;
            }
        }
    }

    // --- UTF-16LE pass --------------------------------------------------------
    // A wide run is printable-ASCII bytes each followed by a 0x00 byte. This
    // catches the wide string literals that pervade Windows binaries.
    {
        size_t len = 0, start = 0;
        for (size_t i = 0; i + 1 < n; i += 2) {
            if (printable(d[i]) && d[i + 1] == 0x00) {
                if (len == 0) { start = i; }
                if (len < STR_MAXLEN - 1) { run[len++] = (char)d[i]; }
            } else {
                if (len >= minlen) {
                    run[len] = '\0';
                    emit(&c, start, "utf16", run);
                }
                len = 0;
            }
        }
        if (len >= minlen) {
            run[len] = '\0';
            emit(&c, start, "utf16", run);
        }
    }

    free(d);

    if (mode == STR_TEXT) {
        printf("\n%u string(s)%s\n", c.count, c.count >= STR_CAP ? " (capped)" : "");
    } else if (mode == STR_JSON) {
        puts("]");
    }
    return 0;
}
