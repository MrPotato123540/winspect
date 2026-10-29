// winspect pca - Program Compatibility Assistant text files
//
// The PCA service (PcaSvc) keeps small text logs of programs it watched,
// in %SystemRoot%\appcompat\pca. Public write-ups disagree on their encoding
// (ANSI vs UTF-16LE), so it is detected per file: a UTF-16 BOM, or NUL bytes
// in the odd positions of the first bytes, means UTF-16LE; otherwise UTF-8
// when valid, else the ANSI code page. Lines are interpreted by the
// unit-tested pca_parse_line (artparse.c). Read-only.

#include "pca.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int mode, first, only_flagged;
    unsigned rows, flagged;
} pctx;

// Whole file as UTF-8 text (malloc'd), encoding detected as described above.
static char *read_text(const char *path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    unsigned char *d = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (64LL << 20) &&
            (d = (unsigned char *)malloc((size_t)sz.QuadPart + 2)) != NULL) {
        if (!ReadFile(h, d, (DWORD)sz.QuadPart, &got, NULL)) got = 0;
    }
    CloseHandle(h);
    if (d == NULL || got == 0) { free(d); return NULL; }
    int u16 = got >= 2 && d[0] == 0xFF && d[1] == 0xFE;
    if (!u16 && got >= 4) {
        unsigned zeros = 0, pairs = 0;
        for (DWORD i = 1; i < got && i < 512; i += 2, pairs++) if (d[i] == 0) zeros++;
        u16 = pairs && zeros * 2 > pairs;
    }
    char *out = NULL;
    if (u16) {
        const WCHAR *w = (const WCHAR *)(d + ((d[0] == 0xFF && d[1] == 0xFE) ? 2 : 0));
        int wn = (int)((got - (DWORD)((const unsigned char *)w - d)) / 2);
        int need = WideCharToMultiByte(CP_UTF8, 0, w, wn, NULL, 0, NULL, NULL);
        out = (char *)malloc((size_t)need + 1);
        if (out) { WideCharToMultiByte(CP_UTF8, 0, w, wn, out, need, NULL, NULL); out[need] = 0; }
    } else if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)d, (int)got, NULL, 0) > 0) {
        out = (char *)malloc(got + 1);
        if (out) { memcpy(out, d, got); out[got] = 0; }
    } else {
        // ANSI (1252 per one write-up): widen with the legacy code page.
        int wn = MultiByteToWideChar(1252, 0, (const char *)d, (int)got, NULL, 0);
        WCHAR *w = (WCHAR *)malloc(((size_t)wn + 1) * sizeof(WCHAR));
        if (w) {
            MultiByteToWideChar(1252, 0, (const char *)d, (int)got, w, wn);
            int need = WideCharToMultiByte(CP_UTF8, 0, w, wn, NULL, 0, NULL, NULL);
            out = (char *)malloc((size_t)need + 1);
            if (out) { WideCharToMultiByte(CP_UTF8, 0, w, wn, out, need, NULL, NULL); out[need] = 0; }
            free(w);
        }
    }
    free(d);
    return out;
}

static void one_file(pctx *c, const char *dir, const char *name)
{
    char path[MAX_PATH * 2];
    snprintf(path, sizeof path, "%s\\%s", dir, name);
    char *t = read_text(path);
    if (t == NULL) return;
    char *p = t;
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) p += 3;
    while (*p) {
        char *e = strchr(p, '\n');
        if (e) *e = 0;
        size_t L = strlen(p);
        if (L && p[L - 1] == '\r') p[L - 1] = 0;
        pca_rec r;
        if (pca_parse_line(p, &r) == 0) {
            const char *reason = r.kind != PCA_RAW && ioc_user_writable(r.path) ? "ran from a user-writable dir" : NULL;
            const char *kind = r.kind == PCA_LAUNCH ? "launch" : r.kind == PCA_GENERAL ? "general" : "raw";
            c->rows++;
            if (reason) c->flagged++;
            if (!(c->only_flagged && reason == NULL)) {
                if (c->mode == 0) {
                    if (r.kind == PCA_RAW) printf("    %-19s %-7s %s\n", "-", kind, r.raw);
                    else printf("%s %-19s %-7s %s%s%s\n", reason ? "[!]" : "   ", r.time, kind, r.path,
                                r.vendor[0] ? "  | " : "", r.vendor);
                    if (reason) printf("        <- %s\n", reason);
                } else if (c->mode == 2) {
                    printf("%s,%s,", r.time, kind);
                    csv_str(r.path); putchar(',');
                    csv_str(r.status); putchar(',');
                    csv_str(r.description); putchar(',');
                    csv_str(r.vendor); putchar(',');
                    csv_str(r.version); putchar(',');
                    csv_str(r.program_id); putchar(',');
                    csv_str(name); putchar(',');
                    csv_str(r.kind == PCA_RAW ? r.raw : ""); putchar(',');
                    csv_str(reason ? reason : ""); putchar('\n');
                } else {
                    printf("%s{\"time\":\"%s\",\"kind\":\"%s\",\"path\":", c->first ? "" : ",", r.time, kind);
                    json_str(r.path);
                    fputs(",\"run_status\":", stdout);  json_str(r.status);
                    fputs(",\"description\":", stdout); json_str(r.description);
                    fputs(",\"vendor\":", stdout);      json_str(r.vendor);
                    fputs(",\"version\":", stdout);     json_str(r.version);
                    fputs(",\"program_id\":", stdout);  json_str(r.program_id);
                    fputs(",\"file\":", stdout);        json_str(name);
                    fputs(",\"raw\":", stdout);         json_str(r.kind == PCA_RAW ? r.raw : "");
                    printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
                    json_str(reason ? reason : "");
                    putchar('}');
                    c->first = 0;
                }
            }
        }
        if (!e) break;
        p = e + 1;
    }
    free(t);
}

int cmd_pca(int argc, char **argv)
{
    pctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *dir = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)          c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)      c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)  c.only_flagged = 1;
        else if (dir == NULL && argv[a][0] != '-')   dir = argv[a];
        else {
            fprintf(stderr, "pca: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    char def[MAX_PATH];
    if (dir == NULL) {
        UINT n = GetSystemWindowsDirectoryA(def, MAX_PATH);
        if (n == 0 || n >= MAX_PATH - 20) { fputs("pca: cannot resolve the Windows directory\n", stderr); return 1; }
        snprintf(def + n, sizeof def - n, "\\appcompat\\pca");
        dir = def;
    }
    DWORD at = GetFileAttributesA(dir);
    if (at == INVALID_FILE_ATTRIBUTES || !(at & FILE_ATTRIBUTE_DIRECTORY)) {
        if (c.mode == 1) puts("[]");
        fprintf(stderr, "pca: no folder '%s' (Windows 11 22H2 or later keeps these files)\n", dir);
        return 1;
    }
    if (c.mode == 0) {
        printf("pca  %s  (UTC)\n\n", dir);
    } else if (c.mode == 2) {
        puts("time,kind,path,run_status,description,vendor,version,program_id,file,raw,reason");
    } else {
        putchar('[');
    }
    static const char *const files[] = { "PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt" };
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) one_file(&c, dir, files[i]);
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) printf("\n%u record(s), %u flagged\n", c.rows, c.flagged);
    return 0;
}
