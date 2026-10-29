// winspect webcache - WebCacheV01.dat containers
//
// The Containers table lists every container table (Container_<id>) with its
// Name: "History" (visits; Url "Visited: <user>@<url>"), "iedownload"
// (downloads), "Content" (cached files), cookies, DOM storage... Each
// container row has Url, Filename, AccessCount, and FILETIMEs for creation,
// modification, access and expiry. Read through esedb.c; judged by
// browser_reason (artparse.c). Read-only.

#include "webcache.h"
#include "esedb.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int mode, first, only_flagged, all;
    unsigned rows, flagged;
    const char *kind;           // container name of the table being read
    uint64_t container;
} wctx;

static unsigned char *slurp(const char *path, size_t *n)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    unsigned char *d = NULL;
    size_t got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (2LL << 30) &&
            (d = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL) {
        while (got < (size_t)sz.QuadPart) {
            DWORD part = 0;
            if (!ReadFile(h, d + got, (DWORD)((size_t)sz.QuadPart - got), &part, NULL) || part == 0) break;
            got += part;
        }
    }
    CloseHandle(h);
    if (d && got == 0) { free(d); d = NULL; }
    *n = got;
    return d;
}

// UTF-16 column -> UTF-8 (empty when absent or compressed).
static void wtext(const ese_row *r, const char *col, char *out, size_t n)
{
    ese_val v;
    out[0] = 0;
    if (!ese_get(r, col, &v) || v.compressed || v.len < 2) return;
    WCHAR w[4096];
    size_t wn = v.len / 2 < 4095 ? v.len / 2 : 4095;
    memcpy(w, v.data, wn * 2);
    w[wn] = 0;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)n, NULL, NULL);
}

static void row_cb(const ese_row *r, void *vctx)
{
    wctx *c = (wctx *)vctx;
    static char url[8192], file[1024];
    wtext(r, "Url", url, sizeof url);
    wtext(r, "Filename", file, sizeof file);
    if (url[0] == 0) return;
    // History rows: "Visited: user@url" (also ":2023...: user@url" for daily / weekly ones).
    char user[128] = "";
    const char *u = url;
    const char *at = strchr(url, '@');
    const char *colon = strstr(url, ": ");
    if (at && colon && colon < at && (size_t)(at - colon - 2) < sizeof user) {
        memcpy(user, colon + 2, (size_t)(at - colon - 2));
        user[at - colon - 2] = 0;
        u = at + 1;
    }
    int download = _stricmp(c->kind, "iedownload") == 0;
    const char *reason = browser_reason(download, u, download ? file : NULL, 0);
    c->rows++;
    if (reason) c->flagged++;
    if (c->only_flagged && reason == NULL) return;
    char acc[32], mod[32], cre[32];
    filetime_utc_str((uint64_t)ese_int(r, "AccessedTime"), acc, sizeof acc);
    filetime_utc_str((uint64_t)ese_int(r, "ModifiedTime"), mod, sizeof mod);
    filetime_utc_str((uint64_t)ese_int(r, "CreationTime"), cre, sizeof cre);
    long long count = (long long)ese_int(r, "AccessCount"), entry = (long long)ese_int(r, "EntryId");
    if (c->mode == 0) {
        printf("%s %-19s %-11s %4lld  %s%s%s\n", reason ? "[!]" : "   ", acc, c->kind, count, user, user[0] ? " @ " : "", u);
        if (file[0]) printf("        cached as %s\n", file);
        if (reason) printf("        <- %s\n", reason);
    } else if (c->mode == 2) {
        printf("%s,%s,%s,", acc, mod, cre);
        csv_str(c->kind); printf(",%llu,%lld,%lld,", (unsigned long long)c->container, entry, count);
        csv_str(user); putchar(',');
        csv_str(u); putchar(',');
        csv_str(file); putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"accessed\":\"%s\",\"modified\":\"%s\",\"created\":\"%s\",\"container\":", c->first ? "" : ",", acc, mod, cre);
        json_str(c->kind);
        printf(",\"container_id\":%llu,\"entry_id\":%lld,\"access_count\":%lld,\"user\":", (unsigned long long)c->container, entry, count);
        json_str(user);
        fputs(",\"url\":", stdout);      json_str(u);
        fputs(",\"filename\":", stdout); json_str(file);
        printf(",\"file_size\":%lld,\"suspicious\":%s,\"reason\":", (long long)ese_int(r, "FileSize"), reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

typedef struct { uint64_t id; char name[64]; } cinfo;
typedef struct { cinfo v[512]; int n; } clist;

static void cont_cb(const ese_row *r, void *vctx)
{
    clist *l = (clist *)vctx;
    if (l->n >= 512) return;
    cinfo *ci = &l->v[l->n];
    ci->id = (uint64_t)ese_int(r, "ContainerId");
    wtext(r, "Name", ci->name, sizeof ci->name);
    if (ci->name[0]) l->n++;
}

static int one_db(wctx *c, const char *path)
{
    size_t n = 0;
    unsigned char *d = slurp(path, &n);
    if (d == NULL) return -1;
    ese_db db;
    static ese_table t;
    static clist cl;
    cl.n = 0;
    if (ese_open(&db, d, n) != 0 || ese_table_open(&db, "Containers", &t) != 0) { free(d); return -2; }
    ese_rows(&db, &t, cont_cb, &cl);
    for (int i = 0; i < cl.n; i++) {
        const char *nm = cl.v[i].name;
        int wanted = _stricmp(nm, "History") == 0 || _stricmp(nm, "iedownload") == 0 ||
                     (c->all && _stricmp(nm, "Content") == 0);
        if (!wanted) continue;
        char tn[48];
        snprintf(tn, sizeof tn, "Container_%llu", (unsigned long long)cl.v[i].id);
        if (ese_table_open(&db, tn, &t) != 0) continue;
        c->kind = nm;
        c->container = cl.v[i].id;
        ese_rows(&db, &t, row_cb, c);
    }
    free(d);
    return 0;
}

int cmd_webcache(int argc, char **argv)
{
    wctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *file = NULL, *home = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                       c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                   c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)               c.only_flagged = 1;
        else if (strcmp(argv[a], "--all") == 0)                   c.all = 1;
        else if (strcmp(argv[a], "--home") == 0 && a + 1 < argc)  home = argv[++a];
        else if (file == NULL && argv[a][0] != '-')               file = argv[a];
        else {
            fprintf(stderr, "webcache: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    char path[MAX_PATH * 2];
    if (home) {
        snprintf(path, sizeof path, "%s\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat", home);
        file = path;
        if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {   // no WebCache for this user: nothing to show
            if (c.mode == 1) puts("[]");
            else if (c.mode == 2) puts("accessed,modified,created,container,container_id,entry_id,access_count,user,url,filename,reason");
            return 0;
        }
    }
    if (file == NULL) {
        fputs("webcache: give a copy of WebCacheV01.dat (the live one is locked; e.g. esentutl /y\n"
              "          %LOCALAPPDATA%\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat /vss /d C:\\cases\\WebCacheV01.dat)\n", stderr);
        return 1;
    }
    if (c.mode == 0) printf("webcache  %s  (accessed time UTC, access count)\n\n", file);
    else if (c.mode == 2) puts("accessed,modified,created,container,container_id,entry_id,access_count,user,url,filename,reason");
    else putchar('[');
    int r = one_db(&c, file);
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) printf("\n%u entr%s, %u flagged\n", c.rows, c.rows == 1 ? "y" : "ies", c.flagged);
    if (r == -1) { fprintf(stderr, "webcache: cannot read '%s' (locked? copy it first)\n", file); return 1; }
    if (r == -2) { fprintf(stderr, "webcache: '%s' is not a WebCache database\n", file); return 1; }
    return 0;
}
