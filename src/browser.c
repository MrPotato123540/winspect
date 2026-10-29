// winspect browser - browser history and downloads
//
// Chromium (Chrome, Edge, Brave):  <User Data>\<profile>\History
//   urls       (url, title, visit_count, last_visit_time)       time: microseconds since 1601
//   downloads  (target_path, start_time, total_bytes, danger_type, tab_url, ...)
//   downloads_url_chains (id, chain_index, url)                  the redirect chain; index 0 = first URL
// Firefox:  <profile>\places.sqlite (+ places.sqlite-wal, where recent pages live)
//   moz_places (url, title, visit_count, last_visit_date)       time: microseconds since 1970
//   moz_annos  (place_id, anno_attribute_id, content, dateAdded) with
//   moz_anno_attributes.name = 'downloads/destinationFileURI'   the saved file of a download
// Columns are found by NAME from each table's CREATE TABLE text, because the
// column order changes between browser versions. Judging: browser_reason
// (artparse.c, unit-tested). Read-only.

#include "browser.h"
#include "sqlite.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t ft;
    const char *browser, *reason;
    char profile[300], url[2048], detail[1024];
    int download, danger;
    long long bytes;
} brow;

typedef struct {
    int mode, first, only_flagged, downloads_only;
    uint64_t since;             // FILETIME lower bound, 0 = none
    unsigned rows, flagged;
    brow *v;                    // collected, printed newest first at the end
    size_t n, cap;
} bctx;

// ---- small helpers -----------------------------------------------------------------

static unsigned char *slurp(const char *path, size_t *n)
{
    WCHAR w[MAX_PATH * 2];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, w, MAX_PATH * 2);
    HANDLE h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    unsigned char *d = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (1LL << 31) &&
            (d = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL) {
        if (!ReadFile(h, d, (DWORD)sz.QuadPart, &got, NULL)) got = 0;
    }
    CloseHandle(h);
    if (d && got == 0) { free(d); d = NULL; }
    *n = got;
    return d;
}

static int col(char names[][64], int n, const char *want)
{
    for (int i = 0; i < n; i++) if (_stricmp(names[i], want) == 0) return i;
    return -1;
}

static void text(const sqlite_val *v, int n, int i, char *out, size_t on)
{
    out[0] = 0;
    if (i < 0 || i >= n || v[i].type != SQ_TEXT) return;
    size_t L = v[i].n < on - 1 ? v[i].n : on - 1;
    memcpy(out, v[i].p, L);
    out[L] = 0;
}

static int64_t num(const sqlite_val *v, int n, int i)
{
    if (i < 0 || i >= n) return 0;
    if (v[i].type == SQ_INT) return v[i].i;
    if (v[i].type == SQ_FLOAT) return (int64_t)v[i].f;
    return 0;
}

// file:///C:/a%20b/c.exe -> C:\a b\c.exe
static void file_uri_to_path(const char *u, char *out, size_t n)
{
    const char *p = u;
    if (_strnicmp(p, "file:///", 8) == 0) p += 8;
    size_t k = 0;
    for (; *p && k + 1 < n; p++) {
        if (*p == '%' && p[1] && p[2]) {
            char hx[3] = { p[1], p[2], 0 };
            out[k++] = (char)strtol(hx, NULL, 16);
            p += 2;
        } else {
            out[k++] = *p == '/' ? '\\' : *p;
        }
    }
    out[k] = 0;
}

static void emit(bctx *c, uint64_t ft, const char *browser, const char *profile, int download,
                 const char *url, const char *detail, long long bytes, int danger)
{
    if (c->since && ft < c->since) return;
    if (c->downloads_only && !download) return;
    const char *reason = browser_reason(download, url, download ? detail : NULL, danger);
    c->rows++;
    if (reason) c->flagged++;
    if (c->only_flagged && reason == NULL) return;
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 256;
        brow *nv = (brow *)realloc(c->v, nc * sizeof *nv);
        if (nv == NULL) return;
        c->v = nv;
        c->cap = nc;
    }
    brow *r = &c->v[c->n++];
    r->ft = ft;
    r->browser = browser;
    r->reason = reason;
    snprintf(r->profile, sizeof r->profile, "%s", profile);
    snprintf(r->url, sizeof r->url, "%s", url);
    snprintf(r->detail, sizeof r->detail, "%s", detail);
    r->download = download;
    r->danger = danger;
    r->bytes = bytes;
}

static int newest_first(const void *a, const void *b)
{
    uint64_t x = ((const brow *)a)->ft, y = ((const brow *)b)->ft;
    return x < y ? 1 : x > y ? -1 : 0;
}

static void print_row(bctx *c, const brow *r)
{
    char when[32];
    filetime_utc_str(r->ft, when, sizeof when);
    const char *kind = r->download ? "download" : "visit";
    if (c->mode == 0) {
        printf("%s %-19s %-8s %-8s %s\n", r->reason ? "[!]" : "   ", when, r->browser, kind, r->url);
        if (r->detail[0]) printf("%42s%s%s\n", "", r->download ? "-> " : "", r->detail);
        if (r->reason) printf("%42s<- %s\n", "", r->reason);
    } else if (c->mode == 2) {
        printf("%s,%s,", when, r->browser);
        csv_str(r->profile); printf(",%s,", kind);
        csv_str(r->url); putchar(',');
        csv_str(r->detail); printf(",%lld,%d,", r->bytes, r->danger);
        csv_str(r->reason ? r->reason : ""); putchar('\n');
    } else {
        printf("%s{\"time\":\"%s\",\"browser\":\"%s\",\"profile\":", c->first ? "" : ",", when, r->browser);
        json_str(r->profile);
        printf(",\"kind\":\"%s\",\"url\":", kind);
        json_str(r->url);
        fputs(r->download ? ",\"saved_to\":" : ",\"title\":", stdout);
        json_str(r->detail);
        if (r->download) printf(",\"bytes\":%lld,\"danger_type\":%d", r->bytes, r->danger);
        printf(",\"suspicious\":%s,\"reason\":", r->reason ? "true" : "false");
        json_str(r->reason ? r->reason : "");
        putchar('}');
        c->first = 0;
    }
}

// ---- Chromium ------------------------------------------------------------------

typedef struct {
    bctx *c;
    const char *browser, *profile;
    char names[64][64];
    int n;
    // downloads_url_chains: first URL of each download id
    char (*chain)[1024];
    int64_t nchain;
} cctx;

static void ch_url(int64_t rowid, const sqlite_val *v, int n, void *vctx)
{
    (void)rowid;
    cctx *x = (cctx *)vctx;
    char url[2048], title[512];
    text(v, n, col(x->names, x->n, "url"), url, sizeof url);
    text(v, n, col(x->names, x->n, "title"), title, sizeof title);
    int64_t t = num(v, n, col(x->names, x->n, "last_visit_time"));
    if (url[0] == 0) return;
    emit(x->c, t > 0 ? (uint64_t)t * 10 : 0, x->browser, x->profile, 0, url, title, 0, 0);
}

static void ch_chain(int64_t rowid, const sqlite_val *v, int n, void *vctx)
{
    (void)rowid;
    cctx *x = (cctx *)vctx;
    int64_t id = num(v, n, col(x->names, x->n, "id"));
    int64_t idx = num(v, n, col(x->names, x->n, "chain_index"));
    if (idx != 0 || id <= 0 || id >= x->nchain) return;
    text(v, n, col(x->names, x->n, "url"), x->chain[id], sizeof x->chain[0]);
}

static void ch_dl(int64_t rowid, const sqlite_val *v, int n, void *vctx)
{
    cctx *x = (cctx *)vctx;
    char target[1024], url[2048] = "";
    text(v, n, col(x->names, x->n, "target_path"), target, sizeof target);
    if (target[0] == 0) text(v, n, col(x->names, x->n, "current_path"), target, sizeof target);
    // id is an INTEGER PRIMARY KEY: its value is the rowid.
    if (rowid > 0 && rowid < x->nchain && x->chain[rowid][0]) snprintf(url, sizeof url, "%s", x->chain[rowid]);
    if (url[0] == 0) text(v, n, col(x->names, x->n, "tab_url"), url, sizeof url);
    int64_t t = num(v, n, col(x->names, x->n, "start_time"));
    int64_t bytes = num(v, n, col(x->names, x->n, "total_bytes"));
    int danger = (int)num(v, n, col(x->names, x->n, "danger_type"));
    emit(x->c, t > 0 ? (uint64_t)t * 10 : 0, x->browser, x->profile, 1, url[0] ? url : "-", target, bytes, danger);
}

static void chromium(bctx *c, const sqlite_db *db, const char *browser, const char *profile)
{
    static cctx x;
    memset(&x, 0, sizeof x);
    x.c = c;
    x.browser = browser;
    x.profile = profile;
    uint32_t r;
    if (!c->downloads_only && (r = sqlite_table_root(db, "urls")) != 0) {
        x.n = sqlite_columns(db, "urls", x.names, 64);
        if (x.n > 0) sqlite_scan(db, r, ch_url, &x);
    }
    x.nchain = 4096;
    x.chain = calloc((size_t)x.nchain, sizeof *x.chain);
    if (x.chain && (r = sqlite_table_root(db, "downloads_url_chains")) != 0) {
        x.n = sqlite_columns(db, "downloads_url_chains", x.names, 64);
        if (x.n > 0) sqlite_scan(db, r, ch_chain, &x);
    }
    if ((r = sqlite_table_root(db, "downloads")) != 0) {
        x.n = sqlite_columns(db, "downloads", x.names, 64);
        if (x.n > 0) sqlite_scan(db, r, ch_dl, &x);
    }
    free(x.chain);
}

// ---- Firefox -----------------------------------------------------------------------

typedef struct {
    bctx *c;
    const char *profile;
    char names[64][64];
    int n;
    int64_t dest_attr;          // moz_anno_attributes id of downloads/destinationFileURI
    char (*urls)[1024];         // moz_places url by id (for downloads)
    int64_t nurls;
} fctx;

static uint64_t unix_us_to_ft(int64_t us) { return us > 0 ? ((uint64_t)us + 11644473600000000ULL) * 10 : 0; }

static void ff_place(int64_t rowid, const sqlite_val *v, int n, void *vctx)
{
    fctx *x = (fctx *)vctx;
    char url[2048], title[512];
    text(v, n, col(x->names, x->n, "url"), url, sizeof url);
    text(v, n, col(x->names, x->n, "title"), title, sizeof title);
    if (rowid > 0 && rowid < x->nurls) snprintf(x->urls[rowid], sizeof x->urls[0], "%s", url);
    int64_t t = num(v, n, col(x->names, x->n, "last_visit_date"));
    if (url[0] && t > 0) emit(x->c, unix_us_to_ft(t), "Firefox", x->profile, 0, url, title, 0, 0);
}

static void ff_attr(int64_t rowid, const sqlite_val *v, int n, void *vctx)
{
    fctx *x = (fctx *)vctx;
    char name[128];
    text(v, n, col(x->names, x->n, "name"), name, sizeof name);
    if (strcmp(name, "downloads/destinationFileURI") == 0) x->dest_attr = rowid;
}

static void ff_anno(int64_t rowid, const sqlite_val *v, int n, void *vctx)
{
    (void)rowid;
    fctx *x = (fctx *)vctx;
    if (num(v, n, col(x->names, x->n, "anno_attribute_id")) != x->dest_attr || x->dest_attr == 0) return;
    char content[2048], path[1024];
    text(v, n, col(x->names, x->n, "content"), content, sizeof content);
    file_uri_to_path(content, path, sizeof path);
    int64_t place = num(v, n, col(x->names, x->n, "place_id"));
    const char *url = place > 0 && place < x->nurls && x->urls[place][0] ? x->urls[place] : "-";
    emit(x->c, unix_us_to_ft(num(v, n, col(x->names, x->n, "dateAdded"))), "Firefox", x->profile, 1, url, path, 0, 0);
}

static void firefox(bctx *c, const sqlite_db *db, const char *profile)
{
    static fctx x;
    memset(&x, 0, sizeof x);
    x.c = c;
    x.profile = profile;
    x.nurls = 65536;
    x.urls = calloc((size_t)x.nurls, sizeof *x.urls);
    if (x.urls == NULL) return;
    uint32_t r;
    // moz_places is always read: downloads need the place URLs (visits are
    // dropped by emit when --downloads is given).
    if ((r = sqlite_table_root(db, "moz_places")) != 0 && (x.n = sqlite_columns(db, "moz_places", x.names, 64)) > 0)
        sqlite_scan(db, r, ff_place, &x);
    if ((r = sqlite_table_root(db, "moz_anno_attributes")) != 0 &&
            (x.n = sqlite_columns(db, "moz_anno_attributes", x.names, 64)) > 0)
        sqlite_scan(db, r, ff_attr, &x);
    if (x.dest_attr && (r = sqlite_table_root(db, "moz_annos")) != 0 &&
            (x.n = sqlite_columns(db, "moz_annos", x.names, 64)) > 0)
        sqlite_scan(db, r, ff_anno, &x);
    free(x.urls);
}

// ---- files and profiles ------------------------------------------------------------

// One database file (+ its -wal); the kind is decided by its tables.
static int one_db(bctx *c, const char *path, const char *browser, const char *profile)
{
    size_t n = 0, wn = 0;
    unsigned char *d = slurp(path, &n);
    if (d == NULL) return -1;
    char walp[MAX_PATH * 2 + 8];
    snprintf(walp, sizeof walp, "%s-wal", path);
    unsigned char *w = slurp(walp, &wn);
    sqlite_db db;
    int rc = 0;
    if (sqlite_open(&db, d, n) != 0) {
        rc = -2;
    } else {
        if (w) sqlite_apply_wal(&db, w, wn);
        if (sqlite_table_root(&db, "moz_places")) firefox(c, &db, profile);
        else if (sqlite_table_root(&db, "urls") || sqlite_table_root(&db, "downloads")) chromium(c, &db, browser, profile);
        else rc = -2;
        sqlite_close(&db);
    }
    free(w);
    free(d);
    return rc;
}

// Every profile of every known browser under one user folder.
static void user_dir(bctx *c, const char *home, const char *user)
{
    static const struct { const char *name, *rel; } chromiums[] = {
        { "Chrome", "AppData\\Local\\Google\\Chrome\\User Data" },
        { "Edge",   "AppData\\Local\\Microsoft\\Edge\\User Data" },
        { "Brave",  "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data" },
    };
    char pat[MAX_PATH * 2], path[MAX_PATH * 2], prof[300];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    for (size_t i = 0; i < sizeof chromiums / sizeof chromiums[0]; i++) {
        snprintf(pat, sizeof pat, "%s\\%s\\*", home, chromiums[i].rel);
        if ((h = FindFirstFileA(pat, &fd)) == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.') continue;
            snprintf(path, sizeof path, "%s\\%s\\%s\\History", home, chromiums[i].rel, fd.cFileName);
            if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) continue;
            snprintf(prof, sizeof prof, "%s\\%s", user, fd.cFileName);
            one_db(c, path, chromiums[i].name, prof);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    snprintf(pat, sizeof pat, "%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*", home);
    if ((h = FindFirstFileA(pat, &fd)) != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.') continue;
            snprintf(path, sizeof path, "%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\%s\\places.sqlite", home, fd.cFileName);
            if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) continue;
            snprintf(prof, sizeof prof, "%s\\%s", user, fd.cFileName);
            one_db(c, path, "Firefox", prof);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
}

int cmd_browser(int argc, char **argv)
{
    bctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *file = NULL, *home_arg = NULL;
    int all = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)            c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)        c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)    c.only_flagged = 1;
        else if (strcmp(argv[a], "--downloads") == 0)  c.downloads_only = 1;
        else if (strcmp(argv[a], "--all-users") == 0)  all = 1;
        else if (strcmp(argv[a], "--home") == 0 && a + 1 < argc) home_arg = argv[++a];
        else if (strcmp(argv[a], "--since") == 0 && a + 1 < argc) {
            long h = strtol(argv[++a], NULL, 10);
            if (h <= 0) { fputs("browser: --since needs a positive number of hours\n", stderr); return 1; }
            FILETIME now;
            GetSystemTimeAsFileTime(&now);
            c.since = (((uint64_t)now.dwHighDateTime << 32) | now.dwLowDateTime) - (uint64_t)h * 36000000000ULL;
        }
        else if (file == NULL && argv[a][0] != '-') file = argv[a];
        else {
            fprintf(stderr, "browser: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (c.mode == 0) {
        puts("browser  (history and downloads, UTC)\n");
    } else if (c.mode == 2) {
        puts("time,browser,profile,kind,url,detail,bytes,danger_type,reason");
    } else {
        putchar('[');
    }
    int rc = 0;
    if (home_arg) {
        // One user folder, e.g. Users\bob of a mounted image.
        const char *nm = strrchr(home_arg, '\\');
        user_dir(&c, home_arg, nm && nm[1] ? nm + 1 : home_arg);
    } else if (file) {
        int r = one_db(&c, file, "Chromium", "-");
        if (r == -1) { fprintf(stderr, "browser: cannot open '%s'\n", file); rc = 1; }
        else if (r == -2) { fprintf(stderr, "browser: '%s' is not a Chromium History or Firefox places.sqlite database\n", file); rc = 1; }
    } else if (all) {
        char users[MAX_PATH] = "C:\\Users";
        DWORD n = GetEnvironmentVariableA("PUBLIC", users, MAX_PATH);
        if (n > 0 && n < MAX_PATH) { char *s = strrchr(users, '\\'); if (s) *s = 0; }
        char pat[MAX_PATH + 4], home[MAX_PATH * 2];
        snprintf(pat, sizeof pat, "%s\\*", users);
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(pat, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.') continue;
                snprintf(home, sizeof home, "%s\\%s", users, fd.cFileName);
                user_dir(&c, home, fd.cFileName);
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
    } else {
        char home[MAX_PATH], user[128] = "";
        DWORD ul = sizeof user;
        GetUserNameA(user, &ul);
        if (GetEnvironmentVariableA("USERPROFILE", home, MAX_PATH) > 0) user_dir(&c, home, user);
    }
    if (c.n > 1) qsort(c.v, c.n, sizeof *c.v, newest_first);
    for (size_t i = 0; i < c.n; i++) print_row(&c, &c.v[i]);
    free(c.v);
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) printf("\n%u row(s), %u flagged\n", c.rows, c.flagged);
    return rc;
}
