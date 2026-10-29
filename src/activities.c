// winspect activities - Windows Timeline (ActivitiesCache.db)
//
// Table Activity, columns found by name (sqlite_columns):
//   AppId          JSON array of {application, platform}: the "x_exe_path" /
//                  "windows_win32" entry is the program, else the first one
//   ActivityType   5 = opened (an app or a document), 6 = app in focus (with
//                  activeDurationSeconds in the payload), others listed as such
//   Payload        JSON: displayText, appDisplayName, description (often the
//                  document path), activeDurationSeconds
//   StartTime / EndTime / LastModifiedTime   seconds since 1970, UTC
// Read-only; the JSON pieces go through jsonmini.

#include "activities.h"
#include "sqlite.h"
#include "jsonmini.h"
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
    char names[64][64];
    int n;
    const char *source;
} actx;

static unsigned char *slurp(const char *path, size_t *n)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
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

static int col(actx *x, const char *want)
{
    for (int i = 0; i < x->n; i++) if (_stricmp(x->names[i], want) == 0) return i;
    return -1;
}

static void text(const sqlite_val *v, int n, int i, char *out, size_t on)
{
    out[0] = 0;
    if (i < 0 || i >= n || (v[i].type != SQ_TEXT && v[i].type != SQ_BLOB)) return;
    size_t L = v[i].n < on - 1 ? v[i].n : on - 1;
    memcpy(out, v[i].p, L);
    out[L] = 0;
}

static int64_t num(const sqlite_val *v, int n, int i)
{
    return i >= 0 && i < n && v[i].type == SQ_INT ? v[i].i : 0;
}

static void unix_str(int64_t t, char *out, size_t n)
{
    if (t <= 0) { snprintf(out, n, "-"); return; }
    filetime_utc_str(((uint64_t)t + 11644473600ULL) * 10000000ULL, out, n);
}

static void row_cb(int64_t rowid, const sqlite_val *v, int n, void *vctx)
{
    (void)rowid;
    actx *x = (actx *)vctx;
    static char appid[8192], payload[16384];
    text(v, n, col(x, "AppId"), appid, sizeof appid);
    text(v, n, col(x, "Payload"), payload, sizeof payload);
    int type = (int)num(v, n, col(x, "ActivityType"));
    char start[32], end[32];
    unix_str(num(v, n, col(x, "StartTime")), start, sizeof start);
    unix_str(num(v, n, col(x, "EndTime")), end, sizeof end);
    // The program: prefer an exe path entry.
    char app[1024] = "";
    jm_node *aj = jm_parse(appid, strlen(appid));
    if (aj && aj->type == JM_ARR) {
        for (const jm_node *e = aj->child; e; e = e->next) {
            const char *a = jm_gets(e, "application"), *pl = jm_gets(e, "platform");
            if (a == NULL) continue;
            if (app[0] == 0) snprintf(app, sizeof app, "%s", a);
            if (pl && (strcmp(pl, "x_exe_path") == 0 || strcmp(pl, "windows_win32") == 0)) {
                snprintf(app, sizeof app, "%s", a);
                break;
            }
        }
    }
    jm_free(aj);
    char shown[1024] = "", appname[256] = "", desc[1024] = "";
    long long secs = -1;
    jm_node *pj = jm_parse(payload, strlen(payload));
    if (pj && pj->type == JM_OBJ) {
        const char *s;
        if ((s = jm_gets(pj, "displayText")) != NULL) snprintf(shown, sizeof shown, "%s", s);
        if ((s = jm_gets(pj, "appDisplayName")) != NULL) snprintf(appname, sizeof appname, "%s", s);
        if ((s = jm_gets(pj, "description")) != NULL) snprintf(desc, sizeof desc, "%s", s);
        const jm_node *d = jm_get(pj, "activeDurationSeconds");
        if (d && d->type == JM_NUM) secs = (long long)d->num;
    }
    jm_free(pj);
    const char *kind = type == 5 ? "opened" : type == 6 ? "in focus" : type == 10 ? "clipboard" :
                       type == 16 ? "copy/paste" : "other";
    const char *reason = ioc_user_writable(app) ? "application in a user-writable dir" : NULL;
    x->rows++;
    if (reason) x->flagged++;
    if (x->only_flagged && reason == NULL) return;
    if (x->mode == 0) {
        printf("%s %-19s %-9s %s\n", reason ? "[!]" : "   ", start, kind, app);
        if (shown[0] || desc[0]) printf("        %s%s%s\n", shown, desc[0] && strcmp(desc, shown) ? "  " : "",
                                        strcmp(desc, shown) ? desc : "");
        if (secs >= 0) printf("        in focus %lld s (until %s)\n", secs, end);
        if (reason) printf("        <- %s\n", reason);
    } else if (x->mode == 2) {
        printf("%s,%s,%s,", start, end, kind);
        csv_str(app); putchar(',');
        csv_str(appname); putchar(',');
        csv_str(shown); putchar(',');
        csv_str(desc); printf(",%lld,", secs);
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"start\":\"%s\",\"end\":\"%s\",\"type\":%d,\"kind\":\"%s\",\"application\":", x->first ? "" : ",",
               start, end, type, kind);
        json_str(app);
        fputs(",\"app_name\":", stdout);    json_str(appname);
        fputs(",\"display_text\":", stdout); json_str(shown);
        fputs(",\"description\":", stdout);  json_str(desc);
        printf(",\"focus_seconds\":%lld,\"suspicious\":%s,\"reason\":", secs, reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        x->first = 0;
    }
}

static int one_db(actx *x, const char *path)
{
    size_t n = 0, wn = 0;
    unsigned char *d = slurp(path, &n);
    if (d == NULL) return -1;
    char walp[MAX_PATH * 2 + 8];
    snprintf(walp, sizeof walp, "%s-wal", path);
    unsigned char *w = slurp(walp, &wn);
    sqlite_db db;
    int rc = -2;
    if (sqlite_open(&db, d, n) == 0) {
        if (w) sqlite_apply_wal(&db, w, wn);
        uint32_t root = sqlite_table_root(&db, "Activity");
        if (root && (x->n = sqlite_columns(&db, "Activity", x->names, 64)) > 0) {
            sqlite_scan(&db, root, row_cb, x);
            rc = 0;
        }
        sqlite_close(&db);
    }
    free(w);
    free(d);
    return rc;
}

static void home_dir(actx *x, const char *home)
{
    char pat[MAX_PATH * 2], path[MAX_PATH * 2];
    snprintf(pat, sizeof pat, "%s\\AppData\\Local\\ConnectedDevicesPlatform\\*", home);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.') continue;
        snprintf(path, sizeof path, "%s\\AppData\\Local\\ConnectedDevicesPlatform\\%s\\ActivitiesCache.db", home, fd.cFileName);
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) one_db(x, path);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int cmd_activities(int argc, char **argv)
{
    static actx x;
    memset(&x, 0, sizeof x);
    x.first = 1;
    const char *file = NULL, *home = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                       x.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                   x.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)               x.only_flagged = 1;
        else if (strcmp(argv[a], "--home") == 0 && a + 1 < argc)  home = argv[++a];
        else if (file == NULL && argv[a][0] != '-')               file = argv[a];
        else {
            fprintf(stderr, "activities: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (x.mode == 0) puts("activities  (Windows Timeline, UTC)\n");
    else if (x.mode == 2) puts("start,end,kind,application,app_name,display_text,description,focus_seconds,reason");
    else putchar('[');
    int rc = 0;
    if (file) {
        int r = one_db(&x, file);
        if (r == -1) { fprintf(stderr, "activities: cannot open '%s'\n", file); rc = 1; }
        else if (r == -2) { fprintf(stderr, "activities: '%s' has no Activity table\n", file); rc = 1; }
    } else if (home) {
        home_dir(&x, home);
    } else {
        char h[MAX_PATH];
        if (GetEnvironmentVariableA("USERPROFILE", h, MAX_PATH) > 0) home_dir(&x, h);
    }
    if (x.mode == 1) puts("]");
    else if (x.mode == 0) printf("\n%u activit%s, %u flagged\n", x.rows, x.rows == 1 ? "y" : "ies", x.flagged);
    return rc;
}
