// winspect setupapi - SetupAPI device/driver install logs
//
// The text format is parsed by the unit-tested sa_next (artparse.c). This
// file finds the logs, converts the local section start times to UTC and
// prints the rows. Read-only.

#include "setupapi.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"
#include "textfile.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int mode, first, all, only_flagged;
    int tz;                     // 0 none, 1 this machine's zone, 2 fixed offset
    int offset_min;             // minutes east of UTC (tz == 2)
    const char *find;
    unsigned rows, flagged;
} sctx;

static int ci_contains(const char *h, const char *n)
{
    if (n == NULL || *n == 0) return 1;
    for (; *h; h++) {
        size_t i = 0;
        for (; n[i]; i++) {
            char a = h[i], b = n[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
        }
        if (n[i] == 0) return 1;
    }
    return 0;
}

// "+03:00", "-05:30", "+3" -> minutes east of UTC; 0 on success.
static int parse_offset(const char *s, int *out)
{
    int sign = 1;
    if (*s == '+') s++;
    else if (*s == '-') { sign = -1; s++; }
    else return -1;
    int h = 0, m = 0, d = 0;
    while (*s >= '0' && *s <= '9' && d < 2) { h = h * 10 + (*s++ - '0'); d++; }
    if (d == 0) return -1;
    if (*s == ':') {
        s++;
        if (!(s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9')) return -1;
        m = (s[0] - '0') * 10 + (s[1] - '0');
        s += 2;
    }
    if (*s || h > 14 || m > 59) return -1;
    *out = sign * (h * 60 + m);
    return 0;
}

// Local "YYYY-MM-DD hh:mm:ss[.fff]" -> UTC "YYYY-MM-DD hh:mm:ss" ("" if not possible).
static void to_utc(const sctx *c, const char *local, char out[24])
{
    out[0] = 0;
    if (c->tz == 0 || strlen(local) < 19) return;
    SYSTEMTIME lt, ut;
    memset(&lt, 0, sizeof lt);
    if (sscanf(local, "%4hu-%2hu-%2hu %2hu:%2hu:%2hu", &lt.wYear, &lt.wMonth, &lt.wDay, &lt.wHour, &lt.wMinute,
               &lt.wSecond) != 6)
        return;
    if (c->tz == 1) {
        if (!TzSpecificLocalTimeToSystemTime(NULL, &lt, &ut)) return;
    } else {
        FILETIME ft;
        if (!SystemTimeToFileTime(&lt, &ft)) return;
        ULARGE_INTEGER u;
        u.LowPart = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
        u.QuadPart -= (ULONGLONG)((LONGLONG)c->offset_min * 600000000LL);
        ft.dwLowDateTime = u.LowPart;
        ft.dwHighDateTime = u.HighPart;
        if (!FileTimeToSystemTime(&ft, &ut)) return;
    }
    snprintf(out, 24, "%04u-%02u-%02u %02u:%02u:%02u", ut.wYear, ut.wMonth, ut.wDay, ut.wHour, ut.wMinute, ut.wSecond);
}

// A driver package taken from a folder any user can write to.
static const char *flag_reason(const sa_sec *s)
{
    int pkg = strstr(s->title, "Import Driver Package") != NULL || strstr(s->title, "SetupCopyOEMInf") != NULL ||
              strstr(s->title, "DiInstallDriver") != NULL;
    if (pkg && s->target[0] && ioc_user_writable(s->target)) return "driver package installed from a user-writable dir";
    return NULL;
}

static void one_file(sctx *c, const char *path, const char *name)
{
    char *t = read_text_file(path);
    if (t == NULL) {
        fprintf(stderr, "setupapi: cannot read '%s'\n", path);
        return;
    }
    sa_iter it;
    static sa_sec s;
    sa_init(&it, t);
    while (sa_next(&it, &s)) {
        if (!c->all && s.target[0] == 0) continue;
        if (c->find && !ci_contains(s.title, c->find) && !ci_contains(s.target, c->find) && !ci_contains(s.signer, c->find))
            continue;
        const char *reason = flag_reason(&s);
        const char *kind = sa_device_kind(s.target);
        char utc[24];
        to_utc(c, s.start, utc);
        c->rows++;
        if (reason) c->flagged++;
        if (c->only_flagged && reason == NULL) continue;
        if (c->mode == 0) {
            printf("%s %-23s %s%s%s\n", reason ? "[!]" : "   ", s.start[0] ? s.start : "-", s.title,
                   s.target[0] ? " - " : "", s.target);
            printf("        end %s  status %s%s%s", s.end[0] ? s.end : "-", s.status[0] ? s.status : "(not logged)",
                   kind ? "  | " : "", kind ? kind : "");
            if (s.signer[0]) printf("  | signer %s", s.signer);
            if (s.errors || s.warnings) printf("  | %u error(s), %u warning(s)", s.errors, s.warnings);
            putchar('\n');
            if (utc[0]) printf("        UTC %s\n", utc);
            if (reason) printf("        <- %s\n", reason);
        } else if (c->mode == 2) {
            printf("%s,%s,%s,", s.start, utc, s.end);
            csv_str(s.title); putchar(',');
            csv_str(s.target); putchar(',');
            csv_str(kind ? kind : ""); putchar(',');
            csv_str(s.status); putchar(',');
            csv_str(s.signer); putchar(',');
            printf("%u,%u,%s,", s.errors, s.warnings, s.boot);
            csv_str(name); putchar(',');
            csv_str(reason ? reason : ""); putchar('\n');
        } else {
            printf("%s{\"start\":\"%s\",\"time_utc\":\"%s\",\"end\":\"%s\",\"title\":", c->first ? "" : ",", s.start, utc, s.end);
            json_str(s.title);
            fputs(",\"target\":", stdout);      json_str(s.target);
            fputs(",\"device_kind\":", stdout); json_str(kind ? kind : "");
            fputs(",\"status\":", stdout);      json_str(s.status);
            fputs(",\"signer\":", stdout);      json_str(s.signer);
            printf(",\"errors\":%u,\"warnings\":%u,\"boot_session\":\"%s\",\"file\":", s.errors, s.warnings, s.boot);
            json_str(name);
            printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
            json_str(reason ? reason : "");
            putchar('}');
            c->first = 0;
        }
    }
    free(t);
}

static int cmp_name(const void *a, const void *b)
{
    return _stricmp(*(char *const *)a, *(char *const *)b);
}

int cmd_setupapi(int argc, char **argv)
{
    sctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *src = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)          c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)      c.mode = 2;
        else if (strcmp(argv[a], "--all") == 0)      c.all = 1;
        else if (strcmp(argv[a], "--flagged") == 0)  c.only_flagged = 1;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc) c.find = argv[++a];
        else if (strcmp(argv[a], "--utc-offset") == 0 && a + 1 < argc) {
            if (parse_offset(argv[++a], &c.offset_min) != 0) {
                fprintf(stderr, "setupapi: --utc-offset takes +hh:mm or -hh:mm, not '%s'\n", argv[a]);
                return 1;
            }
            c.tz = 2;
        }
        else if (src == NULL && argv[a][0] != '-')   src = argv[a];
        else {
            fprintf(stderr, "setupapi: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    char def[MAX_PATH];
    if (src == NULL) {
        UINT n = GetSystemWindowsDirectoryA(def, MAX_PATH);
        if (n == 0 || n >= MAX_PATH - 8) { fputs("setupapi: cannot resolve the Windows directory\n", stderr); return 1; }
        snprintf(def + n, sizeof def - n, "\\INF");
        src = def;
        if (c.tz == 0) c.tz = 1;            // live logs: this machine's zone
    }
    DWORD at = GetFileAttributesA(src);
    if (at == INVALID_FILE_ATTRIBUTES) {
        if (c.mode == 1) puts("[]");
        fprintf(stderr, "setupapi: no file or folder '%s'\n", src);
        return 1;
    }
    char *names[256];
    int nn = 0;
    char dir[MAX_PATH * 2];
    if (at & FILE_ATTRIBUTE_DIRECTORY) {
        snprintf(dir, sizeof dir, "%s", src);
        char pat[MAX_PATH * 2 + 16];
        snprintf(pat, sizeof pat, "%s\\setupapi*.log", src);
        WIN32_FIND_DATAA fd;
        HANDLE fh = FindFirstFileA(pat, &fd);
        if (fh != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && nn < 256) names[nn++] = _strdup(fd.cFileName);
            } while (FindNextFileA(fh, &fd));
            FindClose(fh);
        }
        if (nn == 0) {
            if (c.mode == 1) puts("[]");
            fprintf(stderr, "setupapi: no setupapi*.log in '%s'\n", src);
            return 1;
        }
        qsort(names, (size_t)nn, sizeof names[0], cmp_name);
    } else {
        const char *sl = strrchr(src, '\\');
        snprintf(dir, sizeof dir, "%.*s", sl ? (int)(sl - src) : 1, sl ? src : ".");
        names[nn++] = _strdup(sl ? sl + 1 : src);
    }
    if (c.mode == 0) {
        printf("setupapi  %s  (times as logged: local%s)\n\n", src,
               c.tz == 1 ? "; UTC from this machine's time zone" : c.tz == 2 ? "; UTC from --utc-offset" : "");
    } else if (c.mode == 2) {
        puts("start,time_utc,end,title,target,device_kind,status,signer,errors,warnings,boot_session,file,reason");
    } else {
        putchar('[');
    }
    for (int i = 0; i < nn; i++) {
        char path[MAX_PATH * 3];
        if (names[i] == NULL) continue;
        snprintf(path, sizeof path, "%s\\%s", dir, names[i]);
        one_file(&c, path, names[i]);
        free(names[i]);
    }
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) printf("\n%u section(s), %u flagged\n", c.rows, c.flagged);
    return 0;
}
