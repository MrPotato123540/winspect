// winspect srum - SRUM network / application usage
//
// Tables (named by GUID) in SRUDB.dat:
//   {973F5D5C-1D90-4944-BE8E-24B94231A174}  network usage: TimeStamp, AppId,
//        UserId, InterfaceLuid, BytesSent, BytesRecvd
//   {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}  application resource usage:
//        TimeStamp, AppId, UserId, Foreground/BackgroundCycleTime, ...BytesRead/Written
//   {DD6636C4-8929-4683-974E-22C046A43763}  network connectivity: TimeStamp,
//        AppId, UserId, InterfaceLuid, ConnectedTime (s), ConnectStartTime (FILETIME)
//   SruDbIdMapTable   IdIndex -> IdBlob: UTF-16 program path / service name /
//        app id (IdType 0, 1, 2) or a binary SID (IdType 3)
// TimeStamp is an OLE automation date (days since 1899-12-30, UTC).
// Read through esedb.c; checked against plaso's SRUDB.dat test values.

#include "srum.h"
#include "esedb.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define T_NET  "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
#define T_APP  "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
#define T_CONN "{DD6636C4-8929-4683-974E-22C046A43763}"

typedef struct { char *s; } idname;

typedef struct {
    int mode, first, only_flagged, view;    // view: 0 network, 1 apps, 2 connectivity, 3 summary
    const char *find;
    idname *ids;
    size_t nids;
    unsigned rows, flagged;
    // --summary accumulation
    struct sumrow { int64_t app; uint64_t sent, recv; unsigned hours; } *sum;
    size_t nsum, capsum;
} sctx;

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

static void ole_str(double ole, char *out, size_t n)
{
    if (ole <= 0) { snprintf(out, n, "-"); return; }
    // days since 1899-12-30 -> FILETIME (109205 days from 1601-01-01). An OLE
    // date is a double: 13:33:00 comes back as 13:32:59.999997, so round to
    // the millisecond (its meaningful precision) before printing seconds.
    uint64_t ms = (uint64_t)((ole + 109205.0) * 86400000.0 + 0.5);
    uint64_t ft = ms * 10000ULL;
    filetime_utc_str(ft, out, n);
}

static void map_cb(const ese_row *r, void *vctx)
{
    sctx *c = (sctx *)vctx;
    int64_t idx = ese_int(r, "IdIndex"), type = ese_int(r, "IdType");
    ese_val v;
    if (idx <= 0 || idx > 10000000 || !ese_get(r, "IdBlob", &v) || v.compressed) return;
    if ((size_t)idx >= c->nids) {
        size_t nn = (size_t)idx * 2 + 16;
        idname *ni = (idname *)realloc(c->ids, nn * sizeof *ni);
        if (ni == NULL) return;
        memset(ni + c->nids, 0, (nn - c->nids) * sizeof *ni);
        c->ids = ni;
        c->nids = nn;
    }
    char buf[1024] = "";
    if (type == 3 && v.len >= 8 && (size_t)8 + (size_t)v.data[1] * 4 <= v.len) {      // SID
        uint64_t auth = 0;
        for (int i = 2; i < 8; i++) auth = (auth << 8) | v.data[i];
        size_t o = (size_t)snprintf(buf, sizeof buf, "S-%u-%llu", v.data[0], (unsigned long long)auth);
        for (unsigned i = 0; i < v.data[1] && o < sizeof buf; i++) {
            const unsigned char *s = v.data + 8 + 4 * i;
            o += (size_t)snprintf(buf + o, sizeof buf - o, "-%lu",
                                  (unsigned long)(s[0] | (s[1] << 8) | (s[2] << 16) | ((unsigned long)s[3] << 24)));
        }
    } else {                                            // UTF-16 name
        WCHAR w[512];
        size_t wn = v.len / 2 < 511 ? v.len / 2 : 511;
        memcpy(w, v.data, wn * 2);
        w[wn] = 0;
        WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, sizeof buf, NULL, NULL);
    }
    free(c->ids[idx].s);
    c->ids[idx].s = _strdup(buf);
}

static const char *idstr(sctx *c, int64_t id, char *tmp, size_t n)
{
    if (id > 0 && (size_t)id < c->nids && c->ids[id].s) return c->ids[id].s;
    snprintf(tmp, n, "#%lld", (long long)id);
    return tmp;
}

static int ci_contains(const char *h, const char *n)
{
    size_t L = strlen(n);
    for (; *h; h++) if (_strnicmp(h, n, L) == 0) return 1;
    return 0;
}

static void net_cb(const ese_row *r, void *vctx)
{
    sctx *c = (sctx *)vctx;
    char t1[24], t2[24], when[32];
    int64_t appid = ese_int(r, "AppId");
    const char *app = idstr(c, appid, t1, sizeof t1);
    const char *user = idstr(c, ese_int(r, "UserId"), t2, sizeof t2);
    if (c->find && !ci_contains(app, c->find)) return;
    uint64_t sent = (uint64_t)ese_int(r, "BytesSent"), recv = (uint64_t)ese_int(r, "BytesRecvd");
    if (c->view == 3) {
        size_t i;
        for (i = 0; i < c->nsum && c->sum[i].app != appid; i++) ;
        if (i == c->nsum) {
            if (c->nsum == c->capsum) {
                size_t nc = c->capsum ? c->capsum * 2 : 256;
                struct sumrow *ns = (struct sumrow *)realloc(c->sum, nc * sizeof *ns);
                if (ns == NULL) return;
                c->sum = ns;
                c->capsum = nc;
            }
            c->sum[c->nsum++] = (struct sumrow){ appid, 0, 0, 0 };
        }
        c->sum[i].sent += sent;
        c->sum[i].recv += recv;
        c->sum[i].hours++;
        return;
    }
    const char *reason = sent > 0 && ioc_user_writable(app) ? "program in a user-writable dir sent data" : NULL;
    c->rows++;
    if (reason) c->flagged++;
    if (c->only_flagged && reason == NULL) return;
    ole_str(ese_double(r, "TimeStamp"), when, sizeof when);
    long long luid = (long long)ese_int(r, "InterfaceLuid");
    if (c->mode == 0) {
        printf("%s %-19s %12llu %12llu  %-14s %s\n", reason ? "[!]" : "   ", when, (unsigned long long)sent,
               (unsigned long long)recv, user, app);
        if (reason) printf("        <- %s\n", reason);
    } else if (c->mode == 2) {
        printf("%s,", when); csv_str(app); putchar(','); csv_str(user);
        printf(",%llu,%llu,%lld,", (unsigned long long)sent, (unsigned long long)recv, luid);
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"time\":\"%s\",\"id\":%lld,\"application\":", c->first ? "" : ",", when, (long long)ese_int(r, "AutoIncId"));
        json_str(app);
        fputs(",\"user\":", stdout); json_str(user);
        printf(",\"bytes_sent\":%llu,\"bytes_received\":%llu,\"interface_luid\":%lld,\"suspicious\":%s,\"reason\":",
               (unsigned long long)sent, (unsigned long long)recv, luid, reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void app_cb(const ese_row *r, void *vctx)
{
    sctx *c = (sctx *)vctx;
    char t1[24], t2[24], when[32];
    const char *app = idstr(c, ese_int(r, "AppId"), t1, sizeof t1);
    const char *user = idstr(c, ese_int(r, "UserId"), t2, sizeof t2);
    if (c->find && !ci_contains(app, c->find)) return;
    const char *reason = ioc_user_writable(app) ? "program in a user-writable dir" : NULL;
    c->rows++;
    if (reason) c->flagged++;
    if (c->only_flagged && reason == NULL) return;
    ole_str(ese_double(r, "TimeStamp"), when, sizeof when);
    long long fgc = (long long)ese_int(r, "ForegroundCycleTime"), bgc = (long long)ese_int(r, "BackgroundCycleTime");
    long long fbw = (long long)ese_int(r, "ForegroundBytesWritten"), bbw = (long long)ese_int(r, "BackgroundBytesWritten");
    if (c->mode == 0) {
        printf("%s %-19s fg %14lld bg %14lld cycles  written %12lld  %-14s %s\n", reason ? "[!]" : "   ", when,
               fgc, bgc, fbw + bbw, user, app);
    } else if (c->mode == 2) {
        printf("%s,", when); csv_str(app); putchar(','); csv_str(user);
        printf(",%lld,%lld,%lld,", fgc, bgc, fbw + bbw);
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"time\":\"%s\",\"id\":%lld,\"application\":", c->first ? "" : ",", when, (long long)ese_int(r, "AutoIncId"));
        json_str(app);
        fputs(",\"user\":", stdout); json_str(user);
        printf(",\"foreground_cycles\":%lld,\"background_cycles\":%lld,\"bytes_written\":%lld,\"suspicious\":%s,\"reason\":",
               fgc, bgc, fbw + bbw, reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void conn_cb(const ese_row *r, void *vctx)
{
    sctx *c = (sctx *)vctx;
    char t1[24], t2[24], when[32], start[32];
    const char *app = idstr(c, ese_int(r, "AppId"), t1, sizeof t1);
    const char *user = idstr(c, ese_int(r, "UserId"), t2, sizeof t2);
    if (c->find && !ci_contains(app, c->find)) return;
    c->rows++;
    if (c->only_flagged) return;
    ole_str(ese_double(r, "TimeStamp"), when, sizeof when);
    filetime_utc_str((uint64_t)ese_int(r, "ConnectStartTime"), start, sizeof start);
    long long secs = (long long)ese_int(r, "ConnectedTime"), luid = (long long)ese_int(r, "InterfaceLuid");
    if (c->mode == 0) {
        printf("    %-19s connected since %s for %lld s  interface %lld  %s %s\n", when, start, secs, luid, user, app);
    } else if (c->mode == 2) {
        printf("%s,%s,%lld,%lld,", when, start, secs, luid); csv_str(app); putchar(','); csv_str(user); putchar('\n');
    } else {
        printf("%s{\"time\":\"%s\",\"id\":%lld,\"connect_start\":\"%s\",\"connected_seconds\":%lld,\"interface_luid\":%lld,\"application\":",
               c->first ? "" : ",", when, (long long)ese_int(r, "AutoIncId"), start, secs, luid);
        json_str(app);
        fputs(",\"user\":", stdout); json_str(user);
        putchar('}');
        c->first = 0;
    }
}

static int by_sent(const void *a, const void *b)
{
    uint64_t x = ((const struct sumrow *)a)->sent, y = ((const struct sumrow *)b)->sent;
    return x < y ? 1 : x > y ? -1 : 0;
}

int cmd_srum(int argc, char **argv)
{
    static sctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *file = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                       c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                   c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)               c.only_flagged = 1;
        else if (strcmp(argv[a], "--network") == 0)               c.view = 0;
        else if (strcmp(argv[a], "--apps") == 0)                  c.view = 1;
        else if (strcmp(argv[a], "--connectivity") == 0)          c.view = 2;
        else if (strcmp(argv[a], "--summary") == 0)               c.view = 3;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc)  c.find = argv[++a];
        else if (file == NULL && argv[a][0] != '-')               file = argv[a];
        else {
            fprintf(stderr, "srum: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (file == NULL) {
        fputs("srum: give a copy of SRUDB.dat (the live %SystemRoot%\\System32\\sru\\SRUDB.dat is locked;\n"
              "      e.g. esentutl /y C:\\Windows\\System32\\sru\\SRUDB.dat /vss /d C:\\cases\\SRUDB.dat)\n", stderr);
        return 1;
    }
    size_t n = 0;
    unsigned char *d = slurp(file, &n);
    ese_db db;
    if (d == NULL || ese_open(&db, d, n) != 0) {
        fprintf(stderr, "srum: '%s' is not readable as an ESE database\n", file);
        free(d);
        return 1;
    }
    static ese_table t;
    if (ese_table_open(&db, "SruDbIdMapTable", &t) == 0) ese_rows(&db, &t, map_cb, &c);
    const char *tn = c.view == 1 ? T_APP : c.view == 2 ? T_CONN : T_NET;
    if (ese_table_open(&db, tn, &t) != 0) {
        fprintf(stderr, "srum: table %s not found (not a SRUM database?)\n", tn);
        free(d);
        return 1;
    }
    if (c.mode == 0) {
        printf("srum  %s  (%s, UTC)\n\n", file, c.view == 1 ? "application resource usage" : c.view == 2 ? "network connectivity" :
               c.view == 3 ? "network bytes per application, largest upload first" : "network usage per hour");
        if (c.view == 0) printf("    %-19s %12s %12s  %-14s %s\n", "hour", "sent", "received", "user", "application");
    } else if (c.mode == 2) {
        puts(c.view == 1 ? "time,application,user,foreground_cycles,background_cycles,bytes_written,reason" :
             c.view == 2 ? "time,connect_start,connected_seconds,interface_luid,application,user" :
             c.view == 3 ? "application,bytes_sent,bytes_received,hours,reason" :
                           "time,application,user,bytes_sent,bytes_received,interface_luid,reason");
    } else {
        putchar('[');
    }
    ese_rows(&db, &t, c.view == 1 ? app_cb : c.view == 2 ? conn_cb : net_cb, &c);
    if (c.view == 3) {
        if (c.nsum > 1) qsort(c.sum, c.nsum, sizeof *c.sum, by_sent);
        for (size_t i = 0; i < c.nsum; i++) {
            char tmp[24];
            const char *app = idstr(&c, c.sum[i].app, tmp, sizeof tmp);
            const char *reason = c.sum[i].sent > 0 && ioc_user_writable(app) ? "program in a user-writable dir sent data" : NULL;
            c.rows++;
            if (reason) c.flagged++;
            if (c.only_flagged && reason == NULL) continue;
            if (c.mode == 0) {
                printf("%s %14llu sent %14llu received  %5u h  %s\n", reason ? "[!]" : "   ",
                       (unsigned long long)c.sum[i].sent, (unsigned long long)c.sum[i].recv, c.sum[i].hours, app);
                if (reason) printf("        <- %s\n", reason);
            } else if (c.mode == 2) {
                csv_str(app);
                printf(",%llu,%llu,%u,", (unsigned long long)c.sum[i].sent, (unsigned long long)c.sum[i].recv, c.sum[i].hours);
                csv_str(reason ? reason : ""); putchar('\n');
            } else {
                printf("%s{\"application\":", c.first ? "" : ",");
                json_str(app);
                printf(",\"bytes_sent\":%llu,\"bytes_received\":%llu,\"hours\":%u,\"suspicious\":%s,\"reason\":",
                       (unsigned long long)c.sum[i].sent, (unsigned long long)c.sum[i].recv, c.sum[i].hours, reason ? "true" : "false");
                json_str(reason ? reason : "");
                putchar('}');
                c.first = 0;
            }
        }
    }
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) printf("\n%u row(s), %u flagged\n", c.rows, c.flagged);
    for (size_t i = 0; i < c.nids; i++) free(c.ids[i].s);
    free(c.ids);
    free(c.sum);
    free(d);
    return 0;
}
