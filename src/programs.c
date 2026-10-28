// winspect programs - installed software (Uninstall keys)
//
// Every installer that registers with "Programs and Features" writes a key
//   SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<id>             (64-bit)
//   SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\<id> (32-bit)
//   HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\<id>        (per user)
// with DisplayName, DisplayVersion, Publisher, InstallDate ("YYYYMMDD"),
// InstallLocation, UninstallString. The key's last-write time approximates
// when the program was installed or last updated. For an investigation the
// newest entries answer "what was installed around the incident?", and a
// remote-access tool among them is a classic sign of hands-on intrusion; the
// product list is in artparse.c (rmm_tool_name, unit-tested).
// Entries with SystemComponent = 1 (hidden from Programs and Features) are
// still listed and marked. Live or offline (SOFTWARE / NTUSER.DAT). Read-only.

#include "programs.h"
#include "artparse.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t when;
    const char *scope;
    char id[256], name[512], version[128], publisher[256], date[16], location[512];
    int hidden;
    const char *reason;
    char rmm[64];
} prow;

typedef struct {
    prow *rows;
    size_t n, cap;
} plist;

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

typedef struct { char n[4096][192]; int count; } idlist;
static void on_id(const char *name, void *vctx)
{
    idlist *l = (idlist *)vctx;
    if (l->count < 4096) snprintf(l->n[l->count++], sizeof l->n[0], "%s", name);
}

static void scan(regsrc *src, const char *base, const char *scope, plist *pl)
{
    if (src == NULL) return;
    rkey k;
    if (rk_open(src, base, &k) != 0) return;
    static idlist ids;
    ids.count = 0;
    rk_subkeys(src, &k, on_id, &ids);
    rk_close(&k);
    for (int i = 0; i < ids.count; i++) {
        char p[512];
        snprintf(p, sizeof p, "%s\\%s", base, ids.n[i]);
        if (rk_open(src, p, &k) != 0) continue;
        if (pl->n == pl->cap) {
            size_t nc = pl->cap ? pl->cap * 2 : 128;
            prow *nr = (prow *)realloc(pl->rows, nc * sizeof *nr);
            if (nr == NULL) { rk_close(&k); return; }
            pl->rows = nr;
            pl->cap = nc;
        }
        prow *r = &pl->rows[pl->n++];
        memset(r, 0, sizeof *r);
        r->scope = scope;
        r->when = rk_lastwrite(src, &k);
        snprintf(r->id, sizeof r->id, "%s", ids.n[i]);
        rk_get_str(src, &k, "DisplayName", r->name, sizeof r->name);
        rk_get_str(src, &k, "DisplayVersion", r->version, sizeof r->version);
        rk_get_str(src, &k, "Publisher", r->publisher, sizeof r->publisher);
        rk_get_str(src, &k, "InstallDate", r->date, sizeof r->date);
        rk_get_str(src, &k, "InstallLocation", r->location, sizeof r->location);
        unsigned char d[4];
        uint32_t type = 0;
        r->hidden = rk_get(src, &k, "SystemComponent", &type, d, 4) == 4 && type == REG_DWORD && d[0] == 1;
        rk_close(&k);
        const char *t = rmm_tool_name(r->name[0] ? r->name : r->id);
        if (t != NULL) {
            snprintf(r->rmm, sizeof r->rmm, "%s", t);
            r->reason = "remote-access (RMM) tool - confirm it is authorised";
        }
    }
}

static int newest_first(const void *a, const void *b)
{
    uint64_t x = ((const prow *)a)->when, y = ((const prow *)b)->when;
    return (x < y) - (x > y);
}

int cmd_programs(int argc, char **argv)
{
    int mode = 0, only_flagged = 0;
    const char *hsw = NULL, *hcu = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0) only_flagged = 1;
        else if (strcmp(argv[a], "--software") == 0 && a + 1 < argc) hsw = argv[++a];
        else if (strcmp(argv[a], "--ntuser") == 0 && a + 1 < argc)   hcu = argv[++a];
        else {
            fprintf(stderr, "programs: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    static regsrc sw, cu;
    regsrc *psw = NULL, *pcu = NULL;
    char err[512];
    if (hsw || hcu) {
        if (hsw) {
            if (regsrc_open_hive(&sw, hsw, err, sizeof err) != 0) { fprintf(stderr, "programs: %s\n", err); return 1; }
            psw = &sw;
        }
        if (hcu) {
            if (regsrc_open_hive(&cu, hcu, err, sizeof err) != 0) {
                fprintf(stderr, "programs: %s\n", err);
                if (psw) regsrc_close(psw);
                return 1;
            }
            pcu = &cu;
        }
    } else {
        if (regsrc_open_live(&sw, HKEY_LOCAL_MACHINE, "SOFTWARE", "HKLM\\SOFTWARE") == 0) psw = &sw;
        regsrc_open_live(&cu, HKEY_CURRENT_USER, NULL, "HKCU");
        pcu = &cu;
    }

    plist pl = { NULL, 0, 0 };
    scan(psw, "Microsoft\\Windows\\CurrentVersion\\Uninstall", "machine", &pl);
    scan(psw, "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "machine-32", &pl);
    scan(pcu, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "user", &pl);
    if (psw) regsrc_close(psw);
    if (pcu) regsrc_close(pcu);
    qsort(pl.rows, pl.n, sizeof *pl.rows, newest_first);

    if (mode == 0) {
        puts("programs  (Uninstall keys, newest first; time = key last write)\n");
        printf("      %-19s  %-10s %-44s %-16s %s\n", "key written (UTC)", "scope", "name", "version", "publisher");
    } else if (mode == 2) {
        puts("key_written,scope,id,name,version,publisher,install_date,location,hidden,rmm_tool,reason");
    } else {
        putchar('[');
    }
    unsigned shown = 0, flagged = 0;
    for (size_t i = 0; i < pl.n; i++) {
        const prow *r = &pl.rows[i];
        if (r->reason) flagged++;
        if (only_flagged && r->reason == NULL) continue;
        char when[32];
        ft_str(r->when, when, sizeof when);
        if (mode == 0) {
            printf("  %s%-19s  %-10s %-44s %-16s %s%s\n", r->reason ? "[!] " : "    ", when, r->scope,
                   r->name[0] ? r->name : r->id, r->version, r->publisher, r->hidden ? "  (hidden)" : "");
            if (r->reason) printf("        <- %s: %s\n", r->rmm, r->reason);
        } else if (mode == 2) {
            csv_str(when); putchar(',');
            csv_str(r->scope); putchar(',');
            csv_str(r->id); putchar(',');
            csv_str(r->name); putchar(',');
            csv_str(r->version); putchar(',');
            csv_str(r->publisher); putchar(',');
            csv_str(r->date); putchar(',');
            csv_str(r->location);
            printf(",%s,", r->hidden ? "true" : "false");
            csv_str(r->rmm); putchar(',');
            csv_str(r->reason ? r->reason : ""); putchar('\n');
        } else {
            printf("%s{\"key_written\":", shown ? "," : "");
            json_str(when);
            fputs(",\"scope\":", stdout);        json_str(r->scope);
            fputs(",\"id\":", stdout);           json_str(r->id);
            fputs(",\"name\":", stdout);         json_str(r->name);
            fputs(",\"version\":", stdout);      json_str(r->version);
            fputs(",\"publisher\":", stdout);    json_str(r->publisher);
            fputs(",\"install_date\":", stdout); json_str(r->date);
            fputs(",\"location\":", stdout);     json_str(r->location);
            printf(",\"hidden\":%s,\"rmm_tool\":", r->hidden ? "true" : "false");
            json_str(r->rmm);
            printf(",\"suspicious\":%s,\"reason\":", r->reason ? "true" : "false");
            json_str(r->reason ? r->reason : "");
            putchar('}');
        }
        shown++;
    }
    if (mode == 1) {
        puts("]");
    } else if (mode == 0) {
        printf("\n%lu program(s), %u remote-access tool(s)\n", (unsigned long)pl.n, flagged);
    }
    free(pl.rows);
    return 0;
}
