// winspect rdp - outgoing Remote Desktop connection history
//
// The Remote Desktop client (mstsc.exe) remembers, per user, under
//   HKCU\Software\Microsoft\Terminal Server Client, with
//     Default            MRU0..MRU9 (REG_SZ): last hosts typed, MRU0 newest
//     Servers\<host>     one key per host ever connected to; UsernameHint is
//                        the account used, CertHash the accepted certificate
// The Servers keys' last-write time approximates the last connection to that
// host (the key is updated when the hint or certificate changes); the Default
// key's last-write time is when MRU0 was last set. Investigators read this as
// "which machines did this account RDP to" - lateral movement seen from the
// source side. The same data comes from a live HKCU or another user's
// NTUSER.DAT (--hive). Read-only.

#include "rdp.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TSC "Software\\Microsoft\\Terminal Server Client"

typedef struct {
    regsrc *src;
    int mode, first;
    unsigned count;
} rctx;

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

static void row(rctx *c, const char *source, int pos, const char *host, const char *user,
                const char *when, int cert)
{
    c->count++;
    if (c->mode == 0) {
        char p[8] = "-";
        if (pos >= 0) snprintf(p, sizeof p, "%d", pos);
        printf("    %-8s %3s  %-19s  %-40s %s%s\n", source, p, when, host, user,
               cert ? "  (certificate accepted)" : "");
    } else if (c->mode == 2) {
        csv_str(source);
        printf(",%d,", pos);
        csv_str(when); putchar(',');
        csv_str(host); putchar(',');
        csv_str(user);
        printf(",%s\n", cert ? "true" : "false");
    } else {
        printf("%s{\"source\":", c->first ? "" : ",");
        json_str(source);
        if (pos >= 0) printf(",\"position\":%d", pos); else fputs(",\"position\":null", stdout);
        fputs(",\"time\":", stdout);          json_str(when);
        fputs(",\"host\":", stdout);          json_str(host);
        fputs(",\"username_hint\":", stdout); json_str(user);
        printf(",\"certificate_accepted\":%s}", cert ? "true" : "false");
        c->first = 0;
    }
}

typedef struct { char names[512][260]; int n; } namelist;
static void on_name(const char *name, void *vctx)
{
    namelist *l = (namelist *)vctx;
    if (l->n < 512) snprintf(l->names[l->n++], sizeof l->names[0], "%s", name);
}

int cmd_rdp(int argc, char **argv)
{
    rctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *hive = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "--hive") == 0 && a + 1 < argc) hive = argv[++a];
        else {
            fprintf(stderr, "rdp: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    regsrc src;
    if (hive != NULL) {
        char err[512];
        if (regsrc_open_hive(&src, hive, err, sizeof err) != 0) {
            fprintf(stderr, "rdp: %s\n", err);
            return 1;
        }
        if (regsrc_dirty(&src)) fputs("rdp: note: hive is dirty (transaction logs not replayed)\n", stderr);
    } else {
        regsrc_open_live(&src, HKEY_CURRENT_USER, NULL, "HKCU");
    }
    c.src = &src;

    if (c.mode == 0) {
        printf("rdp  (outgoing Remote Desktop history in %s)\n\n", src.label);
        printf("    %-8s %3s  %-19s  %-40s %s\n", "source", "pos", "time (UTC)", "host", "user name hint");
    } else if (c.mode == 2) {
        puts("source,position,time,host,username_hint,certificate_accepted");
    } else {
        putchar('[');
    }

    rkey k;
    if (rk_open(&src, TSC "\\Default", &k) == 0) {
        char when[32];
        ft_str(rk_lastwrite(&src, &k), when, sizeof when);
        for (int i = 0; i < 10; i++) {
            char name[8], host[512];
            snprintf(name, sizeof name, "MRU%d", i);
            if (!rk_get_str(&src, &k, name, host, sizeof host) || host[0] == '\0') continue;
            row(&c, "Default", i, host, "", i == 0 ? when : "", 0);
        }
        rk_close(&k);
    }
    static namelist servers;
    servers.n = 0;
    if (rk_open(&src, TSC "\\Servers", &k) == 0) {
        rk_subkeys(&src, &k, on_name, &servers);
        rk_close(&k);
    }
    for (int i = 0; i < servers.n; i++) {
        char p[700], user[512] = "", when[32];
        snprintf(p, sizeof p, TSC "\\Servers\\%s", servers.names[i]);
        if (rk_open(&src, p, &k) != 0) continue;
        rk_get_str(&src, &k, "UsernameHint", user, sizeof user);
        unsigned char cert[64];
        uint32_t type = 0;
        int has_cert = rk_get(&src, &k, "CertHash", &type, cert, sizeof cert) > 0;
        ft_str(rk_lastwrite(&src, &k), when, sizeof when);
        row(&c, "Servers", -1, servers.names[i], user, when, has_cert);
        rk_close(&k);
    }
    regsrc_close(&src);

    if (c.mode == 1) {
        puts("]");
    } else if (c.mode == 0) {
        printf("\n%u entr%s\n", c.count, c.count == 1 ? "y" : "ies");
    }
    return 0;
}
