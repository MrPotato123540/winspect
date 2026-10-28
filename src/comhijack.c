// winspect comhijack - per-user COM overrides
//
// COM looks a CLSID up in HKCR, which is a merged view: HKCU\Software\Classes
// first, HKLM\SOFTWARE\Classes second. Any user can therefore register a
// class ID that Windows or an application already uses and point it at their
// own DLL; the next time a process of that user creates the object, the
// user's DLL is loaded. No admin rights, no file changed in System32.
//
// We walk the per-user CLSID keys (usually a few hundred at most), read each
// one's InprocServer32 / LocalServer32 default value and look the same CLSID
// up machine-wide. A different server file (compared by com_path_same in
// artparse.c, unit-tested: env vars, quotes, case, arguments, bare names) is
// flagged. Per-user-only classes are normal for per-user installs (OneDrive
// keeps its shell extensions in AppData) and are only listed with --all.
// Read-only: through regsrc, live registry or offline hive files.

#include "comhijack.h"
#include "regsrc.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int mode, first, all, only_flagged, compare;
    unsigned seen, overrides, flagged;
    regsrc *user, *mach;
    const char *upfx, *mpfx;   // path prefixes inside each source
    const char *view;          // "" or "WOW6432Node\\"
} cctx;

// Default value of <prefix><view>CLSID\<clsid>\<sub> (InprocServer32 then
// LocalServer32). Returns 1 and the kind found, or 0.
static int server_of(regsrc *s, const char *pfx, const char *view, const char *clsid,
                     char *out, size_t n, const char **kind)
{
    static const char *const subs[] = { "InprocServer32", "LocalServer32" };
    for (size_t i = 0; i < 2; i++) {
        char path[512];
        rkey k;
        snprintf(path, sizeof path, "%s%sCLSID\\%s\\%s", pfx, view, clsid, subs[i]);
        if (rk_open(s, path, &k) != 0) continue;
        int ok = rk_get_str(s, &k, "", out, n);
        rk_close(&k);
        if (ok && out[0]) {
            *kind = subs[i];
            return 1;
        }
    }
    out[0] = 0;
    return 0;
}

static void class_name(regsrc *s, const char *pfx, const char *view, const char *clsid, char *out, size_t n)
{
    char path[512];
    rkey k;
    out[0] = 0;
    snprintf(path, sizeof path, "%s%sCLSID\\%s", pfx, view, clsid);
    if (rk_open(s, path, &k) == 0) {
        rk_get_str(s, &k, "", out, n);
        rk_close(&k);
    }
}

static void one_clsid(const char *clsid, void *vctx)
{
    cctx *c = (cctx *)vctx;
    if (clsid[0] != '{') return;
    char usrv[1024], machv[1024] = "", name[256] = "";
    const char *ukind = "", *mkind = "";
    if (!server_of(c->user, c->upfx, c->view, clsid, usrv, sizeof usrv, &ukind)) return;
    c->seen++;
    int in_machine = 0;
    if (c->compare) {
        in_machine = server_of(c->mach, c->mpfx, c->view, clsid, machv, sizeof machv, &mkind);
        class_name(c->mach, c->mpfx, c->view, clsid, name, sizeof name);
    }
    if (name[0] == 0) class_name(c->user, c->upfx, c->view, clsid, name, sizeof name);
    if (in_machine) c->overrides++;
    const char *reason = NULL;
    if (in_machine && !com_path_same(usrv, machv))
        reason = "per-user registration replaces the machine COM server (COM hijacking, T1546.015)";
    if (reason) c->flagged++;
    if (c->only_flagged && reason == NULL) return;
    if (!c->all && !in_machine) return;

    // Key last-write time: when the per-user registration was made / changed.
    char path[512], when[32] = "-";
    rkey k;
    snprintf(path, sizeof path, "%s%sCLSID\\%s", c->upfx, c->view, clsid);
    if (rk_open(c->user, path, &k) == 0) {
        filetime_utc_str(rk_lastwrite(c->user, &k), when, sizeof when);
        rk_close(&k);
    }
    const char *view = c->view[0] ? "32-bit" : "64-bit";
    if (c->mode == 0) {
        printf("%s %s  %s  (%s view, key written %s UTC)\n", reason ? "[!]" : "   ", clsid,
               name[0] ? name : "(no name)", view, when);
        printf("      user    %-14s %s\n", ukind, usrv);
        if (c->compare) printf("      machine %-14s %s\n", in_machine ? mkind : "-", in_machine ? machv : "(not registered)");
        if (reason) printf("      <- %s\n", reason);
    } else if (c->mode == 2) {
        printf("%s,", clsid);
        csv_str(name); printf(",%s,%s,%s,", view, when, ukind);
        csv_str(usrv); putchar(',');
        csv_str(machv); printf(",%s,", in_machine ? "true" : "false");
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"clsid\":\"%s\",\"name\":", c->first ? "" : ",", clsid);
        json_str(name);
        printf(",\"view\":\"%s\",\"key_written\":\"%s\",\"user_kind\":\"%s\",\"user_server\":", view, when, ukind);
        json_str(usrv);
        fputs(",\"machine_server\":", stdout);
        json_str(machv);
        printf(",\"overrides_machine\":%s,\"suspicious\":%s,\"reason\":", in_machine ? "true" : "false",
               reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

int cmd_comhijack(int argc, char **argv)
{
    cctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *usrclass = NULL, *software = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                          c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                      c.mode = 2;
        else if (strcmp(argv[a], "--all") == 0)                      c.all = 1;
        else if (strcmp(argv[a], "--flagged") == 0)                  c.only_flagged = 1;
        else if (strcmp(argv[a], "--usrclass") == 0 && a + 1 < argc) usrclass = argv[++a];
        else if (strcmp(argv[a], "--software") == 0 && a + 1 < argc) software = argv[++a];
        else {
            fprintf(stderr, "comhijack: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (software && !usrclass) {
        fputs("comhijack: --software needs --usrclass (both from the same machine)\n", stderr);
        return 1;
    }
    static regsrc us, ms;
    char err[256];
    if (usrclass) {
        // UsrClass.dat's root is the Classes key itself.
        if (regsrc_open_hive(&us, usrclass, err, sizeof err) != 0) {
            fprintf(stderr, "comhijack: %s\n", err);
            return 1;
        }
        c.upfx = "";
        if (software) {
            if (regsrc_open_hive(&ms, software, err, sizeof err) != 0) {
                fprintf(stderr, "comhijack: %s\n", err);
                regsrc_close(&us);
                return 1;
            }
            c.mpfx = "Classes\\";
            c.compare = 1;
        }
    } else {
        LONG e = regsrc_open_live(&us, HKEY_CURRENT_USER, "Software\\Classes", "HKCU\\Software\\Classes");
        if (e != 0) {
            fprintf(stderr, "comhijack: cannot open HKCU\\Software\\Classes (error %ld)\n", (long)e);
            return 1;
        }
        e = regsrc_open_live(&ms, HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes", "HKLM\\SOFTWARE\\Classes");
        c.compare = e == 0;
        c.upfx = c.mpfx = "";
    }
    c.user = &us;
    c.mach = &ms;
    if (!c.compare) c.all = 1;      // nothing to compare against: list everything

    if (c.mode == 0) {
        printf("comhijack  (per-user COM classes from %s%s%s)\n\n", us.label,
               c.compare ? " vs " : "; no machine hive given, nothing compared",
               c.compare ? ms.label : "");
    } else if (c.mode == 2) {
        puts("clsid,name,view,key_written,user_kind,user_server,machine_server,overrides_machine,reason");
    } else {
        putchar('[');
    }
    static const char *const views[] = { "", "WOW6432Node\\" };
    for (size_t v = 0; v < 2; v++) {
        char path[64];
        rkey k;
        c.view = views[v];
        snprintf(path, sizeof path, "%s%sCLSID", c.upfx, c.view);
        if (rk_open(c.user, path, &k) != 0) continue;
        rk_subkeys(c.user, &k, one_clsid, &c);
        rk_close(&k);
    }
    if (c.mode == 1) {
        puts("]");
    } else if (c.mode == 0) {
        printf("\n%u per-user class(es) with a server, %u also registered machine-wide, %u flagged\n",
               c.seen, c.overrides, c.flagged);
    }
    regsrc_close(&us);
    if (c.compare || software) regsrc_close(&ms);
    return 0;
}
