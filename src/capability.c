// winspect capability - Capability Access Manager usage history
//
//   ...\CapabilityAccessManager\ConsentStore\<capability>\<PackageFamilyName>
//   ...\CapabilityAccessManager\ConsentStore\<capability>\NonPackaged\<path, '#' for '\'>
//       Value               "Allow" / "Deny"
//       LastUsedTimeStart   FILETIME (REG_QWORD)
//       LastUsedTimeStop    FILETIME, 0 while in use
// under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion and the same path in
// each user's hive. Read through regsrc, so live keys and hive files work
// alike. Read-only.

#include "capability.h"
#include "regsrc.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char n[512][260]; int count; } names;

static void collect(const char *name, void *vctx)
{
    names *l = (names *)vctx;
    if (l->count < 512) snprintf(l->n[l->count++], sizeof l->n[0], "%s", name);
}

typedef struct {
    int mode, first, all, only_flagged;
    const char *find;
    unsigned shown, flagged;
} cctx;

static uint64_t qword(regsrc *s, rkey *k, const char *value)
{
    unsigned char d[8];
    uint32_t type = 0;
    if (rk_get(s, k, value, &type, d, 8) != 8) return 0;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | d[i];
    return v;
}

static void one(cctx *c, regsrc *s, const char *keypath, const char *scope, const char *capability, const char *entry, int nonpackaged)
{
    rkey k;
    if (rk_open(s, keypath, &k) != 0) return;
    uint64_t start = qword(s, &k, "LastUsedTimeStart"), stop = qword(s, &k, "LastUsedTimeStop");
    char consent[32] = "";
    rk_get_str(s, &k, "Value", consent, sizeof consent);
    rk_close(&k);
    if (start == 0 && !c->all) return;
    char app[600];
    if (nonpackaged) cam_app_path(entry, app, sizeof app);
    else snprintf(app, sizeof app, "%s", entry);
    const char *reason = start ? cam_reason(capability, app, nonpackaged) : NULL;
    if (c->only_flagged && reason == NULL) return;
    if (c->find && !ioc_contains_ci(app, c->find) && !ioc_contains_ci(capability, c->find)) return;
    char t0[24] = "", t1[24] = "", iso[40];
    if (start) { filetime_utc_str(start, iso, sizeof iso); snprintf(t0, sizeof t0, "%.19s", iso); }
    if (stop)  { filetime_utc_str(stop, iso, sizeof iso);  snprintf(t1, sizeof t1, "%.19s", iso); }
    int in_use = start != 0 && stop == 0;
    c->shown++;
    if (reason) c->flagged++;
    if (c->mode == 0) {
        printf("%s %-22s %-19s  %-19s  %-5s %-6s %s\n", reason ? "[!]" : "   ", capability, t0[0] ? t0 : "-",
               in_use ? "IN USE NOW" : (t1[0] ? t1 : "-"), consent[0] ? consent : "-", scope, app);
        if (reason) printf("        <- %s\n", reason);
    } else if (c->mode == 2) {
        csv_str(capability);
        printf(",%s,%s,%d,", t0, t1, in_use);
        csv_str(consent); putchar(',');
        csv_str(scope); putchar(',');
        printf("%d,", nonpackaged ? 0 : 1);
        csv_str(app); putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"capability\":", c->first ? "" : ",");
        json_str(capability);
        printf(",\"last_start\":\"%s\",\"last_stop\":\"%s\",\"in_use\":%s,\"consent\":", t0, t1, in_use ? "true" : "false");
        json_str(consent);
        fputs(",\"scope\":", stdout); json_str(scope);
        printf(",\"packaged\":%s,\"app\":", nonpackaged ? "false" : "true");
        json_str(app);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

// store = path of ConsentStore inside the source.
static void walk(cctx *c, regsrc *s, const char *store, const char *scope)
{
    rkey k;
    if (rk_open(s, store, &k) != 0) return;
    static names caps, apps, np;
    caps.count = 0;
    rk_subkeys(s, &k, collect, &caps);
    rk_close(&k);
    for (int i = 0; i < caps.count; i++) {
        char cp[700];
        snprintf(cp, sizeof cp, "%s\\%s", store, caps.n[i]);
        if (rk_open(s, cp, &k) != 0) continue;
        apps.count = 0;
        rk_subkeys(s, &k, collect, &apps);
        rk_close(&k);
        for (int a = 0; a < apps.count; a++) {
            char ap[1100];
            snprintf(ap, sizeof ap, "%s\\%s", cp, apps.n[a]);
            if (_stricmp(apps.n[a], "NonPackaged") != 0) {
                one(c, s, ap, scope, caps.n[i], apps.n[a], 0);
                continue;
            }
            if (rk_open(s, ap, &k) != 0) continue;
            np.count = 0;
            rk_subkeys(s, &k, collect, &np);
            rk_close(&k);
            for (int p = 0; p < np.count; p++) {
                char pp[1500];
                snprintf(pp, sizeof pp, "%s\\%s", ap, np.n[p]);
                one(c, s, pp, scope, caps.n[i], np.n[p], 1);
            }
        }
    }
}

int cmd_capability(int argc, char **argv)
{
    cctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *software = NULL, *ntuser = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)          c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)      c.mode = 2;
        else if (strcmp(argv[a], "--all") == 0)      c.all = 1;
        else if (strcmp(argv[a], "--flagged") == 0)  c.only_flagged = 1;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc)     c.find = argv[++a];
        else if (strcmp(argv[a], "--software") == 0 && a + 1 < argc) software = argv[++a];
        else if (strcmp(argv[a], "--ntuser") == 0 && a + 1 < argc)   ntuser = argv[++a];
        else {
            fprintf(stderr, "capability: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    static regsrc machine, user;
    int have_m = 0, have_u = 0;
    static const char REL[] = "Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";
    char err[512];
    if (software || ntuser) {
        if (software) {
            if (regsrc_open_hive(&machine, software, err, sizeof err) != 0) { if (c.mode == 1) puts("[]"); fprintf(stderr, "capability: %s\n", err); return 1; }
            have_m = 1;
        }
        if (ntuser) {
            if (regsrc_open_hive(&user, ntuser, err, sizeof err) != 0) {
                if (c.mode == 1) puts("[]");
                fprintf(stderr, "capability: %s\n", err);
                if (have_m) regsrc_close(&machine);
                return 1;
            }
            have_u = 1;
        }
    } else {
        have_m = regsrc_open_live(&machine, HKEY_LOCAL_MACHINE, "SOFTWARE", "HKLM\\SOFTWARE") == 0;
        have_u = regsrc_open_live(&user, HKEY_CURRENT_USER, NULL, "HKCU") == 0;
    }
    if (c.mode == 0) {
        puts("capability  (who used the microphone, camera, location ...; UTC)\n");
        printf("    %-22s %-19s  %-19s  %-5s %-6s %s\n", "capability", "last start", "last stop", "set", "scope", "app");
    } else if (c.mode == 2) {
        puts("capability,last_start,last_stop,in_use,consent,scope,packaged,app,reason");
    } else {
        putchar('[');
    }
    if (have_m) { walk(&c, &machine, REL, "system"); regsrc_close(&machine); }
    if (have_u) {
        char up[200];
        snprintf(up, sizeof up, "Software\\%s", REL);
        walk(&c, &user, up, "user");
        regsrc_close(&user);
    }
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) printf("\n%u entr%s, %u flagged%s\n", c.shown, c.shown == 1 ? "y" : "ies", c.flagged,
                                 c.all ? "" : "  (--all also lists apps that never used the capability)");
    return 0;
}
