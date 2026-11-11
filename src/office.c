// winspect office - Office Trusted Documents, macro settings, trusted locations
//
// Layout under the user's hive (same below Software\Policies for policy):
//   Software\Microsoft\Office\<version>\<Application>\Security
//       VBAWarnings, AccessVBOM, BlockContentExecutionFromInternet   (DWORD)
//       Trusted Documents\TrustRecords      one binary value per document
//       Trusted Locations\<LocationN>       Path, AllowSubFolders, Description
// The value formats and the flag rules are in officeparse.c (portable,
// unit-tested); this file walks the keys through regsrc (live or hive file).

#include "office.h"
#include "officeparse.h"
#include "regsrc.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    regsrc *src;
    int mode, first, only_flagged;
    unsigned count, flagged;
    // where the walk currently is
    char version[32], app[64];
    const char *scope;          // "user" or "policy"
    rkey cur;                   // key whose values are being read
} octx;

static void emit(octx *c, const char *kind, const char *when, const char *item, const char *detail, const char *reason)
{
    if (c->only_flagged && reason == NULL) return;
    c->count++;
    if (reason) c->flagged++;
    if (c->mode == 0) {
        printf("%s %-9s %-19s  %-10s %-5s %s", reason ? "[!]" : "   ", kind, when[0] ? when : "-", c->app, c->version, item);
        if (detail[0]) printf("  (%s)", detail);
        putchar('\n');
        if (reason) printf("        <- %s\n", reason);
    } else if (c->mode == 2) {
        printf("%s,%s,", kind, when);
        csv_str(c->app); putchar(',');
        csv_str(c->version); putchar(',');
        csv_str(c->scope); putchar(',');
        csv_str(item); putchar(',');
        csv_str(detail); putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"kind\":\"%s\",\"time\":\"%s\",\"application\":", c->first ? "" : ",", kind, when);
        json_str(c->app);
        fputs(",\"version\":", stdout); json_str(c->version);
        fputs(",\"scope\":", stdout);   json_str(c->scope);
        fputs(",\"item\":", stdout);    json_str(item);
        fputs(",\"detail\":", stdout);  json_str(detail);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void trust_record(const char *name, uint32_t type, const unsigned char *data, size_t len, void *vctx)
{
    octx *c = (octx *)vctx;
    uint64_t ft;
    int content;
    if (type != REG_BINARY || trustrec_parse(data, len, &ft, &content) != 0) return;
    char path[1024], iso[40], when[24];
    trustrec_path(name, path, sizeof path);
    filetime_utc_str(ft, iso, sizeof iso);
    snprintf(when, sizeof when, "%.19s", iso);
    emit(c, "document", when, path, content ? "macros / active content enabled" : "editing enabled",
         trustrec_reason(path, content));
}

static void setting(octx *c, const char *name)
{
    uint32_t type = 0;
    unsigned char d[8];
    long n = rk_get(c->src, &c->cur, name, &type, d, sizeof d);
    if (n != 4 || type != REG_DWORD) return;
    uint32_t v = (uint32_t)d[0] | (uint32_t)d[1] << 8 | (uint32_t)d[2] << 16 | (uint32_t)d[3] << 24;
    const char *reason = office_setting_reason(name, v);
    char detail[48];
    snprintf(detail, sizeof detail, "= %lu, %s", (unsigned long)v, c->scope);
    // Only values that weaken the default are worth a row.
    if (reason) emit(c, "setting", "", name, detail, reason);
}

typedef struct { char names[64][96]; int n; } namelist;

static void collect(const char *name, void *vctx)
{
    namelist *l = (namelist *)vctx;
    if (l->n < 64) snprintf(l->names[l->n++], sizeof l->names[0], "%s", name);
}

static void one_app(octx *c, const char *office_root)
{
    char base[512], path[640];
    snprintf(base, sizeof base, "%s\\%s\\%s\\Security", office_root, c->version, c->app);
    if (rk_open(c->src, base, &c->cur) == 0) {
        setting(c, "VBAWarnings");
        setting(c, "AccessVBOM");
        setting(c, "BlockContentExecutionFromInternet");
        rk_close(&c->cur);
    }
    snprintf(path, sizeof path, "%s\\Trusted Documents\\TrustRecords", base);
    rkey k;
    if (rk_open(c->src, path, &k) == 0) {
        rk_values(c->src, &k, trust_record, c);
        rk_close(&k);
    }
    snprintf(path, sizeof path, "%s\\Trusted Locations", base);
    if (rk_open(c->src, path, &k) == 0) {
        static namelist locs;
        locs.n = 0;
        rk_subkeys(c->src, &k, collect, &locs);
        rk_close(&k);
        for (int i = 0; i < locs.n; i++) {
            char lp[800], dir[1024], desc[256], when[24] = "", iso[40];
            snprintf(lp, sizeof lp, "%s\\%s", path, locs.names[i]);
            rkey lk;
            if (rk_open(c->src, lp, &lk) != 0) continue;
            if (rk_get_str(c->src, &lk, "Path", dir, sizeof dir) && dir[0]) {
                rk_get_str(c->src, &lk, "Description", desc, sizeof desc);
                uint64_t lw = rk_lastwrite(c->src, &lk);
                if (lw) { filetime_utc_str(lw, iso, sizeof iso); snprintf(when, sizeof when, "%.19s", iso); }
                emit(c, "location", when, dir, desc, trustloc_reason(dir));
            }
            rk_close(&lk);
        }
    }
}

static void walk(octx *c, const char *office_root, const char *scope)
{
    c->scope = scope;
    rkey root;
    if (rk_open(c->src, office_root, &root) != 0) return;
    static namelist versions;
    versions.n = 0;
    rk_subkeys(c->src, &root, collect, &versions);
    rk_close(&root);
    for (int v = 0; v < versions.n; v++) {
        // Version keys are numbers ("16.0", "15.0", "12.0"); "Common",
        // "Outlook" etc. sit beside them and hold other things.
        if (versions.names[v][0] < '0' || versions.names[v][0] > '9') continue;
        snprintf(c->version, sizeof c->version, "%s", versions.names[v]);
        char vp[256];
        snprintf(vp, sizeof vp, "%s\\%s", office_root, c->version);
        rkey vk;
        if (rk_open(c->src, vp, &vk) != 0) continue;
        static namelist apps;
        apps.n = 0;
        rk_subkeys(c->src, &vk, collect, &apps);
        rk_close(&vk);
        for (int a = 0; a < apps.n; a++) {
            snprintf(c->app, sizeof c->app, "%s", apps.names[a]);
            one_app(c, office_root);
        }
    }
}

int cmd_office(int argc, char **argv)
{
    octx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *hive = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)         c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)     c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0) c.only_flagged = 1;
        else if (strcmp(argv[a], "--hive") == 0 && a + 1 < argc) hive = argv[++a];
        else {
            fprintf(stderr, "office: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    static regsrc src;
    if (hive != NULL) {
        char err[512];
        if (regsrc_open_hive(&src, hive, err, sizeof err) != 0) {
            if (c.mode == 1) puts("[]");
            fprintf(stderr, "office: %s\n", err);
            return 1;
        }
        if (regsrc_dirty(&src)) fputs("office: note: hive is dirty (transaction logs not replayed)\n", stderr);
    } else {
        regsrc_open_live(&src, HKEY_CURRENT_USER, NULL, "HKCU");
    }
    c.src = &src;
    if (c.mode == 0) {
        printf("office  (%s; macro trust decisions, settings and trusted locations; UTC)\n\n", src.label);
        printf("    %-9s %-19s  %-10s %-5s %s\n", "kind", "time", "app", "ver", "item");
    } else if (c.mode == 2) {
        puts("kind,time,application,version,scope,item,detail,reason");
    } else {
        putchar('[');
    }
    walk(&c, "Software\\Microsoft\\Office", "user");
    walk(&c, "Software\\Policies\\Microsoft\\Office", "policy");
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) printf("\n%u row(s), %u flagged\n", c.count, c.flagged);
    regsrc_close(&src);
    return 0;
}
