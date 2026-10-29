// winspect defender - Microsoft Defender exclusions and "off switch" policies
//
// Defender keeps its exclusion lists in the registry, one key per kind, where
// each VALUE NAME is an excluded item (the data is just a DWORD 0):
//   HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Extensions,
//        Processes,IpAddresses}                       - set locally (UI/PowerShell)
//   HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\{...}
//                                                     - pushed by Group Policy
// Attackers who gain admin rights commonly add an exclusion so their tools are
// never scanned; defenders review these lists for exactly that reason (the same
// data Get-MpPreference shows). We also report the DWORDs that disable
// protection outright (DisableAntiSpyware, DisableRealtimeMonitoring, ...) -
// in the Group Policy key AND in Defender's own key: the local
// SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware is honoured too and
// is what installers of other AV products - and malware - often set.
// --software reads an offline SOFTWARE hive instead of the live registry.
//
// Read-only: keys are opened with KEY_READ and nothing is ever written. Since
// Windows 10 the local Exclusions keys are readable only by administrators, so
// ERROR_ACCESS_DENIED is reported as "access denied" rather than "no entries" -
// silently showing an empty list would be misleading.

#include "defender.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Paths inside the SOFTWARE hive (live: HKLM\SOFTWARE).
#define DEF_LOCAL  "Microsoft\\Windows Defender"
#define DEF_POLICY "Policies\\Microsoft\\Windows Defender"

typedef struct {
    int mode;           // 0 text, 1 json, 2 csv
    int first;          // JSON comma management
    unsigned count;     // exclusions printed
    int denied;         // any key we could not read
    regsrc *src;        // live HKLM\SOFTWARE or an offline SOFTWARE hive
} def_ctx;

static void emit(def_ctx *c, const char *source, const char *kind, const char *value)
{
    if (c->mode == 0) {
        printf("  %-7s %-12s %s\n", source, kind, value);
    } else if (c->mode == 2) {
        csv_str(source); putchar(',');
        csv_str(kind);   putchar(',');
        csv_str(value);  putchar('\n');
    } else {
        printf("%s{\"source\":", c->first ? "" : ",");
        json_str(source);
        fputs(",\"kind\":", stdout);  json_str(kind);
        fputs(",\"value\":", stdout); json_str(value);
        putchar('}');
        c->first = 0;
    }
}

typedef struct { def_ctx *c; const char *source, *kind; } exfwd;
static void on_excl(const char *name, uint32_t type, const unsigned char *d, size_t len, void *vctx)
{
    exfwd *f = (exfwd *)vctx;
    (void)type; (void)d; (void)len;
    if (name[0] == '\0') return;     // the unnamed "(Default)" value is not an exclusion
    emit(f->c, f->source, f->kind, name);
    f->c->count++;
}

// List every value name under <base>\Exclusions\<kind>.
static void enum_exclusions(def_ctx *c, const char *base, const char *source,
                            const char *kind)
{
    char path[256];
    snprintf(path, sizeof path, "%s\\Exclusions\\%s", base, kind);
    rkey k;
    int rc = rk_open(c->src, path, &k);
    if (rc == -1 || rc == ERROR_FILE_NOT_FOUND) {
        return;     // key absent = no exclusions of this kind
    }
    if (rc != 0) {
        if (rc == ERROR_ACCESS_DENIED) {
            c->denied = 1;
            if (c->mode == 0) {
                printf("  %-7s %-12s (access denied - run elevated to read)\n", source, kind);
            }
        }
        return;
    }
    exfwd f = { c, source, kind };
    rk_values(c->src, &k, on_excl, &f);
    rk_close(&k);
}

// Read a DWORD switch; returns 1 and fills *out when it exists.
static int read_dword(def_ctx *c, const char *subkey, const char *value, DWORD *out)
{
    rkey k;
    if (rk_open(c->src, subkey, &k) != 0) return 0;
    unsigned char d[4];
    uint32_t type = 0;
    int ok = rk_get(c->src, &k, value, &type, d, 4) == 4 && type == REG_DWORD;
    rk_close(&k);
    if (ok) *out = (DWORD)d[0] | ((DWORD)d[1] << 8) | ((DWORD)d[2] << 16) | ((DWORD)d[3] << 24);
    return ok;
}

int cmd_defender(int argc, char **argv)
{
    def_ctx c = { 0, 1, 0, 0, NULL };
    const char *hive = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--software") == 0 && a + 1 < argc) hive = argv[++a];
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else {
            fprintf(stderr, "defender: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    static const char *kinds[] = { "Paths", "Extensions", "Processes", "IpAddresses" };
    regsrc src;
    if (hive != NULL) {
        char err[512];
        if (regsrc_open_hive(&src, hive, err, sizeof err) != 0) {
            fprintf(stderr, "defender: %s\n", err);
            return 1;
        }
    } else if (regsrc_open_live(&src, HKEY_LOCAL_MACHINE, "SOFTWARE", "HKLM\\SOFTWARE") != 0) {
        fputs("defender: cannot open HKLM\\SOFTWARE\n", stderr);
        return 1;
    }
    c.src = &src;

    if (c.mode == 0) {
        puts("defender exclusions\n");
        printf("  %-7s %-12s %s\n", "source", "kind", "value");
    } else if (c.mode == 2) {
        puts("source,kind,value");
    } else {
        fputs("{\"exclusions\":[", stdout);
    }

    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        enum_exclusions(&c, DEF_LOCAL, "local", kinds[i]);
    }
    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        enum_exclusions(&c, DEF_POLICY, "policy", kinds[i]);
    }

    // Policy values that turn protection off. A value of 1 means "disabled";
    // they only exist if someone (an admin, GPO - or an intruder) set them.
    static const struct { const char *src, *key, *value; } offsw[] = {
        { "policy", DEF_POLICY,                              "DisableAntiSpyware" },
        { "policy", DEF_POLICY,                              "DisableAntiVirus" },
        { "policy", DEF_POLICY "\\Real-Time Protection",     "DisableRealtimeMonitoring" },
        { "policy", DEF_POLICY "\\Real-Time Protection",     "DisableBehaviorMonitoring" },
        { "policy", DEF_POLICY "\\Real-Time Protection",     "DisableIOAVProtection" },
        { "policy", DEF_POLICY "\\Spynet",                   "SpynetReporting" },
        { "local",  DEF_LOCAL,                               "DisableAntiSpyware" },
        { "local",  DEF_LOCAL,                               "DisableAntiVirus" },
        { "local",  DEF_LOCAL "\\Real-Time Protection",      "DisableRealtimeMonitoring" },
    };

    if (c.mode == 1) {
        fputs("],\"policies\":[", stdout);
    } else if (c.mode == 0) {
        printf("\n%u exclusion(s)%s\n\nswitches that turn protection off (only those that are set)\n",
               c.count, c.denied ? "  - some lists unreadable, run elevated" : "");
    }
    int pfirst = 1;
    unsigned off = 0;
    for (size_t i = 0; i < sizeof offsw / sizeof offsw[0]; i++) {
        DWORD v = 0;
        if (!read_dword(&c, offsw[i].key, offsw[i].value, &v)) {
            continue;
        }
        // SpynetReporting=0 means cloud protection off; the Disable* ones mean
        // off when non-zero.
        int is_off = (strcmp(offsw[i].value, "SpynetReporting") == 0) ? (v == 0) : (v != 0);
        off += (unsigned)is_off;
        if (c.mode == 0) {
            printf("  %-7s %-28s = %lu%s\n", offsw[i].src, offsw[i].value, (unsigned long)v,
                   is_off ? "   [PROTECTION OFF]" : "");
        } else if (c.mode == 1) {
            printf("%s{\"source\":\"%s\",\"name\":", pfirst ? "" : ",", offsw[i].src);
            json_str(offsw[i].value);
            printf(",\"value\":%lu,\"protection_off\":%s}", (unsigned long)v,
                   is_off ? "true" : "false");
            pfirst = 0;
        }
        // CSV carries only the exclusion table; policies are text/JSON only.
    }

    if (c.mode == 1) {
        printf("],\"access_denied\":%s}\n", c.denied ? "true" : "false");
    } else if (c.mode == 0) {
        printf("\n%u switch(es) disabling protection\n", off);
    }
    regsrc_close(&src);
    return 0;
}
