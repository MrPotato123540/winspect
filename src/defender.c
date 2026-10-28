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
// data Get-MpPreference shows). We also report the policy DWORDs that disable
// protection outright (DisableAntiSpyware, DisableRealtimeMonitoring, ...).
//
// Read-only: keys are opened with KEY_READ and nothing is ever written. Since
// Windows 10 the local Exclusions keys are readable only by administrators, so
// ERROR_ACCESS_DENIED is reported as "access denied" rather than "no entries" -
// silently showing an empty list would be misleading.

#include "defender.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define DEF_LOCAL  "SOFTWARE\\Microsoft\\Windows Defender"
#define DEF_POLICY "SOFTWARE\\Policies\\Microsoft\\Windows Defender"

typedef struct {
    int mode;           // 0 text, 1 json, 2 csv
    int first;          // JSON comma management
    unsigned count;     // exclusions printed
    int denied;         // any key we could not read
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

// List every value name under <base>\Exclusions\<kind>.
static void enum_exclusions(def_ctx *c, const char *base, const char *source,
                            const char *kind)
{
    WCHAR wpath[256];
    char path[256];
    snprintf(path, sizeof path, "%s\\Exclusions\\%s", base, kind);
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 256);

    HKEY k;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, wpath, 0, KEY_READ | KEY_WOW64_64KEY, &k);
    if (rc == ERROR_FILE_NOT_FOUND) {
        return;     // key absent = no exclusions of this kind
    }
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED) {
            c->denied = 1;
            if (c->mode == 0) {
                printf("  %-7s %-12s (access denied - run elevated to read)\n", source, kind);
            }
        }
        return;
    }
    for (DWORD i = 0;; i++) {
        WCHAR name[1024];
        DWORD nlen = sizeof name / sizeof name[0];
        rc = RegEnumValueW(k, i, name, &nlen, NULL, NULL, NULL, NULL);
        if (rc == ERROR_MORE_DATA) {
            continue;   // absurdly long name: skip it, keep going
        }
        if (rc != ERROR_SUCCESS) {
            break;      // ERROR_NO_MORE_ITEMS (or a hard error) ends the list
        }
        char u8[2048];
        int got = WideCharToMultiByte(CP_UTF8, 0, name, (int)nlen, u8, sizeof u8 - 1, NULL, NULL);
        u8[(got > 0) ? got : 0] = '\0';
        if (u8[0] == '\0') {
            continue;   // the unnamed "(Default)" value is not an exclusion
        }
        emit(c, source, kind, u8);
        c->count++;
    }
    RegCloseKey(k);
}

// Read a DWORD policy switch; returns 1 and fills *out when it exists.
static int read_dword(const char *subkey, const char *value, DWORD *out)
{
    // Open with KEY_WOW64_64KEY ourselves (rather than RegGetValue's
    // RRF_SUBKEY_WOW6464KEY, which older Windows builds reject) so a 32-bit
    // build still sees the real 64-bit policy keys.
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &k)
            != ERROR_SUCCESS) {
        return 0;
    }
    DWORD sz = sizeof *out;
    LONG rc = RegGetValueA(k, NULL, value, RRF_RT_REG_DWORD, NULL, out, &sz);
    RegCloseKey(k);
    return rc == ERROR_SUCCESS;
}

int cmd_defender(int argc, char **argv)
{
    def_ctx c = { 0, 1, 0, 0 };
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else {
            fprintf(stderr, "defender: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    static const char *kinds[] = { "Paths", "Extensions", "Processes", "IpAddresses" };

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
    static const struct { const char *key, *value; } offsw[] = {
        { DEF_POLICY,                              "DisableAntiSpyware" },
        { DEF_POLICY,                              "DisableAntiVirus" },
        { DEF_POLICY "\\Real-Time Protection",     "DisableRealtimeMonitoring" },
        { DEF_POLICY "\\Real-Time Protection",     "DisableBehaviorMonitoring" },
        { DEF_POLICY "\\Real-Time Protection",     "DisableIOAVProtection" },
        { DEF_POLICY "\\Spynet",                   "SpynetReporting" },
    };

    if (c.mode == 1) {
        fputs("],\"policies\":[", stdout);
    } else if (c.mode == 0) {
        printf("\n%u exclusion(s)%s\n\npolicy switches (only those that are set)\n",
               c.count, c.denied ? "  - some lists unreadable, run elevated" : "");
    }
    int pfirst = 1;
    unsigned off = 0;
    for (size_t i = 0; i < sizeof offsw / sizeof offsw[0]; i++) {
        DWORD v = 0;
        if (!read_dword(offsw[i].key, offsw[i].value, &v)) {
            continue;
        }
        // SpynetReporting=0 means cloud protection off; the Disable* ones mean
        // off when non-zero.
        int is_off = (strcmp(offsw[i].value, "SpynetReporting") == 0) ? (v == 0) : (v != 0);
        off += (unsigned)is_off;
        if (c.mode == 0) {
            printf("  %-28s = %lu%s\n", offsw[i].value, (unsigned long)v,
                   is_off ? "   [PROTECTION OFF]" : "");
        } else if (c.mode == 1) {
            printf("%s{\"name\":", pfirst ? "" : ",");
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
    return 0;
}
