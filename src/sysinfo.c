// winspect sysinfo - the "who / what / when" of a machine from its registry
//
// The first page of most investigations (RegRipper's and KAPE's "basic
// system info" idea; only the idea is borrowed): which machine is this, which
// Windows, installed when, shut down when, which time zone, who logged on
// last, which network interfaces with which addresses, which user profiles
// exist, and which networks it has been connected to. All of it lives in two
// hives, so the same code reads the live registry or offline copies:
//
//   SYSTEM   <cs>\Control\ComputerName\ComputerName      ComputerName
//            <cs>\Control\Windows                         ShutdownTime (FILETIME)
//            <cs>\Control\TimeZoneInformation             Bias, StandardName, TimeZoneKeyName
//            <cs>\Services\Tcpip\Parameters\Interfaces\{} IPAddress / DhcpIPAddress, ...
//   SOFTWARE Microsoft\Windows NT\CurrentVersion          ProductName, builds, InstallDate (unix)
//            Microsoft\Windows\CurrentVersion\Authentication\LogonUI  LastLoggedOnUser
//            Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>    ProfileImagePath
//            Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{} ProfileName,
//                     NameType, Category, DateCreated / DateLastConnected (SYSTEMTIME,
//                     LOCAL time)
// Time values are decoded by portable, unit-tested helpers (artparse.c).
// Read-only.

#include "sysinfo.h"
#include "artparse.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    regsrc *sw, *sys;
    char cs[32];
    int json, firstsec;
} sctx;

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

static uint32_t get_dword(regsrc *s, const rkey *k, const char *name, int *found)
{
    unsigned char d[4];
    uint32_t type = 0;
    *found = rk_get(s, k, name, &type, d, 4) == 4 && type == REG_DWORD;
    return *found ? (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24) : 0;
}

// REG_MULTI_SZ (or REG_SZ) joined with ", ".
static void get_multi(regsrc *s, const rkey *k, const char *name, char *out, size_t n)
{
    unsigned char d[2048];
    uint32_t type = 0;
    out[0] = '\0';
    long len = rk_get(s, k, name, &type, d, sizeof d);
    if (len <= 0 || (type != REG_MULTI_SZ && type != REG_SZ)) return;
    size_t L = (size_t)len < sizeof d ? (size_t)len : sizeof d, o = 0;
    for (size_t i = 0; i + 1 < L; ) {
        size_t j = i;
        while (j + 1 < L && (d[j] | d[j + 1])) j += 2;
        if (j == i) break;
        char part[256];
        regsrc_u16(d + i, j - i, part, sizeof part);
        if (part[0] && strcmp(part, "0.0.0.0") != 0) {
            int w = snprintf(out + o, n - o, "%s%s", o ? ", " : "", part);
            if (w < 0 || (size_t)w >= n - o) break;
            o += (size_t)w;
        }
        i = j + 2;
    }
}

// ---- small output helpers: "key: value" in text, "key":"value" in JSON ----
static int firstfield;
static void sec_begin(sctx *c, const char *name, int array)
{
    if (c->json) {
        printf("%s\"%s\":%c", c->firstsec ? "" : ",", name, array ? '[' : '{');
        firstfield = 1;
    } else {
        printf("\n%s\n", name);
    }
    c->firstsec = 0;
}
static void sec_end(sctx *c, int array)
{
    if (c->json) putchar(array ? ']' : '}');
}
static void field(sctx *c, const char *k, const char *v)
{
    if (c->json) {
        printf("%s\"%s\":", firstfield ? "" : ",", k);
        json_str(v);
        firstfield = 0;
    } else if (v[0]) {
        printf("  %-24s %s\n", k, v);
    }
}

static void computer_name(sctx *c)
{
    sec_begin(c, "computer", 0);
    if (c->sys) {
        char p[160], name[256] = "", when[32] = "-";
        snprintf(p, sizeof p, "%s\\Control\\ComputerName\\ComputerName", c->cs);
        rkey k;
        if (rk_open(c->sys, p, &k) == 0) {
            rk_get_str(c->sys, &k, "ComputerName", name, sizeof name);
            ft_str(rk_lastwrite(c->sys, &k), when, sizeof when);
            rk_close(&k);
        }
        field(c, "name", name);
        field(c, "name_key_written", when);
        // Other control sets can hold an OLDER name (machine renamed): show it.
        char others[512] = "";
        size_t ol = 0;
        for (int i = 1; i <= 3; i++) {
            char cs[32], other[256] = "";
            snprintf(cs, sizeof cs, "ControlSet%03d", i);
            if (_stricmp(cs, c->cs) == 0) continue;
            snprintf(p, sizeof p, "%s\\Control\\ComputerName\\ComputerName", cs);
            if (rk_open(c->sys, p, &k) != 0) continue;
            rk_get_str(c->sys, &k, "ComputerName", other, sizeof other);
            rk_close(&k);
            if (other[0] && _stricmp(other, name) != 0) {
                int w = snprintf(others + ol, sizeof others - ol, "%s%s (%s)", ol ? ", " : "", other, cs);
                if (w > 0 && (size_t)w < sizeof others - ol) ol += (size_t)w;
            }
        }
        field(c, "other_names", others);
        char shut[32] = "";
        snprintf(p, sizeof p, "%s\\Control\\Windows", c->cs);
        if (rk_open(c->sys, p, &k) == 0) {
            unsigned char d[8];
            uint32_t type = 0;
            if (rk_get(c->sys, &k, "ShutdownTime", &type, d, 8) == 8) {
                uint64_t t = 0;
                for (int i = 7; i >= 0; i--) t = (t << 8) | d[i];
                ft_str(t, shut, sizeof shut);
            }
            rk_close(&k);
        }
        field(c, "last_shutdown_utc", shut);
        snprintf(p, sizeof p, "%s\\Control\\TimeZoneInformation", c->cs);
        if (rk_open(c->sys, p, &k) == 0) {
            char tz[256] = "", off[32] = "";
            int f;
            if (!rk_get_str(c->sys, &k, "TimeZoneKeyName", tz, sizeof tz) || tz[0] == '\0')
                rk_get_str(c->sys, &k, "StandardName", tz, sizeof tz);
            int32_t bias = (int32_t)get_dword(c->sys, &k, "Bias", &f);
            if (f) snprintf(off, sizeof off, "UTC%+d:%02d", -bias / 60, (bias < 0 ? -bias : bias) % 60);
            field(c, "time_zone", tz);
            field(c, "utc_offset_standard", off);
            rk_close(&k);
        }
    }
    sec_end(c, 0);
}

static void windows_version(sctx *c)
{
    sec_begin(c, "windows", 0);
    rkey k;
    if (c->sw && rk_open(c->sw, "Microsoft\\Windows NT\\CurrentVersion", &k) == 0) {
        static const char *const names[] = { "ProductName", "EditionID", "DisplayVersion", "CurrentVersion",
            "CurrentBuild", "CSDVersion", "BuildLabEx", "InstallationType", "RegisteredOwner",
            "RegisteredOrganization", "ProductId", NULL };
        for (int i = 0; names[i]; i++) {
            char v[256] = "";
            rk_get_str(c->sw, &k, names[i], v, sizeof v);
            field(c, names[i], v);
        }
        int f;
        uint32_t ubr = get_dword(c->sw, &k, "UBR", &f);
        char ubrs[16] = "";
        if (f) snprintf(ubrs, sizeof ubrs, "%lu", (unsigned long)ubr);
        field(c, "UBR", ubrs);
        uint32_t inst = get_dword(c->sw, &k, "InstallDate", &f);
        char when[32] = "";
        if (f) unix_time_str(inst, when, sizeof when);
        field(c, "install_date_utc", when);
        rk_close(&k);
    }
    if (c->sw && rk_open(c->sw, "Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI", &k) == 0) {
        char u[256] = "", sam[256] = "", when[32];
        rk_get_str(c->sw, &k, "LastLoggedOnUser", u, sizeof u);
        rk_get_str(c->sw, &k, "LastLoggedOnSAMUser", sam, sizeof sam);
        ft_str(rk_lastwrite(c->sw, &k), when, sizeof when);
        field(c, "last_logged_on_user", u);
        field(c, "last_logged_on_sam_user", sam);
        field(c, "last_logon_key_written", when);
        rk_close(&k);
    }
    sec_end(c, 0);
}

typedef struct { char n[256][128]; int count; } names_t;
static void name_cb(const char *name, void *vctx)
{
    names_t *l = (names_t *)vctx;
    if (l->count < 256) snprintf(l->n[l->count++], sizeof l->n[0], "%s", name);
}

static int firstrow;
static void row_begin(sctx *c) { if (c->json) { printf("%s{", firstrow ? "" : ","); firstfield = 1; } firstrow = 0; }
static void row_end(sctx *c)   { if (c->json) putchar('}'); else putchar('\n'); }

static void interfaces(sctx *c)
{
    sec_begin(c, "interfaces", 1);
    firstrow = 1;
    char base[160];
    snprintf(base, sizeof base, "%s\\Services\\Tcpip\\Parameters\\Interfaces", c->cs);
    rkey k;
    static names_t ifs;
    ifs.count = 0;
    if (c->sys && rk_open(c->sys, base, &k) == 0) {
        rk_subkeys(c->sys, &k, name_cb, &ifs);
        rk_close(&k);
    }
    for (int i = 0; i < ifs.count; i++) {
        char p[320];
        snprintf(p, sizeof p, "%s\\%s", base, ifs.n[i]);
        if (rk_open(c->sys, p, &k) != 0) continue;
        int f;
        int dhcp = get_dword(c->sys, &k, "EnableDHCP", &f) != 0;
        char ip[512], mask[512], gw[512], dns[512] = "", dom[256] = "", when[32];
        get_multi(c->sys, &k, dhcp ? "DhcpIPAddress" : "IPAddress", ip, sizeof ip);
        get_multi(c->sys, &k, dhcp ? "DhcpSubnetMask" : "SubnetMask", mask, sizeof mask);
        get_multi(c->sys, &k, dhcp ? "DhcpDefaultGateway" : "DefaultGateway", gw, sizeof gw);
        if (!rk_get_str(c->sys, &k, "NameServer", dns, sizeof dns) || dns[0] == '\0')
            rk_get_str(c->sys, &k, "DhcpNameServer", dns, sizeof dns);
        if (!rk_get_str(c->sys, &k, "Domain", dom, sizeof dom) || dom[0] == '\0')
            rk_get_str(c->sys, &k, "DhcpDomain", dom, sizeof dom);
        ft_str(rk_lastwrite(c->sys, &k), when, sizeof when);
        rk_close(&k);
        if (ip[0] == '\0' && gw[0] == '\0' && dns[0] == '\0') continue;   // unused adapter
        row_begin(c);
        if (!c->json) printf("  %s\n", ifs.n[i]);
        field(c, "interface", c->json ? ifs.n[i] : "");
        field(c, "dhcp", dhcp ? "yes" : "no");
        field(c, "ip_address", ip);
        field(c, "subnet_mask", mask);
        field(c, "default_gateway", gw);
        field(c, "name_server", dns);
        field(c, "domain", dom);
        field(c, "key_written", when);
        row_end(c);
    }
    sec_end(c, 1);
}

static void profiles(sctx *c)
{
    sec_begin(c, "profiles", 1);
    firstrow = 1;
    if (!c->json) printf("  %-46s %-19s %s\n", "sid", "last load or key (UTC)", "path");
    static const char *base = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    rkey k;
    static names_t sids;
    sids.count = 0;
    if (c->sw && rk_open(c->sw, base, &k) == 0) {
        rk_subkeys(c->sw, &k, name_cb, &sids);
        rk_close(&k);
    }
    for (int i = 0; i < sids.count; i++) {
        char p[320], path[512] = "", when[32], load[32] = "";
        snprintf(p, sizeof p, "%s\\%s", base, sids.n[i]);
        if (rk_open(c->sw, p, &k) != 0) continue;
        rk_get_str(c->sw, &k, "ProfileImagePath", path, sizeof path);
        ft_str(rk_lastwrite(c->sw, &k), when, sizeof when);
        int fh, fl;
        uint32_t hi = get_dword(c->sw, &k, "LocalProfileLoadTimeHigh", &fh);
        uint32_t lo = get_dword(c->sw, &k, "LocalProfileLoadTimeLow", &fl);
        if (fh && fl) ft_str(((uint64_t)hi << 32) | lo, load, sizeof load);
        rk_close(&k);
        row_begin(c);
        if (c->json) {
            field(c, "sid", sids.n[i]);
            field(c, "path", path);
            field(c, "key_written", when);
            field(c, "last_load_utc", load);
        } else {
            printf("  %-46s %-19s %s", sids.n[i], load[0] ? load : when, path);
        }
        row_end(c);
    }
    sec_end(c, 1);
}

static void networks(sctx *c)
{
    sec_begin(c, "networks", 1);
    firstrow = 1;
    if (!c->json) puts("  (NetworkList; first/last connected are the machine's LOCAL time)");
    static const char *base = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles";
    rkey k;
    static names_t guids;
    guids.count = 0;
    if (c->sw && rk_open(c->sw, base, &k) == 0) {
        rk_subkeys(c->sw, &k, name_cb, &guids);
        rk_close(&k);
    }
    for (int i = 0; i < guids.count; i++) {
        char p[320], name[256] = "", desc[256] = "", created[32] = "", last[32] = "";
        snprintf(p, sizeof p, "%s\\%s", base, guids.n[i]);
        if (rk_open(c->sw, p, &k) != 0) continue;
        rk_get_str(c->sw, &k, "ProfileName", name, sizeof name);
        rk_get_str(c->sw, &k, "Description", desc, sizeof desc);
        int f1, f2;
        uint32_t nt = get_dword(c->sw, &k, "NameType", &f1);
        uint32_t cat = get_dword(c->sw, &k, "Category", &f2);
        unsigned char st[16];
        uint32_t type = 0;
        if (rk_get(c->sw, &k, "DateCreated", &type, st, 16) == 16) systemtime_str(st, 16, created, sizeof created);
        if (rk_get(c->sw, &k, "DateLastConnected", &type, st, 16) == 16) systemtime_str(st, 16, last, sizeof last);
        rk_close(&k);
        row_begin(c);
        if (c->json) {
            field(c, "profile_guid", guids.n[i]);
            field(c, "name", name);
            field(c, "description", desc);
            field(c, "type", f1 ? netlist_name_type(nt) : "");
            field(c, "category", f2 ? netlist_category(cat) : "");
            field(c, "first_connected_local", created);
            field(c, "last_connected_local", last);
        } else {
            printf("  %-32s %-9s %-8s first %-19s  last %s", name, f1 ? netlist_name_type(nt) : "?",
                   f2 ? netlist_category(cat) : "?", created[0] ? created : "-", last[0] ? last : "-");
        }
        row_end(c);
    }
    sec_end(c, 1);
}

int cmd_sysinfo(int argc, char **argv)
{
    sctx c;
    memset(&c, 0, sizeof c);
    c.firstsec = 1;
    const char *hsw = NULL, *hsys = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) c.json = 1;
        else if (strcmp(argv[a], "--software") == 0 && a + 1 < argc) hsw = argv[++a];
        else if (strcmp(argv[a], "--system") == 0 && a + 1 < argc)   hsys = argv[++a];
        else {
            fprintf(stderr, "sysinfo: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    static regsrc sw, sys;
    int offline = hsw || hsys;
    char err[512];
    if (offline) {
        if (hsw && regsrc_open_hive(&sw, hsw, err, sizeof err) != 0) { fprintf(stderr, "sysinfo: %s\n", err); return 1; }
        if (hsys && regsrc_open_hive(&sys, hsys, err, sizeof err) != 0) {
            fprintf(stderr, "sysinfo: %s\n", err);
            if (hsw) regsrc_close(&sw);
            return 1;
        }
        c.sw = hsw ? &sw : NULL;
        c.sys = hsys ? &sys : NULL;
    } else {
        c.sw = regsrc_open_live(&sw, HKEY_LOCAL_MACHINE, "SOFTWARE", "HKLM\\SOFTWARE") == 0 ? &sw : NULL;
        c.sys = regsrc_open_live(&sys, HKEY_LOCAL_MACHINE, "SYSTEM", "HKLM\\SYSTEM") == 0 ? &sys : NULL;
    }
    if (c.sys) regsrc_control_set(c.sys, c.cs, sizeof c.cs);

    if (c.json) {
        putchar('{');
    } else {
        printf("sysinfo  (%s%s%s)\n", c.sys ? c.sys->label : "no SYSTEM", c.sw ? " + " : "", c.sw ? c.sw->label : "");
    }
    computer_name(&c);
    windows_version(&c);
    interfaces(&c);
    profiles(&c);
    networks(&c);
    if (c.json) puts("}");
    if (c.sw) regsrc_close(&sw);
    if (c.sys) regsrc_close(&sys);
    return 0;
}
