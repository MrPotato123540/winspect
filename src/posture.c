// winspect posture - "how hardened is this machine?" in one read-only pass
//
// Many host weaknesses are a single registry value away: WDigest keeping
// passwords in memory, UAC set to elevate without asking, NTLMv1 allowed,
// AlwaysInstallElevated letting any user install MSIs as SYSTEM, an AutoLogon
// password sitting in Winlogon. Hardening guides (CIS, Microsoft security
// baselines) and audit tools check exactly these; the concept comes from tools
// like HardeningKitty / PsInfo, the rule table is ours.
//
// Each rule names a DWORD, how to judge it (posture_judge in artparse.c,
// unit-tested) and what to report when the value is absent - Windows defaults
// differ per setting, so the "missing" verdict is explicit per rule.
//
// Offline: --software / --system / --ntuser judge hive FILES from another
// machine (or an image) with the same rules; rules whose hive was not given
// are skipped.
//
// Read-only. The AutoLogon check reports whether a DefaultPassword value
// EXISTS and never reads or prints its content (live or offline).

#include "posture.h"
#include "artparse.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *area;
    const char *name;
    HKEY root;
    const char *key;
    const char *value;
    posture_op op;
    uint32_t arg;
    posture_status missing;
    const char *ok_text;        // shown for OK
    const char *warn_text;      // shown for WARN
    const char *unset_text;     // shown when the value is absent (NULL: by status)
} posture_rule;

#define LSA   "SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define UACK  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define FWP   "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\"
#define TS    "SYSTEM\\CurrentControlSet\\Control\\Terminal Server"

static const posture_rule rules[] = {
    { "UAC", "UAC enabled", HKEY_LOCAL_MACHINE, UACK, "EnableLUA",
      PR_GOOD_IF_EQ, 1, POSTURE_OK,
      "User Account Control is on", "UAC is OFF: every admin process runs fully elevated", NULL },
    { "UAC", "Admin consent prompt", HKEY_LOCAL_MACHINE, UACK, "ConsentPromptBehaviorAdmin",
      PR_BAD_IF_EQ, 0, POSTURE_OK,
      "admins are prompted before elevation", "admins elevate WITHOUT any prompt", NULL },
    { "UAC", "Secure desktop prompt", HKEY_LOCAL_MACHINE, UACK, "PromptOnSecureDesktop",
      PR_BAD_IF_EQ, 0, POSTURE_OK,
      "elevation prompt on the secure desktop", "elevation prompt on the normal desktop (spoofable)", NULL },

    { "Credentials", "LSA protection (RunAsPPL)", HKEY_LOCAL_MACHINE, LSA, "RunAsPPL",
      PR_GOOD_IF_NONZERO, 0, POSTURE_WARN,
      "lsass runs as a protected process", "lsass is not protected: memory can be read by admin tools", NULL },
    { "Credentials", "WDigest cleartext", HKEY_LOCAL_MACHINE,
      "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential",
      PR_BAD_IF_EQ, 1, POSTURE_OK,
      "WDigest does not keep cleartext passwords", "WDigest keeps CLEARTEXT passwords in lsass memory", NULL },
    { "Credentials", "NTLM level", HKEY_LOCAL_MACHINE, LSA, "LmCompatibilityLevel",
      PR_GOOD_IF_GE, 3, POSTURE_OK,
      "NTLMv2 only (LM/NTLMv1 not sent)", "LM / NTLMv1 responses may be sent", NULL },
    { "Credentials", "LM hash storage", HKEY_LOCAL_MACHINE, LSA, "NoLMHash",
      PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "LM hashes are not stored", "LM hashes ARE stored for new passwords (trivially crackable)",
      "not set - Windows Vista+ default does not store LM hashes" },
    { "Credentials", "Anonymous SAM enumeration", HKEY_LOCAL_MACHINE, LSA, "RestrictAnonymousSAM",
      PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "anonymous users cannot list SAM accounts", "anonymous users can list local accounts",
      "not set - Windows default restricts it" },
    { "Credentials", "Credential Guard", HKEY_LOCAL_MACHINE, LSA, "LsaCfgFlags",
      PR_GOOD_IF_NONZERO, 0, POSTURE_INFO,
      "Credential Guard configured (isolated LSA)", "Credential Guard explicitly disabled",
      "not configured here (Windows 11 22H2+ may enable it by default on capable hardware)" },
    { "Credentials", "Remote local-admin token", HKEY_LOCAL_MACHINE, UACK, "LocalAccountTokenFilterPolicy",
      PR_BAD_IF_EQ, 1, POSTURE_OK,
      "remote logons with local admin accounts get a filtered token",
      "remote logons with LOCAL admin accounts get a full token (eases pass-the-hash lateral movement)",
      NULL },

    { "Privilege", "AlwaysInstallElevated (HKLM)", HKEY_LOCAL_MACHINE,
      "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "AlwaysInstallElevated",
      PR_BAD_IF_EQ, 1, POSTURE_OK,
      "MSI packages do not auto-elevate", "MSI packages install as SYSTEM (needs HKCU too)", NULL },
    { "Privilege", "AlwaysInstallElevated (HKCU)", HKEY_CURRENT_USER,
      "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "AlwaysInstallElevated",
      PR_BAD_IF_EQ, 1, POSTURE_OK,
      "MSI packages do not auto-elevate", "MSI packages install as SYSTEM (if HKLM is set too)", NULL },

    { "Network", "SMBv1 client driver", HKEY_LOCAL_MACHINE,
      "SYSTEM\\CurrentControlSet\\Services\\mrxsmb10", "Start",
      PR_GOOD_IF_EQ, 4, POSTURE_OK,
      "SMBv1 client disabled / not installed", "SMBv1 client is enabled (legacy, wormable protocol)", NULL },
    { "Network", "SMBv1 server", HKEY_LOCAL_MACHINE,
      "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB1",
      PR_BAD_IF_EQ, 1, POSTURE_INFO,
      "SMBv1 server not enabled", "SMBv1 server is enabled",
      "not set - default ON up to Windows 8.1 / 10 1703, removed from 10 1709+" },
    { "Network", "LLMNR", HKEY_LOCAL_MACHINE,
      "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast",
      PR_GOOD_IF_EQ, 0, POSTURE_INFO,
      "LLMNR disabled by policy", "LLMNR enabled (name-poisoning risk on local networks)",
      "not disabled by policy - LLMNR is on by default (name-poisoning risk)" },
    { "Network", "SMB signing required (server)", HKEY_LOCAL_MACHINE,
      "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "RequireSecuritySignature",
      PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "SMB server requires signing", "SMB server does not require signing (NTLM relay to this host)",
      "not set - required by default only on domain controllers and Windows 11 24H2+" },
    { "Network", "SMB signing required (client)", HKEY_LOCAL_MACHINE,
      "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", "RequireSecuritySignature",
      PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "SMB client requires signing", "SMB client does not require signing",
      "not set - required by default only on Windows 11 24H2+" },
    { "Network", "RDP", HKEY_LOCAL_MACHINE, TS, "fDenyTSConnections",
      PR_GOOD_IF_EQ, 1, POSTURE_OK,
      "Remote Desktop connections refused", "Remote Desktop is accepting connections", NULL },
    { "Network", "RDP Network Level Auth", HKEY_LOCAL_MACHINE, TS "\\WinStations\\RDP-Tcp",
      "UserAuthentication", PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "RDP requires NLA", "RDP allows connections without NLA",
      "not set - Windows default requires NLA" },
    { "Network", "Firewall (domain)", HKEY_LOCAL_MACHINE, FWP "DomainProfile", "EnableFirewall",
      PR_GOOD_IF_EQ, 1, POSTURE_INFO, "firewall on", "domain-profile firewall is OFF",
      "not set - Windows default is on" },
    { "Network", "Firewall (private)", HKEY_LOCAL_MACHINE, FWP "StandardProfile", "EnableFirewall",
      PR_GOOD_IF_EQ, 1, POSTURE_INFO, "firewall on", "private-profile firewall is OFF",
      "not set - Windows default is on" },
    { "Network", "Firewall (public)", HKEY_LOCAL_MACHINE, FWP "PublicProfile", "EnableFirewall",
      PR_GOOD_IF_EQ, 1, POSTURE_INFO, "firewall on", "public-profile firewall is OFF",
      "not set - Windows default is on" },

    { "Platform", "Secure Boot", HKEY_LOCAL_MACHINE,
      "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "UEFISecureBootEnabled",
      PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "UEFI Secure Boot is on", "Secure Boot is off",
      "not reported (legacy BIOS boot or no UEFI state)" },
    { "Platform", "Virtualization-based security", HKEY_LOCAL_MACHINE,
      "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", "EnableVirtualizationBasedSecurity",
      PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "VBS configured", "VBS not configured", "VBS not configured" },

    { "Logging", "PowerShell script block logging", HKEY_LOCAL_MACHINE,
      "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
      "EnableScriptBlockLogging", PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "PowerShell script blocks are logged", "PowerShell script block logging not enabled",
      "not enabled by policy - script blocks are not logged" },
    { "Logging", "PowerShell transcription", HKEY_LOCAL_MACHINE,
      "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
      "EnableTranscripting", PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "PowerShell sessions are transcribed to files", "PowerShell transcription not enabled",
      "not enabled by policy - no session transcripts" },
    { "Logging", "Command line in process events", HKEY_LOCAL_MACHINE, UACK "\\Audit",
      "ProcessCreationIncludeCmdLine_Enabled", PR_GOOD_IF_EQ, 1, POSTURE_INFO,
      "event 4688 includes the command line", "event 4688 omits the command line",
      "not enabled - process creation events (4688) carry no command line" },
};

static const char *status_name(posture_status s)
{
    return s == POSTURE_OK ? "OK" : s == POSTURE_WARN ? "WARN" : "INFO";
}

typedef struct { regsrc *sw, *sys, *cu; char cs[32]; } psrc;

// HKLM\SOFTWARE\..., HKLM\SYSTEM\CurrentControlSet\... or HKCU path -> the
// source holding it and the path inside it (NULL if that hive is absent).
static regsrc *pick(psrc *p, HKEY root, const char *key, char *rel, size_t n)
{
    if (root == HKEY_CURRENT_USER) {
        snprintf(rel, n, "%s", key);        // HKCU rules are written "SOFTWARE\..." too
        return p->cu;
    }
    if (_strnicmp(key, "SOFTWARE\\", 9) == 0) { snprintf(rel, n, "%s", key + 9); return p->sw; }
    if (_strnicmp(key, "SYSTEM\\CurrentControlSet\\", 25) == 0) {
        snprintf(rel, n, "%s\\%s", p->cs, key + 25);
        return p->sys;
    }
    return NULL;
}

// 1 = value present (in *out), 0 = absent, -1 = that hive is not available.
static int read_dword(psrc *p, HKEY root, const char *key, const char *value, DWORD *out)
{
    char rel[512];
    regsrc *s = pick(p, root, key, rel, sizeof rel);
    if (s == NULL) return -1;
    rkey k;
    if (rk_open(s, rel, &k) != 0) return 0;
    unsigned char d[4];
    uint32_t type = 0;
    int ok = rk_get(s, &k, value, &type, d, 4) == 4 && type == REG_DWORD;
    rk_close(&k);
    if (ok) *out = (DWORD)d[0] | ((DWORD)d[1] << 8) | ((DWORD)d[2] << 16) | ((DWORD)d[3] << 24);
    return ok;
}

typedef struct { int mode, only_warn, first; unsigned ok, warn, info; } pctx;

static void emit(pctx *c, const char *area, const char *name, const char *value,
                 posture_status st, const char *text)
{
    if (st == POSTURE_OK) c->ok++; else if (st == POSTURE_WARN) c->warn++; else c->info++;
    if (c->only_warn && st != POSTURE_WARN) {
        return;
    }
    if (c->mode == 0) {
        printf("  %-4s  %-12s %-32s %-10s %s\n", status_name(st), area, name, value, text);
    } else if (c->mode == 2) {
        csv_str(status_name(st)); putchar(',');
        csv_str(area);  putchar(',');
        csv_str(name);  putchar(',');
        csv_str(value); putchar(',');
        csv_str(text);  putchar('\n');
    } else {
        printf("%s{\"status\":\"%s\",\"area\":", c->first ? "" : ",", status_name(st));
        json_str(area);
        fputs(",\"check\":", stdout);  json_str(name);
        fputs(",\"value\":", stdout);  json_str(value);
        fputs(",\"detail\":", stdout); json_str(text);
        putchar('}');
        c->first = 0;
    }
}

// ---- checks that are lists, not single values ----------------------------------

typedef struct { pctx *c; const char *proto; unsigned n; } pp_ctx;

// One "netsh interface portproxy" rule: value name "listenaddr/port", data
// "connectaddr/port".
static void portproxy_value(const char *name, uint32_t type, const unsigned char *d, size_t len, void *vctx)
{
    pp_ctx *p = (pp_ctx *)vctx;
    if (type != REG_SZ || name[0] == '\0') return;
    char to[160], text[420];
    regsrc_u16(d, len, to, sizeof to);
    snprintf(text, sizeof text, "connections to %s are forwarded to %s (pivot / tunnel when not set up by you)", name, to);
    emit(p->c, "Network", "Port proxy rule", p->proto, POSTURE_WARN, text);
    p->n++;
}

typedef struct { pctx *c; unsigned n; } hid_ctx;

// SpecialAccounts\UserList: a DWORD 0 hides that account from the sign-in
// screen. Used to keep a backdoor account out of sight.
static void hidden_account_value(const char *name, uint32_t type, const unsigned char *d, size_t len, void *vctx)
{
    hid_ctx *h = (hid_ctx *)vctx;
    if (type != REG_DWORD || len < 4 || (d[0] | d[1] | d[2] | d[3]) != 0 || name[0] == '\0') return;
    char text[300];
    snprintf(text, sizeof text, "account '%.120s' is hidden from the sign-in screen", name);
    emit(h->c, "Accounts", "Hidden account", "hidden", POSTURE_WARN, text);
    h->n++;
}

static void list_checks(pctx *c, psrc *ps)
{
    char rel[512];
    regsrc *s;
    rkey k;

    // Port forwards configured with "netsh interface portproxy". Normal
    // machines have none; an attacker adds one to reach an internal host (or
    // RDP) through this machine.
    if ((s = pick(ps, HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\PortProxy", rel, sizeof rel)) != NULL) {
        static const char *const fam[] = { "v4tov4", "v4tov6", "v6tov4", "v6tov6", NULL };
        pp_ctx pp = { c, "", 0 };
        for (int i = 0; fam[i]; i++) {
            char key[600];
            snprintf(key, sizeof key, "%s\\%s\\tcp", rel, fam[i]);
            if (rk_open(s, key, &k) != 0) continue;
            pp.proto = fam[i];
            rk_values(s, &k, portproxy_value, &pp);
            rk_close(&k);
        }
        if (pp.n == 0) emit(c, "Network", "Port proxy rules", "none", POSTURE_OK, "no port forwarding (portproxy) rules");
    }

    // Named pipes reachable WITHOUT authentication. Empty on current Windows;
    // domain controllers list netlogon / samr / lsarpc.
    if ((s = pick(ps, HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", rel, sizeof rel)) != NULL &&
            rk_open(s, rel, &k) == 0) {
        unsigned char data[2048];
        uint32_t type = 0;
        long len = rk_get(s, &k, "NullSessionPipes", &type, data, sizeof data);
        rk_close(&k);
        char names[512] = "";
        size_t o = 0;
        int other = 0, count = 0;
        if (len > 0 && type == REG_MULTI_SZ) {
            size_t n = (size_t)len < sizeof data ? (size_t)len : sizeof data;
            for (size_t i = 0; i + 1 < n;) {
                size_t j = i;
                while (j + 1 < n && (data[j] | data[j + 1])) j += 2;
                if (j == i) break;
                char item[96];
                regsrc_u16(data + i, j - i, item, sizeof item);
                if (item[0]) {
                    count++;
                    if (_stricmp(item, "netlogon") != 0 && _stricmp(item, "samr") != 0 && _stricmp(item, "lsarpc") != 0) other = 1;
                    int w = snprintf(names + o, sizeof names - o, "%s%s", o ? ", " : "", item);
                    if (w > 0 && (size_t)w < sizeof names - o) o += (size_t)w;
                }
                i = j + 2;
            }
        }
        char text[640];
        if (count == 0) emit(c, "Network", "Null session pipes", "none", POSTURE_OK, "no named pipe is reachable anonymously");
        else {
            snprintf(text, sizeof text, "pipes reachable without authentication: %s%s", names, other ? "" : " (the domain-controller set)");
            emit(c, "Network", "Null session pipes", "set", other ? POSTURE_WARN : POSTURE_INFO, text);
        }
    }

    // Accounts hidden from the sign-in screen.
    if ((s = pick(ps, HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList", rel, sizeof rel)) != NULL) {
        hid_ctx h = { c, 0 };
        if (rk_open(s, rel, &k) == 0) {
            rk_values(s, &k, hidden_account_value, &h);
            rk_close(&k);
        }
        if (h.n == 0) emit(c, "Accounts", "Hidden accounts", "none", POSTURE_OK, "no account is hidden from the sign-in screen");
    }

    // Windows Update pointed at an internal server over plain HTTP: update
    // metadata can be altered on the network ("WSUS spoofing").
    if ((s = pick(ps, HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", rel, sizeof rel)) != NULL) {
        char url[300] = "";
        if (rk_open(s, rel, &k) == 0) {
            rk_get_str(s, &k, "WUServer", url, sizeof url);
            rk_close(&k);
        }
        DWORD use = 0;
        int have = read_dword(ps, HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "UseWUServer", &use);
        char text[420];
        if (url[0] == '\0' || have != 1 || use != 1) {
            emit(c, "Updates", "Update server", "default", POSTURE_OK, "updates come from Microsoft (no WSUS server configured)");
        } else if (_strnicmp(url, "http://", 7) == 0) {
            snprintf(text, sizeof text, "updates come from %.200s over plain HTTP: they can be tampered with on the network", url);
            emit(c, "Updates", "Update server", "http", POSTURE_WARN, text);
        } else {
            snprintf(text, sizeof text, "updates come from the internal server %.200s", url);
            emit(c, "Updates", "Update server", "wsus", POSTURE_OK, text);
        }
    }

    // RDP session shadowing without the user's consent (2 = full control, 4 = view).
    {
        DWORD v = 0;
        int have = read_dword(ps, HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", "Shadow", &v);
        if (have >= 0) {
            char val[16];
            snprintf(val, sizeof val, have ? "%lu" : "(unset)", (unsigned long)v);
            if (have == 1 && (v == 2 || v == 4))
                emit(c, "Network", "RDP shadowing", val, POSTURE_WARN, v == 2 ? "sessions can be CONTROLLED remotely without the user's consent"
                                                                              : "sessions can be VIEWED remotely without the user's consent");
            else emit(c, "Network", "RDP shadowing", val, POSTURE_OK, "sessions cannot be shadowed without consent");
        }
    }

    // Sysmon: if present, far richer process / network telemetry exists in
    // Microsoft-Windows-Sysmon/Operational than in the Security log.
    if ((s = pick(ps, HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", rel, sizeof rel)) != NULL) {
        static const char *const svc[] = { "SysmonDrv", "Sysmon64", "Sysmon", NULL };
        int found = 0;
        for (int i = 0; svc[i] && !found; i++) {
            char key[600];
            snprintf(key, sizeof key, "%s\\%s", rel, svc[i]);
            if (rk_open(s, key, &k) == 0) { found = 1; rk_close(&k); }
        }
        emit(c, "Logging", "Sysmon", found ? "installed" : "absent", POSTURE_INFO,
             found ? "Sysmon is installed: see its Operational log for process / network events" : "Sysmon is not installed");
    }
}

int cmd_posture(int argc, char **argv)
{
    pctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *files[3] = { NULL, NULL, NULL };
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "--warn") == 0) c.only_warn = 1;
        else if (strcmp(argv[a], "--software") == 0 && a + 1 < argc) files[0] = argv[++a];
        else if (strcmp(argv[a], "--system") == 0 && a + 1 < argc)   files[1] = argv[++a];
        else if (strcmp(argv[a], "--ntuser") == 0 && a + 1 < argc)   files[2] = argv[++a];
        else {
            fprintf(stderr, "posture: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    static regsrc srcs[3];
    psrc ps = { NULL, NULL, NULL, "" };
    int offline = files[0] || files[1] || files[2];
    if (offline) {
        for (int i = 0; i < 3; i++) {
            if (files[i] == NULL) continue;
            char err[512];
            if (regsrc_open_hive(&srcs[i], files[i], err, sizeof err) != 0) {
                fprintf(stderr, "posture: %s\n", err);
                for (int j = 0; j < i; j++) if (files[j]) regsrc_close(&srcs[j]);
                return 1;
            }
        }
        ps.sw = files[0] ? &srcs[0] : NULL;
        ps.sys = files[1] ? &srcs[1] : NULL;
        ps.cu = files[2] ? &srcs[2] : NULL;
    } else {
        if (regsrc_open_live(&srcs[0], HKEY_LOCAL_MACHINE, "SOFTWARE", "HKLM\\SOFTWARE") == 0) ps.sw = &srcs[0];
        if (regsrc_open_live(&srcs[1], HKEY_LOCAL_MACHINE, "SYSTEM", "HKLM\\SYSTEM") == 0) ps.sys = &srcs[1];
        regsrc_open_live(&srcs[2], HKEY_CURRENT_USER, NULL, "HKCU");
        ps.cu = &srcs[2];
    }
    if (ps.sys) regsrc_control_set(ps.sys, ps.cs, sizeof ps.cs);

    if (c.mode == 0) {
        if (offline) printf("posture  (offline hives:%s%s%s%s%s%s)\n\n", files[0] ? " SOFTWARE=" : "",
                            files[0] ? files[0] : "", files[1] ? " SYSTEM=" : "", files[1] ? files[1] : "",
                            files[2] ? " NTUSER=" : "", files[2] ? files[2] : "");
        else puts("posture  (host hardening checks, read-only)\n");
        printf("  %-4s  %-12s %-32s %-10s %s\n", "", "area", "check", "value", "meaning");
    } else if (c.mode == 2) {
        puts("status,area,check,value,detail");
    } else {
        putchar('[');
    }

    for (size_t i = 0; i < sizeof rules / sizeof rules[0]; i++) {
        const posture_rule *r = &rules[i];
        DWORD v = 0;
        int present = read_dword(&ps, r->root, r->key, r->value, &v);
        if (present < 0) continue;                  // that hive was not given (offline)
        posture_status st = posture_judge(r->op, r->arg, present, v, r->missing);
        char val[24];
        if (present) snprintf(val, sizeof val, "%lu", (unsigned long)v);
        else         snprintf(val, sizeof val, "(unset)");
        const char *text = (!present && r->unset_text != NULL) ? r->unset_text
                         : (st == POSTURE_OK ? r->ok_text : r->warn_text);
        emit(&c, r->area, r->name, val, st, text);
    }

    // AutoLogon: Winlogon may hold a plaintext DefaultPassword. We only check
    // that the value EXISTS; its content is never read into this program.
    if (ps.sw) {
        rkey k;
        int autologon = 0, has_pw = 0;
        if (rk_open(ps.sw, "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", &k) == 0) {
            char al[8] = "";
            if (rk_get_str(ps.sw, &k, "AutoAdminLogon", al, sizeof al)) {
                autologon = (strcmp(al, "1") == 0);
            }
            has_pw = rk_exists(ps.sw, &k, "DefaultPassword");
            rk_close(&k);
        }
        posture_status st = has_pw ? POSTURE_WARN : (autologon ? POSTURE_INFO : POSTURE_OK);
        emit(&c, "Credentials", "AutoLogon password", has_pw ? "present" : (autologon ? "on" : "off"), st,
             has_pw ? "Winlogon DefaultPassword holds a PLAINTEXT password"
                    : (autologon ? "AutoAdminLogon on (password stored elsewhere)" : "no AutoLogon password in the registry"));
    }
    list_checks(&c, &ps);
    for (int i = 0; i < 3; i++) {
        if (offline ? files[i] != NULL : 1) regsrc_close(&srcs[i]);
    }

    if (c.mode == 0) {
        printf("\n%u OK, %u WARN, %u INFO\n", c.ok, c.warn, c.info);
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
