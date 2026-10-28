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
// Read-only: only RegGetValue. The AutoLogon check reports whether a
// DefaultPassword value EXISTS and never reads or prints its content.

#include "posture.h"
#include "artparse.h"
#include "jsonutil.h"

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
      "not set - Windows 10 1709+ ships without SMBv1 server" },
    { "Network", "LLMNR", HKEY_LOCAL_MACHINE,
      "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast",
      PR_GOOD_IF_EQ, 0, POSTURE_INFO,
      "LLMNR disabled by policy", "LLMNR enabled (name-poisoning risk on local networks)",
      "not disabled by policy - LLMNR is on by default (name-poisoning risk)" },
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
};

static const char *status_name(posture_status s)
{
    return s == POSTURE_OK ? "OK" : s == POSTURE_WARN ? "WARN" : "INFO";
}

static int read_dword(HKEY root, const char *key, const char *value, DWORD *out)
{
    DWORD sz = sizeof *out;
    HKEY k;
    if (RegOpenKeyExA(root, key, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) {
        return 0;
    }
    LONG rc = RegGetValueA(k, NULL, value, RRF_RT_REG_DWORD, NULL, out, &sz);
    RegCloseKey(k);
    return rc == ERROR_SUCCESS;
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

int cmd_posture(int argc, char **argv)
{
    pctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "--warn") == 0) c.only_warn = 1;
        else {
            fprintf(stderr, "posture: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    if (c.mode == 0) {
        puts("posture  (host hardening checks, read-only)\n");
        printf("  %-4s  %-12s %-32s %-10s %s\n", "", "area", "check", "value", "meaning");
    } else if (c.mode == 2) {
        puts("status,area,check,value,detail");
    } else {
        putchar('[');
    }

    for (size_t i = 0; i < sizeof rules / sizeof rules[0]; i++) {
        const posture_rule *r = &rules[i];
        DWORD v = 0;
        int present = read_dword(r->root, r->key, r->value, &v);
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
    {
        HKEY k;
        int autologon = 0, has_pw = 0;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                          0, KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
            char al[8] = "";
            DWORD sz = sizeof al;
            if (RegGetValueA(k, NULL, "AutoAdminLogon", RRF_RT_REG_SZ, NULL, al, &sz) == ERROR_SUCCESS) {
                autologon = (strcmp(al, "1") == 0);
            }
            // Query only the size (NULL data buffer): the password is never read.
            has_pw = RegQueryValueExA(k, "DefaultPassword", NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
            RegCloseKey(k);
        }
        posture_status st = has_pw ? POSTURE_WARN : (autologon ? POSTURE_INFO : POSTURE_OK);
        emit(&c, "Credentials", "AutoLogon password", has_pw ? "present" : (autologon ? "on" : "off"), st,
             has_pw ? "Winlogon DefaultPassword holds a PLAINTEXT password"
                    : (autologon ? "AutoAdminLogon on (password stored elsewhere)" : "no AutoLogon password in the registry"));
    }

    if (c.mode == 0) {
        printf("\n%u OK, %u WARN, %u INFO\n", c.ok, c.warn, c.info);
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
