// winspect firewall - firewall rules from the registry
//
// Windows Defender Firewall persists every rule as one REG_SZ value:
//   local:  HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
//   policy: HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules
// The value name is the rule id; the data is a '|'-separated list such as
//   v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=C:\x.exe|
//   Name=@FirewallAPI.dll,-28753|...
// Reading the registry (instead of the INetFwPolicy2 COM API) keeps this a
// plain, dependency-free view of exactly what is stored. Names of built-in
// rules are "indirect strings" (@dll,-id); SHLoadIndirectString turns them
// into readable text, the same way the Firewall UI does.
//
// What we flag: an ACTIVE, INBOUND, ALLOW rule whose program lives in a
// user-writable directory. Malware that wants to listen for connections
// commonly adds exactly such a rule for itself. This is a hint for review.
//
// Read-only: values are enumerated and read; no rule is ever created/changed.

#include "firewall.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int mode;
    int only_in, only_allow, only_active, only_flagged;
    int first;
    unsigned shown, flagged;
} fw_ctx;

static const char *proto_name(const char *num)
{
    if (strcmp(num, "6") == 0)  return "TCP";
    if (strcmp(num, "17") == 0) return "UDP";
    if (strcmp(num, "1") == 0)  return "ICMPv4";
    if (strcmp(num, "58") == 0) return "ICMPv6";
    return num[0] ? num : "any";
}

// Resolve "@FirewallAPI.dll,-28753" style names; leaves plain names as-is.
static void resolve_name(char *name, size_t n)
{
    if (name[0] != '@') {
        return;
    }
    WCHAR win[512], wout[512];
    if (MultiByteToWideChar(CP_UTF8, 0, name, -1, win, 512) == 0) {
        return;
    }
    if (SHLoadIndirectString(win, wout, 512, NULL) == S_OK) {
        WideCharToMultiByte(CP_UTF8, 0, wout, -1, name, (int)n, NULL, NULL);
        name[n - 1] = '\0';
    }
}

static void enum_store(fw_ctx *c, const char *subkey, const char *source)
{
    HKEY k;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &k);
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "firewall: %s rule store: access denied\n", source);
        }
        return;     // not found = no rules in this store (normal for policy)
    }
    DWORD maxname = 0, maxdata = 0;
    RegQueryInfoKeyW(k, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &maxname, &maxdata, NULL, NULL);
    WCHAR *wname = (WCHAR *)malloc((maxname + 1) * sizeof(WCHAR));
    // maxdata is in bytes; round up to whole WCHARs plus two for our terminator.
    WCHAR *wdata = (WCHAR *)malloc(((size_t)(maxdata + 1) / sizeof(WCHAR) + 2) * sizeof(WCHAR));
    char *rule = (char *)malloc(maxdata * 2 + 16);   // UTF-8 can be up to 1.5x UTF-16 bytes
    if (wname == NULL || wdata == NULL || rule == NULL) {
        free(wname); free(wdata); free(rule);
        RegCloseKey(k);
        return;
    }
    for (DWORD i = 0;; i++) {
        DWORD nl = maxname + 1, dl = maxdata, type = 0;
        rc = RegEnumValueW(k, i, wname, &nl, NULL, &type, (BYTE *)wdata, &dl);
        if (rc != ERROR_SUCCESS) {
            break;
        }
        if (type != REG_SZ) {
            continue;
        }
        // Registry strings are not guaranteed NUL-terminated: terminate here
        // (the buffer has 2 spare WCHARs beyond maxdata).
        wdata[dl / sizeof(WCHAR)] = 0;
        WideCharToMultiByte(CP_UTF8, 0, wdata, -1, rule, (int)(maxdata * 2 + 16), NULL, NULL);

        char action[16], active[16], dir[8], proto[16], lport[128], rport[128];
        char app[1024], name[512], svc[128];
        fw_field(rule, "Action", action, sizeof action);
        fw_field(rule, "Active", active, sizeof active);
        fw_field(rule, "Dir", dir, sizeof dir);
        fw_field(rule, "Protocol", proto, sizeof proto);
        fw_field(rule, "LPort", lport, sizeof lport);
        fw_field(rule, "RPort", rport, sizeof rport);
        fw_field(rule, "App", app, sizeof app);
        fw_field(rule, "Svc", svc, sizeof svc);
        fw_field(rule, "Name", name, sizeof name);

        int is_in = _stricmp(dir, "In") == 0;
        int is_allow = _stricmp(action, "Allow") == 0;
        int is_active = _stricmp(active, "TRUE") == 0;
        if ((c->only_in && !is_in) || (c->only_allow && !is_allow) ||
                (c->only_active && !is_active)) {
            continue;
        }
        resolve_name(name, sizeof name);
        int flag = is_in && is_allow && is_active && app[0] && ioc_user_writable(app);
        if (c->only_flagged && !flag) {
            continue;
        }
        c->shown++;
        c->flagged += (unsigned)flag;

        const char *pname = proto_name(proto);
        if (c->mode == 0) {
            printf("  %-6s %-3s %-5s %-3s %-6s L:%-12s R:%-10s %s\n", source,
                   is_active ? "on" : "off", action, dir, pname,
                   lport[0] ? lport : "*", rport[0] ? rport : "*", name);
            if (app[0] || svc[0]) {
                printf("         %s%s%s%s\n", app, (app[0] && svc[0]) ? "  svc=" : (svc[0] ? "svc=" : ""),
                       svc, flag ? "   [INBOUND ALLOW from user-writable dir]" : "");
            }
        } else if (c->mode == 2) {
            csv_str(source); printf(",%s,", is_active ? "true" : "false");
            csv_str(action); putchar(',');
            csv_str(dir);    putchar(',');
            csv_str(pname);  putchar(',');
            csv_str(lport);  putchar(',');
            csv_str(rport);  putchar(',');
            csv_str(app);    putchar(',');
            csv_str(svc);    putchar(',');
            csv_str(name);
            fputs(flag ? ",true\n" : ",false\n", stdout);
        } else {
            printf("%s{\"source\":", c->first ? "" : ",");
            json_str(source);
            printf(",\"active\":%s,\"action\":", is_active ? "true" : "false");
            json_str(action);
            fputs(",\"direction\":", stdout); json_str(dir);
            fputs(",\"protocol\":", stdout);  json_str(pname);
            fputs(",\"local_ports\":", stdout);  json_str(lport);
            fputs(",\"remote_ports\":", stdout); json_str(rport);
            fputs(",\"program\":", stdout);   json_str(app);
            fputs(",\"service\":", stdout);   json_str(svc);
            fputs(",\"name\":", stdout);      json_str(name);
            printf(",\"suspicious\":%s}", flag ? "true" : "false");
            c->first = 0;
        }
    }
    free(wname); free(wdata); free(rule);
    RegCloseKey(k);
}

int cmd_firewall(int argc, char **argv)
{
    fw_ctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)         c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)     c.mode = 2;
        else if (strcmp(argv[a], "--inbound") == 0) c.only_in = 1;
        else if (strcmp(argv[a], "--allow") == 0)   c.only_allow = 1;
        else if (strcmp(argv[a], "--active") == 0)  c.only_active = 1;
        else if (strcmp(argv[a], "--flagged") == 0) c.only_flagged = 1;
        else {
            fprintf(stderr, "firewall: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    if (c.mode == 0) {
        puts("firewall rules (registry)\n");
        printf("  %-6s %-3s %-5s %-3s %-6s %-14s %-12s %s\n", "source", "act", "actn",
               "dir", "proto", "local ports", "remote", "name");
    } else if (c.mode == 2) {
        puts("source,active,action,direction,protocol,local_ports,remote_ports,program,service,name,suspicious");
    } else {
        putchar('[');
    }
    enum_store(&c, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\"
                   "FirewallPolicy\\FirewallRules", "local");
    enum_store(&c, "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules", "policy");

    if (c.mode == 0) {
        printf("\n%u rule(s), %u active inbound ALLOW from user-writable dirs\n",
               c.shown, c.flagged);
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
