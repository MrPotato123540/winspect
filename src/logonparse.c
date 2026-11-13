// Logon / logoff event parsing (see logonparse.h). Portable C.

#include "logonparse.h"
#include "artparse.h"
#include "ioc.h"
#include "bootparse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ci_eq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
    }
    return *a == *b;
}

static int ci_prefix(const char *s, const char *p)
{
    for (; *p; s++, p++) {
        char x = *s, y = *p;
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
    }
    return 1;
}

// Windows logs "-" (and sometimes an empty string) for "not applicable".
static void blank_dash(char *s)
{
    if (strcmp(s, "-") == 0) s[0] = '\0';
}

static void rtrim(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
}

// "DOMAIN\user", or just the name when there is no domain.
static void join_user(char *out, size_t n, const char *domain, const char *name)
{
    if (domain[0] && strcmp(domain, "-") != 0 && name[0]) snprintf(out, n, "%s\\%s", domain, name);
    else snprintf(out, n, "%s", strcmp(name, "-") == 0 ? "" : name);
}

// IPv4-mapped IPv6 ("::ffff:10.0.0.5") is how dual-stack listeners log a v4 client.
static void clean_addr(char *s)
{
    blank_dash(s);
    if (ci_prefix(s, "::ffff:") && strchr(s + 7, '.') != NULL) memmove(s, s + 7, strlen(s + 7) + 1);
}

static void two(const char *xml, const char *dom_field, const char *name_field, char *out, size_t n)
{
    char d[96], u[96];
    evt_data(xml, dom_field, d, sizeof d);
    evt_data(xml, name_field, u, sizeof u);
    join_user(out, n, d, u);
}

int logon_parse(const char *xml, const char *channel, logon_rec *r)
{
    memset(r, 0, sizeof *r);
    char idtxt[16], tmp[64];
    evt_system(xml, "EventID", idtxt, sizeof idtxt);
    r->id = (unsigned)strtoul(idtxt, NULL, 10);
    evt_time(xml, r->time, sizeof r->time);

    if (ci_eq(channel, "Security")) {
        switch (r->id) {
        case 4624:
            r->kind = LK_LOGON;
            two(xml, "TargetDomainName", "TargetUserName", r->user, sizeof r->user);
            evt_data(xml, "TargetLogonId", r->logon_id, sizeof r->logon_id);
            evt_data(xml, "LogonType", tmp, sizeof tmp);
            r->type = (unsigned)strtoul(tmp, NULL, 10);
            evt_data(xml, "IpAddress", r->source, sizeof r->source);
            evt_data(xml, "WorkstationName", r->workstation, sizeof r->workstation);
            evt_data(xml, "ProcessName", r->process, sizeof r->process);
            evt_data(xml, "LogonProcessName", r->logon_process, sizeof r->logon_process);
            evt_data(xml, "AuthenticationPackageName", r->auth, sizeof r->auth);
            evt_data(xml, "LmPackageName", r->lm, sizeof r->lm);
            break;
        case 4625: {
            r->kind = LK_FAILED;
            two(xml, "TargetDomainName", "TargetUserName", r->user, sizeof r->user);
            evt_data(xml, "LogonType", tmp, sizeof tmp);
            r->type = (unsigned)strtoul(tmp, NULL, 10);
            evt_data(xml, "IpAddress", r->source, sizeof r->source);
            evt_data(xml, "WorkstationName", r->workstation, sizeof r->workstation);
            evt_data(xml, "ProcessName", r->process, sizeof r->process);
            evt_data(xml, "LogonProcessName", r->logon_process, sizeof r->logon_process);
            evt_data(xml, "AuthenticationPackageName", r->auth, sizeof r->auth);
            // SubStatus is the specific reason; Status the general one.
            evt_data(xml, "SubStatus", r->status, sizeof r->status);
            if (strtoul(r->status, NULL, 16) == 0) evt_data(xml, "Status", r->status, sizeof r->status);
            break;
        }
        case 4634:
        case 4647:
            r->kind = LK_LOGOFF;
            two(xml, "TargetDomainName", "TargetUserName", r->user, sizeof r->user);
            evt_data(xml, "TargetLogonId", r->logon_id, sizeof r->logon_id);
            evt_data(xml, "LogonType", tmp, sizeof tmp);
            r->type = (unsigned)strtoul(tmp, NULL, 10);
            break;
        case 4648:
            r->kind = LK_EXPLICIT;
            two(xml, "TargetDomainName", "TargetUserName", r->user, sizeof r->user);
            two(xml, "SubjectDomainName", "SubjectUserName", r->by, sizeof r->by);
            evt_data(xml, "SubjectLogonId", r->logon_id, sizeof r->logon_id);
            evt_data(xml, "TargetServerName", r->server, sizeof r->server);
            evt_data(xml, "ProcessName", r->process, sizeof r->process);
            evt_data(xml, "IpAddress", r->source, sizeof r->source);
            break;
        case 4672:
            r->kind = LK_PRIVILEGED;
            two(xml, "SubjectDomainName", "SubjectUserName", r->user, sizeof r->user);
            evt_data(xml, "SubjectLogonId", r->logon_id, sizeof r->logon_id);
            break;
        case 4778:
        case 4779:
            r->kind = r->id == 4778 ? LK_RECONNECT : LK_DISCONNECT;
            two(xml, "AccountDomain", "AccountName", r->user, sizeof r->user);
            evt_data(xml, "LogonID", r->logon_id, sizeof r->logon_id);
            evt_data(xml, "SessionName", r->session, sizeof r->session);
            evt_data(xml, "ClientName", r->workstation, sizeof r->workstation);
            evt_data(xml, "ClientAddress", r->source, sizeof r->source);
            break;
        default:
            return 0;
        }
    } else if (ci_eq(channel, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")) {
        switch (r->id) {
        case 21: r->kind = LK_SESSION_LOGON; break;
        case 23: r->kind = LK_SESSION_LOGOFF; break;
        case 24: r->kind = LK_DISCONNECT; break;
        case 25: r->kind = LK_RECONNECT; break;
        default: return 0;
        }
        // These live in <UserData><EventXML>, as plain elements.
        evt_system(xml, "User", r->user, sizeof r->user);
        evt_system(xml, "SessionID", r->session, sizeof r->session);
        evt_system(xml, "Address", r->source, sizeof r->source);
        if (ci_eq(r->source, "LOCAL")) r->source[0] = '\0';      // the console, not a client
    } else {
        return 0;
    }
    clean_addr(r->source);
    blank_dash(r->workstation);
    blank_dash(r->process);
    blank_dash(r->auth);
    blank_dash(r->lm);
    blank_dash(r->server);
    blank_dash(r->logon_process);
    rtrim(r->logon_process);                 // logged padded: "Advapi  ", "User32 "
    return 1;
}

const char *logon_type_name(unsigned type)
{
    switch (type) {
    case 2:  return "interactive";
    case 3:  return "network";
    case 4:  return "batch";
    case 5:  return "service";
    case 7:  return "unlock";
    case 8:  return "network cleartext";
    case 9:  return "new credentials";
    case 10: return "remote desktop";
    case 11: return "cached interactive";
    case 12: return "cached remote desktop";
    case 13: return "cached unlock";
    default: return "";
    }
}

const char *logon_kind_name(enum logon_kind k)
{
    switch (k) {
    case LK_LOGON:          return "logon";
    case LK_LOGOFF:         return "logoff";
    case LK_EXPLICIT:       return "explicit";
    case LK_PRIVILEGED:     return "privileged";
    case LK_RECONNECT:      return "reconnect";
    case LK_DISCONNECT:     return "disconnect";
    case LK_SESSION_LOGON:  return "session";
    case LK_SESSION_LOGOFF: return "session end";
    case LK_FAILED:         return "FAILED";
    default:                return "";
    }
}

const char *logon_failure_text(const char *status)
{
    switch (strtoul(status, NULL, 16)) {
    case 0xC000006AUL: return "wrong password";
    case 0xC0000064UL: return "no such user";
    case 0xC000006DUL: return "bad user name or password";
    case 0xC0000234UL: return "account locked out";
    case 0xC0000072UL: return "account disabled";
    case 0xC000006FUL: return "outside allowed logon hours";
    case 0xC0000070UL: return "not allowed from this workstation";
    case 0xC0000071UL: return "password expired";
    case 0xC0000193UL: return "account expired";
    case 0xC0000224UL: return "password must be changed";
    case 0xC000015BUL: return "logon type not granted";
    case 0xC000005EUL: return "no logon server available";
    case 0xC0000133UL: return "clock skew too large";
    default:           return "";
    }
}

const char *logon_source_key(const logon_rec *r)
{
    if (r->source[0] && strcmp(r->source, "::1") != 0 && strcmp(ioc_ip_scope(r->source), "loopback") != 0) return r->source;
    if (r->source[0]) return "";            // this machine itself
    return r->workstation;
}

unsigned logon_failures_before(const logon_rec *const *recs, size_t n, size_t idx, long window)
{
    if (idx >= n) return 0;
    const char *key = logon_source_key(recs[idx]);
    if (key[0] == '\0') return 0;
    long long t = iso_epoch(recs[idx]->time);
    if (t < 0) return 0;
    unsigned failed = 0;
    for (size_t b = idx; b-- > 0;) {
        long long tp = iso_epoch(recs[b]->time);
        if (tp < 0 || t - tp > window) break;
        if (recs[b]->kind == LK_FAILED && ci_eq(logon_source_key(recs[b]), key)) failed++;
    }
    return failed;
}

int logon_is_noise(const logon_rec *r)
{
    if (r->kind == LK_LOGON && (r->type == 5 || r->type == 0)) return 1;
    const char *name = strrchr(r->user, '\\');
    name = name ? name + 1 : r->user;
    size_t n = strlen(name);
    if (n == 0) return r->kind == LK_LOGON || r->kind == LK_LOGOFF;
    if (name[n - 1] == '$') return 1;
    if (ci_eq(name, "SYSTEM") || ci_eq(name, "LOCAL SERVICE") || ci_eq(name, "NETWORK SERVICE") ||
            ci_eq(name, "ANONYMOUS LOGON")) return 1;
    // Window manager / font driver host identities: DWM-1, UMFD-0, ...
    if ((ci_prefix(name, "DWM-") || ci_prefix(name, "UMFD-")) && name[n - 1] >= '0' && name[n - 1] <= '9') return 1;
    return 0;
}

const char *logon_reason(const logon_rec *r)
{
    int is_public = strcmp(ioc_ip_scope(r->source), "public") == 0;
    int is_loop = strcmp(ioc_ip_scope(r->source), "loopback") == 0 || strcmp(r->source, "::1") == 0;
    if (r->kind == LK_LOGON) {
        // A remote desktop client on the machine itself: the connection came
        // in through a forwarded port (SSH / plink / netsh portproxy tunnel).
        if (r->type == 10 && is_loop) return "remote desktop logon from loopback (RDP tunnelled through a port forward)";
        if ((r->type == 10 || r->type == 12) && is_public) return "remote desktop logon from a public address";
        if (r->type == 3 && is_public) return "network logon from a public address";
        if (r->type == 8) return "logon type 8: the password reached this machine in cleartext";
        if (r->type == 9 && ci_eq(r->logon_process, "seclogo"))
            return "new credentials for network use only (runas /netonly; pass-the-hash tooling looks the same)";
        // Null sessions (ANONYMOUS LOGON) are always logged as "NTLM V1" although
        // no NTLM response was computed, so they prove nothing about NTLMv1 use.
        if (ci_eq(r->lm, "NTLM V1") && strstr(r->user, "ANONYMOUS LOGON") == NULL) return "NTLMv1 authentication (weak, relayable)";
    } else if ((r->kind == LK_SESSION_LOGON || r->kind == LK_RECONNECT) && is_public) {
        return "remote desktop session from a public address";
    }
    return NULL;
}
