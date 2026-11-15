// winspect token - a live process's security context (access token)
//
// Every process carries an access token: the kernel's answer to "who is this
// and what are they allowed to do?". Access checks compare the token against an
// object's security descriptor (see the secinfo command for the other half).
// This command reads the token and prints its four interesting parts:
//   - User SID      : the account the process runs as (RID 500 = Administrator)
//   - Groups        : the groups the token is a member of
//   - Privileges    : special powers (SeDebugPrivilege, ...) and whether enabled
//   - Integrity     : the mandatory integrity level (Low/Medium/High/System)
//
// The GetTokenInformation calls all follow the same two-step dance: call once
// with a NULL buffer to learn the required size, allocate, then call again.

#include "pidarg.h"
#include "token.h"
#include "jsonutil.h"

#include <windows.h>
#include <sddl.h>       // ConvertSidToStringSidA
#include <stdio.h>
#include <stdlib.h>     // strtoul, malloc, free
#include <string.h>     // strcmp

// A short list of privileges that, when held (and especially when enabled),
// amount to "can take over the box": debug any process, act as part of the OS,
// load a driver, bypass file security, replace a process token, impersonate a
// client, mint a token. Flagging these turns a long privilege list into a quick
// "does this token punch above its weight?" read.
static int is_dangerous_priv(const char *name)
{
    static const char *danger[] = {
        "SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege",
        "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
        "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
        "SeCreateTokenPrivilege", "SeManageVolumePrivilege",
    };
    for (size_t i = 0; i < sizeof danger / sizeof danger[0]; i++) {
        if (strcmp(name, danger[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Calls GetTokenInformation for a class, allocating the right-sized buffer.
// Returns a malloc'd buffer the caller must free, or NULL on failure.
static void *query_token(HANDLE tok, TOKEN_INFORMATION_CLASS cls)
{
    DWORD len = 0;
    // First call is expected to "fail" with ERROR_INSUFFICIENT_BUFFER while
    // telling us the size through len; that is the documented probing pattern.
    GetTokenInformation(tok, cls, NULL, 0, &len);
    if (len == 0) {
        return NULL;
    }
    void *buf = malloc(len);
    if (buf == NULL) {
        return NULL;
    }
    if (!GetTokenInformation(tok, cls, buf, len, &len)) {
        free(buf);
        return NULL;
    }
    return buf;
}

// Prints a SID as its string form (S-1-5-...) plus, when resolvable, the
// account name behind it. LookupAccountSid can fail (deleted account, no
// mapping) and that is fine - the string SID alone is still meaningful.
static void print_sid(PSID sid)
{
    char *str = NULL;
    if (ConvertSidToStringSidA(sid, &str)) {
        printf("%s", str);
        LocalFree(str);
    } else {
        printf("(unprintable SID)");
    }

    // Look the account up with the WIDE API and convert to UTF-8 ourselves, so
    // non-ASCII names (e.g. localized group names) are not mangled by the ANSI
    // code page. main() puts the console in UTF-8 to match.
    WCHAR wname[256], wdomain[256];
    DWORD nlen = 256, dlen = 256;
    SID_NAME_USE use;
    if (LookupAccountSidW(NULL, sid, wname, &nlen, wdomain, &dlen, &use)) {
        char name[512], domain[512];
        WideCharToMultiByte(CP_UTF8, 0, wname, -1, name, sizeof name, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, wdomain, -1, domain, sizeof domain, NULL, NULL);
        if (domain[0]) {
            printf("  (%s\\%s)", domain, name);
        } else {
            printf("  (%s)", name);
        }
    }
}

// Maps an integrity-level RID to a readable name. The integrity level lives in
// the last subauthority (RID) of the token's integrity SID.
static const char *integrity_name(DWORD rid)
{
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID)    return "System";
    if (rid >= SECURITY_MANDATORY_HIGH_RID)      return "High (elevated)";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID)    return "Medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID)       return "Low";
    return "Untrusted";
}

// Returns the integrity level name of a token handle (used for the token itself
// and for its linked token). Reads the RID out of the token's integrity SID.
static const char *token_integrity(HANDLE tok)
{
    TOKEN_MANDATORY_LABEL *label = query_token(tok, TokenIntegrityLevel);
    const char *r = "unknown";
    if (label != NULL) {
        UCHAR *count = GetSidSubAuthorityCount(label->Label.Sid);
        DWORD rid = (count != NULL && *count > 0)
                    ? *GetSidSubAuthority(label->Label.Sid, (DWORD)(*count - 1)) : 0;
        r = integrity_name(rid);
        free(label);
    }
    return r;
}

// Fills out with the string form of a SID (S-1-5-...); empty on failure.
static void sid_string(PSID sid, char *out, size_t n)
{
    out[0] = '\0';
    char *s = NULL;
    if (ConvertSidToStringSidA(sid, &s)) {
        snprintf(out, n, "%s", s);
        LocalFree(s);
    }
}

// Fills out with "DOMAIN\account" (UTF-8); empty when the SID has no mapping.
static void sid_account(PSID sid, char *out, size_t n)
{
    out[0] = '\0';
    WCHAR wn[256], wd[256];
    DWORD nl = 256, dl = 256;
    SID_NAME_USE use;
    if (LookupAccountSidW(NULL, sid, wn, &nl, wd, &dl, &use)) {
        char name[512], dom[512];
        WideCharToMultiByte(CP_UTF8, 0, wn, -1, name, sizeof name, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, wd, -1, dom, sizeof dom, NULL, NULL);
        if (dom[0]) {
            snprintf(out, n, "%s\\%s", dom, name);
        } else {
            snprintf(out, n, "%s", name);
        }
    }
}

// Emits the whole token as one JSON object. Kept separate from the text path so
// neither has to carry conditionals through every field.
static void emit_json(unsigned long pid, HANDLE tok)
{
    char sid[128], acct[512];

    printf("{\"pid\":%lu", pid);

    TOKEN_USER *user = query_token(tok, TokenUser);
    if (user != NULL) {
        sid_string(user->User.Sid, sid, sizeof sid);
        sid_account(user->User.Sid, acct, sizeof acct);
        fputs(",\"user\":{\"sid\":", stdout); json_str(sid);
        fputs(",\"name\":", stdout);         json_str(acct);
        putchar('}');
        free(user);
    }

    TOKEN_MANDATORY_LABEL *label = query_token(tok, TokenIntegrityLevel);
    if (label != NULL) {
        UCHAR *c = GetSidSubAuthorityCount(label->Label.Sid);
        DWORD rid = (c != NULL && *c > 0) ? *GetSidSubAuthority(label->Label.Sid, (DWORD)(*c - 1)) : 0;
        fputs(",\"integrity\":", stdout); json_str(integrity_name(rid));
        free(label);
    }

    DWORD len = 0;
    TOKEN_ELEVATION elev;
    if (GetTokenInformation(tok, TokenElevation, &elev, sizeof elev, &len)) {
        printf(",\"elevated\":%s", elev.TokenIsElevated ? "true" : "false");
    }
    TOKEN_TYPE ttype;
    if (GetTokenInformation(tok, TokenType, &ttype, sizeof ttype, &len)) {
        fputs(",\"token_type\":", stdout);
        json_str(ttype == TokenPrimary ? "Primary" : "Impersonation");
    }
    TOKEN_STATISTICS stats;
    if (GetTokenInformation(tok, TokenStatistics, &stats, sizeof stats, &len)) {
        char ls[40];
        snprintf(ls, sizeof ls, "0x%lX:0x%08lX",
                 (unsigned long)stats.AuthenticationId.HighPart,
                 (unsigned long)stats.AuthenticationId.LowPart);
        fputs(",\"logon_session\":", stdout); json_str(ls);
    }
    TOKEN_LINKED_TOKEN linked;
    if (GetTokenInformation(tok, TokenLinkedToken, &linked, sizeof linked, &len)) {
        fputs(",\"linked_integrity\":", stdout); json_str(token_integrity(linked.LinkedToken));
        CloseHandle(linked.LinkedToken);
    }

    fputs(",\"privileges\":[", stdout);
    TOKEN_PRIVILEGES *privs = query_token(tok, TokenPrivileges);
    if (privs != NULL) {
        int first = 1;
        for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
            char name[128];
            DWORD nlen = sizeof name;
            if (LookupPrivilegeNameA(NULL, &privs->Privileges[i].Luid, name, &nlen)) {
                int enabled = (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? 1 : 0;
                printf("%s{\"name\":", first ? "" : ",");
                json_str(name);
                printf(",\"enabled\":%s,\"dangerous\":%s}",
                       enabled ? "true" : "false",
                       is_dangerous_priv(name) ? "true" : "false");
                first = 0;
            }
        }
        free(privs);
    }
    putchar(']');

    fputs(",\"groups\":[", stdout);
    TOKEN_GROUPS *groups = query_token(tok, TokenGroups);
    if (groups != NULL) {
        int first = 1;
        for (DWORD i = 0; i < groups->GroupCount; i++) {
            DWORD attr = groups->Groups[i].Attributes;
            if (attr & SE_GROUP_LOGON_ID) {
                continue;
            }
            const char *tag = (attr & SE_GROUP_INTEGRITY) ? "integrity"
                            : (attr & SE_GROUP_USE_FOR_DENY_ONLY) ? "deny-only"
                            : (attr & SE_GROUP_ENABLED) ? "enabled" : "disabled";
            sid_string(groups->Groups[i].Sid, sid, sizeof sid);
            sid_account(groups->Groups[i].Sid, acct, sizeof acct);
            printf("%s{\"sid\":", first ? "" : ",");
            json_str(sid);
            fputs(",\"name\":", stdout); json_str(acct);
            fputs(",\"attr\":", stdout);  json_str(tag);
            putchar('}');
            first = 0;
        }
        free(groups);
    }
    puts("]}");
}

int cmd_token(int argc, char **argv)
{
    const char *pid_arg = NULL;
    int json = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) json = 1;
        else if (pid_arg == NULL)           pid_arg = argv[a];
        else {
            fprintf(stderr, "token: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (pid_arg == NULL) {
        fputs("usage: winspect token <pid> [--json]\n", stderr);
        return 1;
    }
    unsigned long pid = 0;
    if (!pid_from_arg("token", pid_arg, &pid)) {
        return 1;
    }

    // QUERY_LIMITED_INFORMATION is the lightest right that still lets us open
    // the token; it works across more targets than QUERY_INFORMATION.
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (h == NULL) {
        DWORD err = GetLastError();
        fprintf(stderr, "token: cannot open pid %lu (error %lu)\n", pid, (unsigned long)err);
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "       (target likely runs at higher integrity; try an elevated console)\n");
        }
        return 1;
    }

    HANDLE tok = NULL;
    if (!OpenProcessToken(h, TOKEN_QUERY, &tok)) {
        fprintf(stderr, "token: OpenProcessToken failed (error %lu)\n", (unsigned long)GetLastError());
        CloseHandle(h);
        return 1;
    }

    if (json) {
        emit_json(pid, tok);
        CloseHandle(tok);
        CloseHandle(h);
        return 0;
    }

    printf("process  pid %lu\n\n", pid);

    // ---- User -----------------------------------------------------------------
    TOKEN_USER *user = query_token(tok, TokenUser);
    if (user != NULL) {
        printf("User\n  ");
        print_sid(user->User.Sid);
        putchar('\n');
        // The RID (last subauthority) is the account's relative id. A couple of
        // well-known ones are worth calling out.
        UCHAR *count = GetSidSubAuthorityCount(user->User.Sid);
        if (count != NULL && *count > 0) {
            DWORD rid = *GetSidSubAuthority(user->User.Sid, (DWORD)(*count - 1));
            if (rid == DOMAIN_USER_RID_ADMIN) {
                puts("  (RID 500: built-in Administrator)");
            }
        }
        free(user);
    }
    putchar('\n');

    // ---- Integrity level + elevation -----------------------------------------
    TOKEN_MANDATORY_LABEL *label = query_token(tok, TokenIntegrityLevel);
    if (label != NULL) {
        UCHAR *count = GetSidSubAuthorityCount(label->Label.Sid);
        DWORD rid = (count != NULL && *count > 0)
                    ? *GetSidSubAuthority(label->Label.Sid, (DWORD)(*count - 1)) : 0;
        printf("Integrity level  0x%lX  %s\n", (unsigned long)rid, integrity_name(rid));
        free(label);
    }
    DWORD elev_len = 0;
    TOKEN_ELEVATION elev;
    if (GetTokenInformation(tok, TokenElevation, &elev, sizeof elev, &elev_len)) {
        printf("Elevated         %s\n", elev.TokenIsElevated ? "yes" : "no");
    }

    // Token type: a Primary token is owned by a process; an Impersonation token
    // is one a thread temporarily wears to act as another user.
    DWORD tlen = 0;
    TOKEN_TYPE ttype;
    if (GetTokenInformation(tok, TokenType, &ttype, sizeof ttype, &tlen)) {
        printf("Token type       %s\n", ttype == TokenPrimary ? "Primary" : "Impersonation");
    }

    // Logon session id (the LUID that ties this token to a logon). Handles that
    // belong to the same logon share it; useful for correlating processes.
    TOKEN_STATISTICS stats;
    if (GetTokenInformation(tok, TokenStatistics, &stats, sizeof stats, &tlen)) {
        printf("Logon session    0x%lX:0x%08lX\n",
               (unsigned long)stats.AuthenticationId.HighPart,
               (unsigned long)stats.AuthenticationId.LowPart);
    }

    // Linked token: on a UAC split-token admin, the filtered (limited) token has
    // a link to its full (elevated) counterpart and vice versa. Showing the
    // other token's integrity makes the split obvious.
    TOKEN_LINKED_TOKEN linked;
    if (GetTokenInformation(tok, TokenLinkedToken, &linked, sizeof linked, &tlen)) {
        printf("Linked token     integrity %s  (UAC split counterpart)\n",
               token_integrity(linked.LinkedToken));
        CloseHandle(linked.LinkedToken);
    }
    putchar('\n');

    // ---- Privileges -----------------------------------------------------------
    // Privileges are machine-wide powers (debug any process, load a driver, ...).
    // Most sit in the token disabled; code enables them with AdjustTokenPrivileges
    // only when about to use them, so "enabled" here is the interesting column.
    TOKEN_PRIVILEGES *privs = query_token(tok, TokenPrivileges);
    if (privs != NULL) {
        printf("Privileges (%lu)\n", (unsigned long)privs->PrivilegeCount);
        for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
            LUID_AND_ATTRIBUTES *la = &privs->Privileges[i];
            char name[128];
            DWORD nlen = sizeof name;
            if (LookupPrivilegeNameA(NULL, &la->Luid, name, &nlen)) {
                int enabled = (la->Attributes & SE_PRIVILEGE_ENABLED) ? 1 : 0;
                int danger = is_dangerous_priv(name);
                printf("  %-32s %-9s%s\n", name, enabled ? "enabled" : "disabled",
                       danger ? (enabled ? "  [!] powerful, ENABLED" : "  [!] powerful") : "");
            }
        }
        free(privs);
    }
    putchar('\n');

    // ---- Groups ---------------------------------------------------------------
    TOKEN_GROUPS *groups = query_token(tok, TokenGroups);
    if (groups != NULL) {
        printf("Groups (%lu)\n", (unsigned long)groups->GroupCount);
        for (DWORD i = 0; i < groups->GroupCount; i++) {
            // Skip the deny-only and logon-id housekeeping groups to keep the
            // list focused on real memberships.
            DWORD attr = groups->Groups[i].Attributes;
            if (attr & SE_GROUP_LOGON_ID) {
                continue;
            }
            // One short tag per group so you can see which are actually active.
            // A deny-only group can only ever remove access, never grant it.
            const char *tag;
            if (attr & SE_GROUP_INTEGRITY)            tag = "integrity";
            else if (attr & SE_GROUP_USE_FOR_DENY_ONLY) tag = "deny-only";
            else if (attr & SE_GROUP_ENABLED)          tag = "enabled";
            else                                       tag = "disabled";
            printf("  [%-9s] ", tag);
            print_sid(groups->Groups[i].Sid);
            putchar('\n');
        }
        free(groups);
    }

    CloseHandle(tok);
    CloseHandle(h);
    return 0;
}
