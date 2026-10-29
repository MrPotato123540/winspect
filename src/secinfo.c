// winspect secinfo - the security descriptor of a process or a file
//
// A securable object (a process, a file, a registry key, ...) carries a security
// descriptor: its owner, plus a DACL (Discretionary Access Control List). The
// DACL is an ordered list of ACEs (Access Control Entries), each saying "this
// SID is ALLOWED / DENIED this access mask". When something tries to open the
// object, the kernel walks the DACL against the caller's token (the subject side,
// see the token command) and decides.
//
// Two special DACL states trip people up, so we spell them out:
//   - NULL DACL  (no DACL present)  -> everyone gets full access. Wide open.
//   - empty DACL (present, 0 ACEs)  -> nobody gets any access. Fully locked.
// And the ordering rule that matters for reading the output: a DENY ACE that
// appears before an ALLOW wins, which is why Windows places deny ACEs first.

#include "secinfo.h"
#include "jsonutil.h"
#include "rights.h"

#include <windows.h>
#include <sddl.h>       // ConvertSidToStringSidA, ConvertSecurityDescriptorToString...
#include <aclapi.h>     // GetNamedSecurityInfo, GetSecurityInfo
#include <authz.h>      // AuthzAccessCheck (effective access for any account)
#include <winsvc.h>     // SERVICE_* access rights (service objects)
#include <ntsecapi.h>   // LsaEnumerateAccountRights (account privileges)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>     // strcmp
#include <ctype.h>      // isdigit

// winspect secinfo understands four kinds of securable object, the way AccessChk
// does. Each kind has its own generic->specific access mapping and its own set of
// named access bits, so we carry the kind through the command.
enum obj_kind { OK_PROCESS, OK_FILE, OK_SERVICE, OK_REGISTRY };

static const char *kind_name(enum obj_kind k)
{
    switch (k) {
    case OK_PROCESS:  return "process";
    case OK_FILE:     return "file";
    case OK_SERVICE:  return "service";
    case OK_REGISTRY: return "registry";
    default:          return "object";
    }
}

// The generic-rights mapping for each kind, used by AccessCheck/Authz to expand
// GENERIC_READ etc. into the object's specific bits.
static GENERIC_MAPPING gm_for(enum obj_kind k)
{
    switch (k) {
    case OK_FILE: {
        GENERIC_MAPPING g = { FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                              FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
        return g;
    }
    case OK_SERVICE: {
        GENERIC_MAPPING g = {
            STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
                SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS,
            STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG,
            STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP |
                SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL,
            SERVICE_ALL_ACCESS };
        return g;
    }
    case OK_REGISTRY: {
        GENERIC_MAPPING g = { KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS };
        return g;
    }
    case OK_PROCESS:
    default: {
        GENERIC_MAPPING g = { PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                              PROCESS_SUSPEND_RESUME, PROCESS_ALL_ACCESS };
        return g;
    }
    }
}

// Named access bits, so a raw mask like 0x120089 reads as "READ_DATA|READ_EA|...".
// This is the detail AccessChk's -v switch adds, and the most instructive part of
// an access mask: it says exactly what the right permits. The per-type tables
// live in the portable rights.c (shared with handles, unit-tested).
static void decode_mask(enum obj_kind k, ACCESS_MASK m, char *out, size_t n)
{
    const char *type;
    switch (k) {
    case OK_FILE:     type = "File";    break;
    case OK_SERVICE:  type = "Service"; break;
    case OK_REGISTRY: type = "Key";     break;
    case OK_PROCESS:
    default:          type = "Process"; break;
    }
    rights_decode(type, (uint32_t)m, out, n);
}

// Turns a granted ACCESS_MASK into the R/W/E/A letters AccessChk prints, using
// the object class's generic mapping (which generic bit covers which specifics).
static void mask_rwx(ACCESS_MASK granted, const GENERIC_MAPPING *gm, char out[5])
{
    int r = (granted & gm->GenericRead) != 0;
    int w = (granted & ~gm->GenericRead & ~gm->GenericExecute & gm->GenericWrite) != 0;
    int x = (granted & ~gm->GenericRead & gm->GenericExecute) != 0;
    int a = (granted & gm->GenericAll) == gm->GenericAll;
    out[0] = r ? 'R' : '-';
    out[1] = w ? 'W' : '-';
    out[2] = x ? 'X' : '-';
    out[3] = a ? 'A' : '-';
    out[4] = '\0';
}

// Resolves an account name OR an "S-1-..." string SID to a SID. On success sets
// *out to a heap SID the caller releases with free(). Returns 1 on success.
static int resolve_account(const char *name, PSID *out)
{
    *out = NULL;
    // String SID form ("S-1-5-...").
    if ((name[0] == 'S' || name[0] == 's') && name[1] == '-') {
        PSID tmp = NULL;
        if (ConvertStringSidToSidA(name, &tmp)) {
            DWORD len = GetLengthSid(tmp);
            PSID copy = malloc(len);
            if (copy != NULL) {
                memcpy(copy, tmp, len);
                *out = copy;
            }
            LocalFree(tmp);
            return *out != NULL;
        }
        // fall through: maybe it is literally an account named like that
    }
    // Account name ("DOMAIN\\user", "Everyone", ...): two-call sizing.
    DWORD cbSid = 0, cchDom = 0;
    SID_NAME_USE use;
    LookupAccountNameA(NULL, name, NULL, &cbSid, NULL, &cchDom, &use);
    if (cbSid == 0) {
        return 0;
    }
    PSID sid = malloc(cbSid);
    char *dom = malloc(cchDom ? cchDom : 1);
    int ok = 0;
    if (sid != NULL && dom != NULL &&
        LookupAccountNameA(NULL, name, sid, &cbSid, dom, &cchDom, &use)) {
        *out = sid;
        ok = 1;
    }
    free(dom);
    if (!ok) {
        free(sid);
    }
    return ok;
}

// Effective access of an ARBITRARY account against a security descriptor, via
// the Authz API. Unlike AccessCheck, this needs no token for the account: Authz
// synthesises a client context from the SID (resolving group membership itself),
// which is exactly how AccessChk answers "what could user X do to this object?".
static int authz_effective(PSECURITY_DESCRIPTOR sd, PSID sid, ACCESS_MASK *granted)
{
    *granted = 0;
    AUTHZ_RESOURCE_MANAGER_HANDLE rm = NULL;
    if (!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, NULL, NULL, NULL, NULL, &rm)) {
        return 0;
    }
    AUTHZ_CLIENT_CONTEXT_HANDLE ctx = NULL;
    LUID zero = { 0, 0 };
    int ok = 0;
    if (AuthzInitializeContextFromSid(0, sid, rm, NULL, zero, NULL, &ctx)) {
        AUTHZ_ACCESS_REQUEST req;
        memset(&req, 0, sizeof req);
        req.DesiredAccess = MAXIMUM_ALLOWED;
        ACCESS_MASK gmask = 0;
        DWORD err = 0;
        AUTHZ_ACCESS_REPLY rep;
        memset(&rep, 0, sizeof rep);
        rep.ResultListLength = 1;
        rep.GrantedAccessMask = &gmask;
        rep.Error = &err;
        if (AuthzAccessCheck(0, ctx, &req, NULL, sd, NULL, 0, &rep, NULL)) {
            *granted = gmask;
            ok = 1;
        }
        AuthzFreeContext(ctx);
    }
    AuthzFreeResourceManager(rm);
    return ok;
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

// Prints a SID as a JSON object {"sid":"S-1-...","name":"DOMAIN\\acct"}.
static void sid_json(PSID sid)
{
    char s[128], acct[512];
    sid_string(sid, s, sizeof s);
    sid_account(sid, acct, sizeof acct);
    fputs("{\"sid\":", stdout); json_str(s);
    fputs(",\"name\":", stdout); json_str(acct);
    putchar('}');
}

// Prints a SID as its string form plus the account name when resolvable.
// (Kept local to this file for now; a later phase folds the shared SID/flag
// helpers used here and in token.c into one place.)
static void print_sid(PSID sid)
{
    char *str = NULL;
    if (ConvertSidToStringSidA(sid, &str)) {
        printf("%s", str);
        LocalFree(str);
    } else {
        printf("(unprintable SID)");
    }
    // Wide lookup + UTF-8 conversion so localized names aren't mangled (main()
    // puts the console in UTF-8 to match).
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

// Walks and prints a DACL, handling the NULL and empty special cases. With
// verbose, each ACE's mask is decoded into named rights for the object kind.
static void print_dacl(PACL dacl, BOOL dacl_present, enum obj_kind kind, int verbose, int json)
{
    if (json) {
        fputs(",\"dacl\":{", stdout);
        if (!dacl_present || dacl == NULL) {
            fputs("\"present\":false,\"null_dacl\":true,\"ace_count\":0,\"aces\":[]}", stdout);
            return;
        }
        printf("\"present\":true,\"null_dacl\":false,\"ace_count\":%u,\"aces\":[",
               dacl->AceCount);
        int first = 1;
        for (WORD i = 0; i < dacl->AceCount; i++) {
            void *raw = NULL;
            if (!GetAce(dacl, i, &raw)) {
                continue;
            }
            ACE_HEADER *hdr = (ACE_HEADER *)raw;
            const char *verb;
            PSID sid;
            ACCESS_MASK mask;
            if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)raw;
                verb = "ALLOW"; mask = a->Mask; sid = (PSID)&a->SidStart;
            } else if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
                ACCESS_DENIED_ACE *a = (ACCESS_DENIED_ACE *)raw;
                verb = "DENY"; mask = a->Mask; sid = (PSID)&a->SidStart;
            } else {
                printf("%s{\"type\":\"other\",\"ace_type\":%u}",
                       first ? "" : ",", hdr->AceType);
                first = 0;
                continue;
            }
            char sidstr[128], acct[512], rights[256];
            sid_string(sid, sidstr, sizeof sidstr);
            sid_account(sid, acct, sizeof acct);
            decode_mask(kind, mask, rights, sizeof rights);
            printf("%s{\"type\":\"%s\",\"mask\":\"0x%08lX\",\"sid\":",
                   first ? "" : ",", verb, (unsigned long)mask);
            json_str(sidstr);
            fputs(",\"name\":", stdout); json_str(acct);
            fputs(",\"rights\":", stdout); json_str(rights);
            putchar('}');
            first = 0;
        }
        fputs("]}", stdout);
        return;
    }

    if (!dacl_present || dacl == NULL) {
        // GetSecurityInfo reports a NULL DACL by leaving the pointer NULL. That
        // is the "wide open" case, a real security finding, not an error.
        puts("  DACL: NULL  -> no access control, everyone has full access");
        return;
    }
    if (dacl->AceCount == 0) {
        puts("  DACL: empty (0 ACEs)  -> no one is granted any access");
        return;
    }

    printf("  DACL: %u ACEs\n", dacl->AceCount);
    for (WORD i = 0; i < dacl->AceCount; i++) {
        // Each ACE begins with an ACE_HEADER telling its type; the allow/deny
        // ACEs we care about are laid out as { header, ACCESS_MASK, SID }.
        void *raw = NULL;
        if (!GetAce(dacl, i, &raw)) {
            continue;
        }
        ACE_HEADER *hdr = (ACE_HEADER *)raw;
        const char *verb;
        PSID sid;
        ACCESS_MASK mask;

        if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)raw;
            verb = "ALLOW";
            mask = a->Mask;
            sid  = (PSID)&a->SidStart;
        } else if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE *a = (ACCESS_DENIED_ACE *)raw;
            verb = "DENY ";
            mask = a->Mask;
            sid  = (PSID)&a->SidStart;
        } else {
            // Audit/alarm and callback ACE types exist but are rare for files
            // and processes; show the type number instead of guessing a layout.
            printf("    [%u] (ACE type %u, not decoded)\n", i, hdr->AceType);
            continue;
        }

        printf("    [%u] %s  0x%08lX  ", i, verb, (unsigned long)mask);
        print_sid(sid);
        putchar('\n');
        if (verbose) {
            char rights[256];
            decode_mask(kind, mask, rights, sizeof rights);
            printf("         %s\n", rights);
        }
    }
}

// Maps an integrity RID to a level name (the object's mandatory label).
static const char *integrity_label_name(DWORD rid)
{
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) return "System";
    if (rid >= SECURITY_MANDATORY_HIGH_RID)   return "High";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID) return "Medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID)    return "Low";
    return "Untrusted";
}

// An object's integrity level lives in its SACL as a SYSTEM_MANDATORY_LABEL_ACE.
// A lower-integrity subject cannot write to a higher-integrity object even if the
// DACL would allow it, so this is part of the real access story. (Reading just
// the label does NOT need SeSecurityPrivilege, unlike the audit part of a SACL.)
static void print_label(PACL sacl, int json)
{
    const char *name = NULL;   // NULL means "no explicit label"
    if (sacl != NULL) {
        for (WORD i = 0; i < sacl->AceCount; i++) {
            void *raw = NULL;
            if (!GetAce(sacl, i, &raw)) {
                continue;
            }
            ACE_HEADER *hdr = (ACE_HEADER *)raw;
            if (hdr->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
                SYSTEM_MANDATORY_LABEL_ACE *la = (SYSTEM_MANDATORY_LABEL_ACE *)raw;
                PSID sid = (PSID)&la->SidStart;
                UCHAR *cnt = GetSidSubAuthorityCount(sid);
                DWORD rid = (cnt != NULL && *cnt > 0)
                            ? *GetSidSubAuthority(sid, (DWORD)(*cnt - 1)) : 0;
                name = integrity_label_name(rid);
                break;
            }
        }
    }

    if (json) {
        fputs(",\"integrity_label\":", stdout);
        if (name != NULL) { json_str(name); }
        else              { fputs("null", stdout); }
        return;
    }
    if (name != NULL) {
        printf("  Integrity label: %s\n", name);
    } else if (sacl == NULL) {
        puts("  Integrity label: (none -> treated as Medium)");
    } else {
        puts("  Integrity label: (none)");
    }
}

// Computes the access THIS user would actually be granted to the object, which
// is the question people really want answered (AccessChk's signature feature).
// We impersonate our own token and ask AccessCheck for MAXIMUM_ALLOWED: it walks
// the DACL for us and returns the maximal granted mask.
static void print_effective(PSECURITY_DESCRIPTOR sd, enum obj_kind kind, int json)
{
    int have = 0;
    DWORD granted = 0;

    if (sd != NULL) {
        HANDLE tok = NULL, imp = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
            // AccessCheck requires an impersonation token, not a primary one.
            if (DuplicateToken(tok, SecurityImpersonation, &imp)) {
                GENERIC_MAPPING gm = gm_for(kind);
                PRIVILEGE_SET ps;
                DWORD ps_len = sizeof ps;
                BOOL status = FALSE;
                if (AccessCheck(sd, imp, MAXIMUM_ALLOWED, &gm, &ps, &ps_len, &granted, &status)) {
                    have = 1;
                }
                CloseHandle(imp);
            }
            CloseHandle(tok);
        }
    }

    char rights[256];
    if (have) {
        decode_mask(kind, granted, rights, sizeof rights);
    }

    if (json) {
        fputs(",\"effective_access\":", stdout);
        if (have) {
            char m[16];
            snprintf(m, sizeof m, "0x%08lX", (unsigned long)granted);
            json_str(m);
        } else {
            fputs("null", stdout);
        }
        fputs(",\"effective_rights\":", stdout);
        if (have) { json_str(rights); } else { fputs("null", stdout); }
        return;
    }
    if (have) {
        printf("  Effective access (you): 0x%08lX  %s\n",
               (unsigned long)granted, granted == 0 ? "(no access)" : rights);
    }
}

// True if s is all decimal digits (so we treat the argument as a PID, not a path).
static int all_digits(const char *s)
{
    if (*s == '\0') {
        return 0;
    }
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s)) {
            return 0;
        }
    }
    return 1;
}

// Lists the privileges and logon rights an account HOLDS system-wide (AccessChk
// -a). This is the subject side, not an object's DACL: LsaEnumerateAccountRights
// returns the right names (e.g. SeDebugPrivilege, SeServiceLogonRight) granted to
// the account's SID in the local security policy.
static int print_account_privileges(const char *account, int json)
{
    PSID sid = NULL;
    if (!resolve_account(account, &sid)) {
        fprintf(stderr, "secinfo: cannot resolve account '%s'\n", account);
        return 1;
    }
    LSA_OBJECT_ATTRIBUTES oa;
    ZeroMemory(&oa, sizeof oa);
    LSA_HANDLE pol = NULL;
    if (LsaOpenPolicy(NULL, &oa, POLICY_LOOKUP_NAMES, &pol) != 0) {
        free(sid);
        fputs("secinfo: LsaOpenPolicy failed\n", stderr);
        return 1;
    }
    LSA_UNICODE_STRING *rights = NULL;
    ULONG count = 0;
    // A missing account-rights entry returns a non-zero status with no rights;
    // we treat that as "holds none" rather than an error.
    LsaEnumerateAccountRights(pol, sid, &rights, &count);

    if (json) {
        fputs("{\"account\":", stdout);
        json_str(account);
        fputs(",\"privileges\":[", stdout);
        for (ULONG i = 0; i < count; i++) {
            char nm[128];
            int wl = rights[i].Length / (int)sizeof(WCHAR);
            int got = WideCharToMultiByte(CP_UTF8, 0, rights[i].Buffer, wl, nm, (int)sizeof nm - 1, NULL, NULL);
            nm[(got > 0) ? got : 0] = '\0';
            printf("%s", i ? "," : "");
            json_str(nm);
        }
        puts("]}");
    } else {
        printf("account  %s\n\n", account);
        if (count == 0) {
            puts("  (no privileges / logon rights held)");
        } else {
            puts("Privileges / logon rights");
            for (ULONG i = 0; i < count; i++) {
                char nm[128];
                int wl = rights[i].Length / (int)sizeof(WCHAR);
                int got = WideCharToMultiByte(CP_UTF8, 0, rights[i].Buffer, wl, nm, (int)sizeof nm - 1, NULL, NULL);
                nm[(got > 0) ? got : 0] = '\0';
                printf("  %s\n", nm);
            }
        }
    }
    if (rights != NULL) {
        LsaFreeMemory(rights);
    }
    LsaClose(pol);
    free(sid);
    return 0;
}

int cmd_secinfo(int argc, char **argv)
{
    const char *target = NULL;
    const char *account = NULL;   // --account <name|SID>: effective access for it
    const char *privs_of = NULL;  // --privileges <name|SID>: rights the account holds
    int json = 0;
    int want_sddl = 0;            // --sddl: dump the descriptor as an SDDL string
    int want_rights = 0;          // --rights: decode each ACE mask into named rights
    enum obj_kind kind = OK_FILE; // refined below
    int kind_set = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      json = 1;
        else if (strcmp(argv[a], "--sddl") == 0) want_sddl = 1;
        else if (strcmp(argv[a], "--rights") == 0) want_rights = 1;
        else if (strcmp(argv[a], "--account") == 0) {
            if (a + 1 >= argc) { fputs("secinfo: --account needs a name or SID\n", stderr); return 1; }
            account = argv[++a];
        }
        else if (strcmp(argv[a], "--privileges") == 0) {
            if (a + 1 >= argc) { fputs("secinfo: --privileges needs a name or SID\n", stderr); return 1; }
            privs_of = argv[++a];
        }
        else if (strcmp(argv[a], "--service") == 0) {
            if (a + 1 >= argc) { fputs("secinfo: --service needs a service name\n", stderr); return 1; }
            target = argv[++a]; kind = OK_SERVICE; kind_set = 1;
        }
        else if (strcmp(argv[a], "--key") == 0) {
            if (a + 1 >= argc) { fputs("secinfo: --key needs a registry path\n", stderr); return 1; }
            target = argv[++a]; kind = OK_REGISTRY; kind_set = 1;
        }
        else if (target == NULL)            target = argv[a];
        else {
            fprintf(stderr, "secinfo: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    // Standalone mode: list what an account can do, independent of any object.
    if (privs_of != NULL) {
        return print_account_privileges(privs_of, json);
    }

    if (target == NULL) {
        fputs("usage: winspect secinfo <pid|path> [--account <name|SID>] [--rights] [--sddl] [--json]\n"
              "       winspect secinfo --service <name> [...]\n"
              "       winspect secinfo --key <MACHINE\\...|CURRENT_USER\\...> [...]\n"
              "       winspect secinfo --privileges <name|SID> [--json]\n", stderr);
        return 1;
    }

    // For an unflagged positional target: all-digits means a PID, else a path.
    if (!kind_set) {
        kind = all_digits(target) ? OK_PROCESS : OK_FILE;
    }

    PSID owner = NULL;
    PACL dacl = NULL;
    PACL sacl = NULL;                 // carries the integrity label (see print_label)
    BOOL dacl_present = FALSE;
    PSECURITY_DESCRIPTOR sd = NULL;   // one buffer backing owner+dacl+sacl; free once
    DWORD err;

    // LABEL_SECURITY_INFORMATION asks for the mandatory integrity label too; it
    // is returned via the SACL out-parameter and (unlike audit ACEs) needs no
    // special privilege to read.
    // GROUP is requested too: AccessCheck requires the security descriptor to
    // carry both an owner AND a group, otherwise it fails and we print no
    // effective-access line.
    const SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION |
                                    GROUP_SECURITY_INFORMATION |
                                    DACL_SECURITY_INFORMATION |
                                    LABEL_SECURITY_INFORMATION;

    unsigned long pid = 0;
    if (kind == OK_PROCESS) {
        // ---- PID: read the process object's security descriptor --------------
        pid = strtoul(target, NULL, 10);
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL, FALSE, (DWORD)pid);
        if (h == NULL) {
            fprintf(stderr, "secinfo: cannot open pid %lu (error %lu)\n", pid, (unsigned long)GetLastError());
            return 1;
        }
        err = GetSecurityInfo(h, SE_KERNEL_OBJECT, si, &owner, NULL, &dacl, &sacl, &sd);
        CloseHandle(h);
        if (err != ERROR_SUCCESS) {
            fprintf(stderr, "secinfo: GetSecurityInfo failed (error %lu)\n", (unsigned long)err);
            return 1;
        }
        dacl_present = (dacl != NULL);
        if (!json) { printf("process  pid %lu\n\n", pid); }
    } else {
        // ---- Named object: file, service or registry key ---------------------
        // GetNamedSecurityInfo takes the same object name the user typed; only the
        // SE_OBJECT_TYPE differs. Registry paths use the "MACHINE\..." form.
        SE_OBJECT_TYPE ot = (kind == OK_SERVICE)  ? SE_SERVICE :
                            (kind == OK_REGISTRY) ? SE_REGISTRY_KEY : SE_FILE_OBJECT;
        err = GetNamedSecurityInfoA(target, ot, si, &owner, NULL, &dacl, &sacl, &sd);
        if (err != ERROR_SUCCESS) {
            fprintf(stderr, "secinfo: GetNamedSecurityInfo('%s' as %s) failed (error %lu)\n",
                    target, kind_name(kind), (unsigned long)err);
            return 1;
        }
        dacl_present = (dacl != NULL);
        if (!json) { printf("%s  %s\n\n", kind_name(kind), target); }
    }

    // ---- Optional extras: SDDL dump and arbitrary-account effective access ----
    char *sddl = NULL;
    if (want_sddl) {
        LPSTR s = NULL;
        if (ConvertSecurityDescriptorToStringSecurityDescriptorA(sd, SDDL_REVISION_1, si, &s, NULL)) {
            sddl = s;   // LocalFree below
        }
    }
    int acct_ok = 0;
    ACCESS_MASK acct_granted = 0;
    char acct_rwx[5] = "----";
    char acct_rights[256] = "";
    PSID acct_sid = NULL;
    if (account != NULL && resolve_account(account, &acct_sid)) {
        if (authz_effective(sd, acct_sid, &acct_granted)) {
            GENERIC_MAPPING gm = gm_for(kind);
            mask_rwx(acct_granted, &gm, acct_rwx);
            decode_mask(kind, acct_granted, acct_rights, sizeof acct_rights);
            acct_ok = 1;
        }
    }

    if (json) {
        // One object; each helper appends its own ,"key":value fragment.
        fputs("{\"type\":", stdout);
        json_str(kind_name(kind));
        if (kind == OK_PROCESS) {
            printf(",\"pid\":%lu", pid);
        } else {
            fputs(",\"name\":", stdout); json_str(target);
        }
        fputs(",\"owner\":", stdout);
        if (owner != NULL) { sid_json(owner); }
        else               { fputs("null", stdout); }
        print_label(sacl, 1);
        print_effective(sd, kind, 1);
        if (account != NULL) {
            fputs(",\"account\":{\"name\":", stdout); json_str(account);
            if (acct_ok) {
                char m[16];
                snprintf(m, sizeof m, "0x%08lX", (unsigned long)acct_granted);
                fputs(",\"granted\":", stdout); json_str(m);
                fputs(",\"rwx\":", stdout);     json_str(acct_rwx);
                fputs(",\"rights\":", stdout);  json_str(acct_rights);
            } else {
                fputs(",\"granted\":null,\"rwx\":null,\"rights\":null", stdout);
            }
            putchar('}');
        }
        print_dacl(dacl, dacl_present, kind, want_rights, 1);
        if (want_sddl) {
            fputs(",\"sddl\":", stdout);
            if (sddl != NULL) { json_str(sddl); } else { fputs("null", stdout); }
        }
        puts("}");
    } else {
        if (owner != NULL) {
            printf("  Owner: ");
            print_sid(owner);
            putchar('\n');
        }
        print_label(sacl, 0);
        print_effective(sd, kind, 0);
        if (account != NULL) {
            if (acct_ok) {
                printf("  Effective access (%s): %s  (0x%08lX)  %s\n",
                       account, acct_rwx, (unsigned long)acct_granted, acct_rights);
            } else {
                printf("  Effective access (%s): (could not evaluate)\n", account);
            }
        }
        print_dacl(dacl, dacl_present, kind, want_rights, 0);
        if (want_sddl) {
            printf("  SDDL: %s\n", sddl != NULL ? sddl : "(unavailable)");
        }
    }

    free(acct_sid);
    if (sddl != NULL) {
        LocalFree(sddl);
    }
    // owner/dacl/sacl all point INTO sd, so a single LocalFree releases everything.
    if (sd != NULL) {
        LocalFree(sd);
    }
    return 0;
}
