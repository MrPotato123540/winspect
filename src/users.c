// winspect users - local accounts
//
// Live: NetUserEnum lists the local accounts and NetUserGetInfo (level 3)
// gives each one's flags, last logon, password age and counters; the members of the local
// Administrators group come from NetLocalGroupGetMembers, the group being
// found by its well-known SID S-1-5-32-544 (its NAME is localised).
//
// Offline (--sam): a copied SAM hive. Account names are the subkeys of
// SAM\Domains\Account\Users\Names, and each one's default value has no data -
// its TYPE field holds the RID, so the name -> RID mapping needs no other
// structure. The per-RID "F" value carries the times and counters
// (sam_parse_f, unit-tested). The "V" value next to it holds the password
// hashes; it is never read. The machine SID is the tail of the domain
// object's V value (SAM\Domains\Account, no secrets there).

#include "users.h"
#include "regsrc.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    int mode, first, only_flagged;
    unsigned count, flagged;
} uctx;

typedef struct {
    char name[260], full[260];
    uint32_t rid;
    int disabled, pw_not_required, pw_never_expires, locked, machine;
    int admin;                    // 1 / 0, -1 = unknown (offline)
    uint64_t last_logon, pw_set;  // FILETIME, 0 = never / unknown
    unsigned logons, bad;
} account;

static uint64_t unix_to_ft(uint64_t t) { return t ? (t + 11644473600ULL) * 10000000ULL : 0; }

static void emit(uctx *c, const account *a)
{
    const char *reason = account_reason(a->name, a->rid, a->disabled, a->pw_not_required, a->machine);
    c->count++;
    if (reason) c->flagged++;
    if (c->only_flagged && reason == NULL) return;
    char ll[32], ps[32];
    filetime_utc_str(a->last_logon, ll, sizeof ll);
    filetime_utc_str(a->pw_set, ps, sizeof ps);
    const char *adm = a->admin < 0 ? "?" : a->admin ? "yes" : "no";
    if (c->mode == 0) {
        printf("%s %-20s %6u  %-8s %-5s %-19s %-19s %6u %4u\n", reason ? "[!]" : "   ", a->name, a->rid,
               a->disabled ? "disabled" : "enabled", adm, ll, ps, a->logons, a->bad);
        if (reason) printf("    <- %s\n", reason);
    } else if (c->mode == 2) {
        csv_str(a->name);
        printf(",%u,%s,%s,%s,%s,%u,%u,%s,%s,", a->rid, a->disabled ? "false" : "true", adm, ll, ps,
               a->logons, a->bad, a->pw_not_required ? "true" : "false", a->pw_never_expires ? "true" : "false");
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"name\":", c->first ? "" : ",");
        json_str(a->name);
        fputs(",\"full_name\":", stdout);
        json_str(a->full);
        printf(",\"rid\":%u,\"enabled\":%s,\"admin\":%s,\"last_logon\":\"%s\",\"password_set\":\"%s\","
               "\"logons\":%u,\"bad_passwords\":%u,\"password_not_required\":%s,\"password_never_expires\":%s,"
               "\"locked\":%s,\"suspicious\":%s,\"reason\":",
               a->rid, a->disabled ? "false" : "true", a->admin < 0 ? "null" : a->admin ? "true" : "false",
               ll, ps, a->logons, a->bad, a->pw_not_required ? "true" : "false",
               a->pw_never_expires ? "true" : "false", a->locked ? "true" : "false", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void w2u(const WCHAR *w, char *out, size_t n)
{
    out[0] = 0;
    if (w) WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)n, NULL, NULL);
}

// Names (DOMAIN\user, lower-cased) in the local Administrators group.
static char **admin_members(size_t *count)
{
    *count = 0;
    PSID sid = NULL;
    if (!ConvertStringSidToSidW(L"S-1-5-32-544", &sid)) return NULL;
    WCHAR name[256], dom[256];
    DWORD nl = 256, dl = 256;
    SID_NAME_USE use;
    BOOL ok = LookupAccountSidW(NULL, sid, name, &nl, dom, &dl, &use);
    LocalFree(sid);
    if (!ok) return NULL;
    LOCALGROUP_MEMBERS_INFO_3 *m = NULL;
    DWORD read = 0, total = 0;
    if (NetLocalGroupGetMembers(NULL, name, 3, (LPBYTE *)&m, MAX_PREFERRED_LENGTH, &read, &total, NULL) != NERR_Success || m == NULL)
        return NULL;
    char **list = (char **)calloc(read ? read : 1, sizeof *list);
    for (DWORD i = 0; list && i < read; i++) {
        char u[512];
        w2u(m[i].lgrmi3_domainandname, u, sizeof u);
        for (char *p = u; *p; p++) if (*p >= 'A' && *p <= 'Z') *p = (char)(*p - 'A' + 'a');
        list[i] = _strdup(u);
        (*count)++;
    }
    NetApiBufferFree(m);
    return list;
}

// RID and (once) the machine SID from the account's SID.
static void sid_parts(const WCHAR *user, account *a, char *msid, size_t msn)
{
    BYTE sb[SECURITY_MAX_SID_SIZE];
    DWORD sl = sizeof sb, dl = 256;
    WCHAR dom[256];
    SID_NAME_USE use;
    if (!LookupAccountNameW(NULL, user, sb, &sl, dom, &dl, &use) || !IsValidSid(sb)) return;
    UCHAR nsub = *GetSidSubAuthorityCount(sb);
    if (nsub) a->rid = *GetSidSubAuthority(sb, nsub - 1u);
    LPSTR s = NULL;
    if (msid[0] == 0 && ConvertSidToStringSidA(sb, &s)) {
        char *r = strrchr(s, '-');
        if (r) *r = 0;
        if (strncmp(s, "S-1-5-21-", 9) == 0) snprintf(msid, msn, "%s", s);
        LocalFree(s);
    }
}

// Names come from level 0 (supported everywhere); the details from
// NetUserGetInfo level 3, or level 1 where 3 is not available (e.g. wine:
// no logon data then, admin from the account's privilege level).
static int live(uctx *c, char *msid, size_t msn)
{
    size_t nadm = 0;
    char **adm = admin_members(&nadm);
    char comp[MAX_COMPUTERNAME_LENGTH + 1] = "";
    DWORD cl = sizeof comp;
    GetComputerNameA(comp, &cl);
    USER_INFO_0 *u = NULL;
    DWORD read = 0, total = 0, resume = 0;
    NET_API_STATUS st;
    time_t now = time(NULL);
    int any = 0;
    do {
        st = NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE *)&u, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if ((st != NERR_Success && st != ERROR_MORE_DATA) || u == NULL) break;
        for (DWORD i = 0; i < read; i++) {
            account a;
            memset(&a, 0, sizeof a);
            w2u(u[i].usri0_name, a.name, sizeof a.name);
            a.admin = adm ? 0 : -1;
            USER_INFO_3 *u3 = NULL;
            USER_INFO_1 *u1 = NULL;
            if (NetUserGetInfo(NULL, u[i].usri0_name, 3, (LPBYTE *)&u3) == NERR_Success && u3) {
                w2u(u3->usri3_full_name, a.full, sizeof a.full);
                a.rid = u3->usri3_user_id;
                a.disabled = (u3->usri3_flags & UF_ACCOUNTDISABLE) != 0;
                a.pw_not_required = (u3->usri3_flags & UF_PASSWD_NOTREQD) != 0;
                a.pw_never_expires = (u3->usri3_flags & UF_DONT_EXPIRE_PASSWD) != 0;
                a.locked = (u3->usri3_flags & UF_LOCKOUT) != 0;
                a.last_logon = unix_to_ft(u3->usri3_last_logon);
                if ((time_t)u3->usri3_password_age <= now)
                    a.pw_set = unix_to_ft((uint64_t)(now - (time_t)u3->usri3_password_age));
                a.logons = u3->usri3_num_logons;
                a.bad = u3->usri3_bad_pw_count;
                NetApiBufferFree(u3);
            } else if (NetUserGetInfo(NULL, u[i].usri0_name, 1, (LPBYTE *)&u1) == NERR_Success && u1) {
                a.disabled = (u1->usri1_flags & UF_ACCOUNTDISABLE) != 0;
                a.pw_not_required = (u1->usri1_flags & UF_PASSWD_NOTREQD) != 0;
                a.pw_never_expires = (u1->usri1_flags & UF_DONT_EXPIRE_PASSWD) != 0;
                a.locked = (u1->usri1_flags & UF_LOCKOUT) != 0;
                if (u1->usri1_password_age && (time_t)u1->usri1_password_age <= now)
                    a.pw_set = unix_to_ft((uint64_t)(now - (time_t)u1->usri1_password_age));
                if (!adm) a.admin = u1->usri1_priv == USER_PRIV_ADMIN;
                NetApiBufferFree(u1);
            }
            sid_parts(u[i].usri0_name, &a, msid, msn);
            char full[600];
            snprintf(full, sizeof full, "%s\\%s", comp, a.name);
            for (char *p = full; *p; p++) if (*p >= 'A' && *p <= 'Z') *p = (char)(*p - 'A' + 'a');
            for (size_t k = 0; adm && k < nadm; k++) if (adm[k] && strcmp(adm[k], full) == 0) a.admin = 1;
            emit(c, &a);
            any = 1;
        }
        NetApiBufferFree(u);
        u = NULL;
    } while (st == ERROR_MORE_DATA);
    for (size_t k = 0; adm && k < nadm; k++) free(adm[k]);
    free(adm);
    if (!any && st != NERR_Success) {
        fprintf(stderr, "users: NetUserEnum failed (%lu)\n", (unsigned long)st);
        return 1;
    }
    return 0;
}

typedef struct { uctx *c; regsrc *s; } octx;

// Names\<user>: the default value's type is the RID.
static void rid_cb(const char *name, uint32_t type, const unsigned char *d, size_t len, void *ctx)
{
    (void)d; (void)len;
    if (name[0] == 0) *(uint32_t *)ctx = type;
}

static void name_cb(const char *name, void *vctx)
{
    octx *o = (octx *)vctx;
    char path[512];
    rkey k;
    snprintf(path, sizeof path, "SAM\\Domains\\Account\\Users\\Names\\%s", name);
    if (rk_open(o->s, path, &k) != 0) return;
    uint32_t rid = 0;
    rk_values(o->s, &k, rid_cb, &rid);
    rk_close(&k);
    account a;
    memset(&a, 0, sizeof a);
    snprintf(a.name, sizeof a.name, "%s", name);
    a.rid = rid;
    a.admin = -1;
    snprintf(path, sizeof path, "SAM\\Domains\\Account\\Users\\%08X", rid);
    if (rk_open(o->s, path, &k) == 0) {
        unsigned char f[0x50];
        uint32_t type = 0;
        long n = rk_get(o->s, &k, "F", &type, f, sizeof f);
        rk_close(&k);
        sam_f sf;
        if (n > 0 && sam_parse_f(f, (size_t)n < sizeof f ? (size_t)n : sizeof f, &sf) == 0) {
            a.disabled = (sf.acb & SAM_ACB_DISABLED) != 0;
            a.pw_not_required = (sf.acb & SAM_ACB_PWNOTREQ) != 0;
            a.pw_never_expires = (sf.acb & SAM_ACB_PWNOEXP) != 0;
            a.locked = (sf.acb & SAM_ACB_AUTOLOCK) != 0;
            a.machine = !(sf.acb & SAM_ACB_NORMAL) && sf.acb != 0;
            a.last_logon = sf.last_logon;
            a.pw_set = sf.pw_set;
            a.logons = sf.logons;
            a.bad = sf.bad;
        }
    }
    emit(o->c, &a);
}

static int offline(uctx *c, const char *sam, char *msid, size_t msn)
{
    static regsrc s;
    char err[256];
    if (regsrc_open_hive(&s, sam, err, sizeof err) != 0) {
        fprintf(stderr, "users: %s\n", err);
        return 1;
    }
    rkey k;
    if (rk_open(&s, "SAM\\Domains\\Account", &k) == 0) {
        // Only the tail of the domain object's V is used (the machine SID).
        static unsigned char v[65536];
        uint32_t type = 0;
        long n = rk_get(&s, &k, "V", &type, v, sizeof v);
        if (n > 0 && (size_t)n <= sizeof v) sam_machine_sid(v, (size_t)n, msid, msn);
        rk_close(&k);
    }
    int rc = 0;
    if (rk_open(&s, "SAM\\Domains\\Account\\Users\\Names", &k) == 0) {
        octx o = { c, &s };
        rk_subkeys(&s, &k, name_cb, &o);
        rk_close(&k);
    } else {
        fprintf(stderr, "users: '%s' has no SAM\\Domains\\Account\\Users\\Names (not a SAM hive?)\n", sam);
        rc = 1;
    }
    regsrc_close(&s);
    return rc;
}

int cmd_users(int argc, char **argv)
{
    uctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *sam = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                     c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                 c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)             c.only_flagged = 1;
        else if (strcmp(argv[a], "--sam") == 0 && a + 1 < argc) sam = argv[++a];
        else {
            fprintf(stderr, "users: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (c.mode == 0) {
        printf("users  (%s; times UTC)\n\n", sam ? sam : "local accounts");
        printf("    %-20s %6s  %-8s %-5s %-19s %-19s %6s %4s\n", "name", "rid", "state", "admin",
               "last logon", "password set", "logons", "bad");
    } else if (c.mode == 2) {
        puts("name,rid,enabled,admin,last_logon,password_set,logons,bad_passwords,password_not_required,password_never_expires,reason");
    } else {
        fputs("{\"accounts\":[", stdout);
    }
    char msid[96] = "";
    int rc = sam ? offline(&c, sam, msid, sizeof msid) : live(&c, msid, sizeof msid);
    if (c.mode == 1) {
        fputs("],\"machine_sid\":", stdout);
        json_str(msid);
        puts("}");
    } else if (c.mode == 0) {
        printf("\nmachine SID %s; %u account(s), %u flagged\n", msid[0] ? msid : "-", c.count, c.flagged);
    }
    return rc;
}
