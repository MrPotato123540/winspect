// winspect bam - Background Activity Moderator (BAM) execution records
//
// BAM is the Windows 10 (1709+) service that throttles background apps. As a
// side effect it records, per user, the executables that ran and when:
//   HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
//   (older builds: ...\bam\UserSettings\<SID>)
// BOTH locations are read: a machine upgraded from 1709 often still has the
// old key with older records that the new one no longer lists; each record
// says which location it came from.
// Each REG_BINARY value is named by the program's path (a \Device\Harddisk-
// VolumeN\... path for desktop programs, a package name for Store apps) and its
// data starts with a FILETIME: the last execution time (UTC). The other values
// in the key (Version, SequenceNumber) are DWORDs and are skipped.
//
// Unlike ShimCache this IS execution evidence, and unlike Prefetch it is tied
// to a user. Entries for programs not run for a while are pruned by Windows.
// Read-only; the key normally requires elevation, reported clearly if denied.
// --hive reads an offline SYSTEM hive instead (control set from Select\Current);
// SIDs are then not resolved to names - this machine does not know them.

#include "bam.h"
#include "ioc.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int mode;
    int first;
    unsigned count;
    unsigned flagged;
    regsrc *src;
    const char *sid;
    const char *where;          // "State" or "legacy"
    char account[600];
} bam_ctx;

// "S-1-5-21-..." -> "DOMAIN\user" when the SID resolves; else leave the SID.
static void sid_to_account(const char *sidstr, char *out, size_t n)
{
    snprintf(out, n, "%s", sidstr);
    PSID sid = NULL;
    if (!ConvertStringSidToSidA(sidstr, &sid)) {
        return;
    }
    char name[256], dom[256];
    DWORD nl = sizeof name, dl = sizeof dom;
    SID_NAME_USE use;
    if (LookupAccountSidA(NULL, sid, name, &nl, dom, &dl, &use)) {
        snprintf(out, n, "%s\\%s", dom, name);
    }
    LocalFree(sid);
}

static void ft_str(const FILETIME *ft, char *out, size_t n)
{
    SYSTEMTIME st;
    if ((ft->dwLowDateTime == 0 && ft->dwHighDateTime == 0) || !FileTimeToSystemTime(ft, &st)) {
        snprintf(out, n, "-");
        return;
    }
    snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

static void on_value(const char *path, uint32_t type, const unsigned char *data, size_t len, void *vctx)
{
    bam_ctx *c = (bam_ctx *)vctx;
    if (type != REG_BINARY || len < 8 || data == NULL) {
        return;     // Version / SequenceNumber and anything malformed
    }
    FILETIME ft;
    memcpy(&ft, data, sizeof ft);
    char ts[32];
    ft_str(&ft, ts, sizeof ts);
    int uw = ioc_user_writable(path);
    c->count++;
    c->flagged += (unsigned)uw;
    if (c->mode == 0) {
        printf("    %-19s  %s%s%s\n", ts, path, uw ? "   [user-writable dir]" : "",
               strcmp(c->where, "legacy") == 0 ? "   (legacy key)" : "");
    } else if (c->mode == 2) {
        csv_str(c->account); putchar(',');
        csv_str(c->sid);     putchar(',');
        csv_str(ts);         putchar(',');
        csv_str(path);
        fputs(uw ? ",true," : ",false,", stdout);
        csv_str(c->where); putchar('\n');
    } else {
        printf("%s{\"user\":", c->first ? "" : ",");
        json_str(c->account);
        fputs(",\"sid\":", stdout);      json_str(c->sid);
        fputs(",\"last_run\":", stdout); json_str(ts);
        fputs(",\"path\":", stdout);     json_str(path);
        printf(",\"user_writable_dir\":%s,\"location\":", uw ? "true" : "false");
        json_str(c->where);
        putchar('}');
        c->first = 0;
    }
}

typedef struct { char sids[256][128]; int n; } sidlist;
static void on_sid(const char *name, void *vctx)
{
    sidlist *l = (sidlist *)vctx;
    if (l->n < 256) snprintf(l->sids[l->n++], sizeof l->sids[0], "%s", name);
}

int cmd_bam(int argc, char **argv)
{
    bam_ctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *hive = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "--hive") == 0 && a + 1 < argc) hive = argv[++a];
        else {
            fprintf(stderr, "bam: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    regsrc src;
    if (hive != NULL) {
        char err[512];
        if (regsrc_open_hive(&src, hive, err, sizeof err) != 0) {
            fprintf(stderr, "bam: %s\n", err);
            return 1;
        }
        if (regsrc_dirty(&src)) fputs("bam: note: hive is dirty (transaction logs not replayed)\n", stderr);
    } else if (regsrc_open_live(&src, HKEY_LOCAL_MACHINE, "SYSTEM", "HKLM\\SYSTEM") != ERROR_SUCCESS) {
        fputs("bam: cannot open HKLM\\SYSTEM\n", stderr);
        return 1;
    }
    c.src = &src;
    char cs[32], roots[2][160];
    regsrc_control_set(&src, cs, sizeof cs);
    snprintf(roots[0], sizeof roots[0], "%s\\Services\\bam\\State\\UserSettings", cs);
    snprintf(roots[1], sizeof roots[1], "%s\\Services\\bam\\UserSettings", cs);
    static const char *const where[2] = { "State", "legacy" };
    int found = 0, denied = 0;
    static sidlist sl[2];
    for (int i = 0; i < 2; i++) {
        rkey users;
        sl[i].n = 0;
        int r = rk_open(&src, roots[i], &users);
        if (r == ERROR_ACCESS_DENIED) denied = 1;
        if (r != 0) continue;
        found = 1;
        rk_subkeys(&src, &users, on_sid, &sl[i]);
        rk_close(&users);
    }
    if (!found) {
        regsrc_close(&src);
        if (denied) {
            fputs("bam: access denied - run elevated\n", stderr);
            return 1;
        }
        // No BAM key: Windows older than 10 1709, or BAM disabled.
        if (c.mode == 1)      puts("[]");
        else if (c.mode == 2) puts("user,sid,last_run,path,user_writable_dir,location");
        else                  puts("bam: no BAM records (needs Windows 10 1709+)");
        return 0;
    }

    if (c.mode == 0) {
        printf("bam (Background Activity Moderator, %s) - last run per program, UTC\n", src.label);
    } else if (c.mode == 2) {
        puts("user,sid,last_run,path,user_writable_dir,location");
    } else {
        putchar('[');
    }
    for (int r = 0; r < 2; r++) {
        for (int i = 0; i < sl[r].n; i++) {
            rkey k;
            char path[400];
            snprintf(path, sizeof path, "%s\\%s", roots[r], sl[r].sids[i]);
            if (rk_open(&src, path, &k) != 0) continue;
            c.sid = sl[r].sids[i];
            c.where = where[r];
            if (hive == NULL) sid_to_account(c.sid, c.account, sizeof c.account);
            else snprintf(c.account, sizeof c.account, "%s", c.sid);
            if (c.mode == 0) printf("\n  %s  (%s)%s\n", c.account, c.sid, r ? "  [legacy bam\\UserSettings]" : "");
            rk_values(&src, &k, on_value, &c);
            rk_close(&k);
        }
    }
    regsrc_close(&src);

    if (c.mode == 0) {
        printf("\n%u record(s), %u in user-writable dirs\n", c.count, c.flagged);
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
