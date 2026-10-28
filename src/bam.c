// winspect bam - Background Activity Moderator (BAM) execution records
//
// BAM is the Windows 10 (1709+) service that throttles background apps. As a
// side effect it records, per user, the executables that ran and when:
//   HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
//   (older builds: ...\bam\UserSettings\<SID>)
// Each REG_BINARY value is named by the program's path (a \Device\Harddisk-
// VolumeN\... path for desktop programs, a package name for Store apps) and its
// data starts with a FILETIME: the last execution time (UTC). The other values
// in the key (Version, SequenceNumber) are DWORDs and are skipped.
//
// Unlike ShimCache this IS execution evidence, and unlike Prefetch it is tied
// to a user. Entries for programs not run for a while are pruned by Windows.
// Read-only; the key normally requires elevation, reported clearly if denied.

#include "bam.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int mode;
    int first;
    unsigned count;
    unsigned flagged;
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

static void enum_user(bam_ctx *c, HKEY users, const char *sid)
{
    HKEY k;
    if (RegOpenKeyExA(users, sid, 0, KEY_READ, &k) != ERROR_SUCCESS) {
        return;
    }
    char account[600];
    sid_to_account(sid, account, sizeof account);
    if (c->mode == 0) {
        printf("\n  %s  (%s)\n", account, sid);
    }
    for (DWORD i = 0;; i++) {
        WCHAR wname[1024];
        DWORD nl = sizeof wname / sizeof wname[0];
        BYTE data[64];
        DWORD dl = sizeof data, type = 0;
        LONG rc = RegEnumValueW(k, i, wname, &nl, NULL, &type, data, &dl);
        if (rc == ERROR_MORE_DATA) {
            continue;   // unusually large value: not a BAM record
        }
        if (rc != ERROR_SUCCESS) {
            break;
        }
        if (type != REG_BINARY || dl < 8) {
            continue;   // Version / SequenceNumber and anything malformed
        }
        char path[2048];
        int got = WideCharToMultiByte(CP_UTF8, 0, wname, (int)nl, path, sizeof path - 1, NULL, NULL);
        path[(got > 0) ? got : 0] = '\0';
        FILETIME ft;
        memcpy(&ft, data, sizeof ft);
        char ts[32];
        ft_str(&ft, ts, sizeof ts);
        int uw = ioc_user_writable(path);
        c->count++;
        c->flagged += (unsigned)uw;
        if (c->mode == 0) {
            printf("    %-19s  %s%s\n", ts, path, uw ? "   [user-writable dir]" : "");
        } else if (c->mode == 2) {
            csv_str(account); putchar(',');
            csv_str(sid);     putchar(',');
            csv_str(ts);      putchar(',');
            csv_str(path);
            fputs(uw ? ",true\n" : ",false\n", stdout);
        } else {
            printf("%s{\"user\":", c->first ? "" : ",");
            json_str(account);
            fputs(",\"sid\":", stdout);      json_str(sid);
            fputs(",\"last_run\":", stdout); json_str(ts);
            fputs(",\"path\":", stdout);     json_str(path);
            printf(",\"user_writable_dir\":%s}", uw ? "true" : "false");
            c->first = 0;
        }
    }
    RegCloseKey(k);
}

int cmd_bam(int argc, char **argv)
{
    bam_ctx c = { 0, 1, 0, 0 };
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else {
            fprintf(stderr, "bam: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    static const char *roots[] = {
        "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        "SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
    };
    HKEY users = NULL;
    LONG rc = ERROR_FILE_NOT_FOUND;
    for (size_t i = 0; i < sizeof roots / sizeof roots[0] && users == NULL; i++) {
        LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, roots[i], 0, KEY_READ, &users);
        if (r != ERROR_SUCCESS) {
            users = NULL;
            if (rc != ERROR_ACCESS_DENIED) {
                rc = r;     // remember "denied" over "not found"
            }
        }
    }
    if (users == NULL) {
        if (rc == ERROR_ACCESS_DENIED) {
            fputs("bam: access denied - run elevated\n", stderr);
            return 1;
        }
        // No BAM key: Windows older than 10 1709, or BAM disabled.
        if (c.mode == 1)      puts("[]");
        else if (c.mode == 2) puts("user,sid,last_run,path,user_writable_dir");
        else                  puts("bam: no BAM records (needs Windows 10 1709+)");
        return 0;
    }

    if (c.mode == 0) {
        puts("bam (Background Activity Moderator) - last run per program, UTC");
    } else if (c.mode == 2) {
        puts("user,sid,last_run,path,user_writable_dir");
    } else {
        putchar('[');
    }
    for (DWORD i = 0;; i++) {
        char sid[256];
        DWORD sl = sizeof sid;
        if (RegEnumKeyExA(users, i, sid, &sl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        enum_user(&c, users, sid);
    }
    RegCloseKey(users);

    if (c.mode == 0) {
        printf("\n%u record(s), %u in user-writable dirs\n", c.count, c.flagged);
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
