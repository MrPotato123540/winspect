// winspect shimcache - the Application Compatibility Cache (ShimCache)
//
// Windows keeps a cache of executables it has evaluated for compatibility
// shims, persisted as one REG_BINARY value:
//   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
//        value "AppCompatCache"
// Each entry is a full path plus that file's last-modified time. For DFIR it
// shows programs that EXISTED on the box - including ones since deleted - and
// their order is most-recent-first.
//
// Two honest caveats, also printed in the output:
//   * The registry copy is only written at shutdown/reboot; programs seen since
//     the last boot live only in kernel memory and are not shown here.
//   * On Windows 10+ an entry does NOT prove the program ran; the timestamp is
//     the FILE's modification time, not an execution time.
// We parse only the Windows 10/11 layout (portable parser in artparse.c,
// unit-tested on Linux). Reading the value normally needs elevation.

#include "shimcache.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHIM_KEY "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"

typedef struct {
    int mode;
    unsigned idx;
    unsigned flagged;
} shim_ctx;

static void ft_str(uint64_t t, char *out, size_t n)
{
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = (DWORD)t;
    ft.dwHighDateTime = (DWORD)(t >> 32);
    if (t == 0 || !FileTimeToSystemTime(&ft, &st)) {
        snprintf(out, n, "-");
        return;
    }
    snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

static void on_entry(const char *path, uint64_t modified, void *vctx)
{
    shim_ctx *c = (shim_ctx *)vctx;
    char ts[32];
    ft_str(modified, ts, sizeof ts);
    int uw = ioc_user_writable(path);
    c->flagged += (unsigned)uw;
    if (c->mode == 0) {
        printf("  %4u  %-19s  %s%s\n", c->idx, ts, path, uw ? "   [user-writable dir]" : "");
    } else if (c->mode == 2) {
        printf("%u,", c->idx);
        csv_str(ts);   putchar(',');
        csv_str(path);
        fputs(uw ? ",true\n" : ",false\n", stdout);
    } else {
        printf("%s{\"position\":%u,\"file_modified\":", c->idx ? "," : "", c->idx);
        json_str(ts);
        fputs(",\"path\":", stdout);
        json_str(path);
        printf(",\"user_writable_dir\":%s}", uw ? "true" : "false");
    }
    c->idx++;
}

int cmd_shimcache(int argc, char **argv)
{
    shim_ctx c = { 0, 0, 0 };
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else {
            fprintf(stderr, "shimcache: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    HKEY k;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SHIM_KEY, 0, KEY_READ | KEY_WOW64_64KEY, &k);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "shimcache: cannot open AppCompatCache key%s\n",
                rc == ERROR_ACCESS_DENIED ? " (access denied - run elevated)" : "");
        return 1;
    }
    DWORD size = 0;
    rc = RegQueryValueExA(k, "AppCompatCache", NULL, NULL, NULL, &size);
    unsigned char *buf = (rc == ERROR_SUCCESS && size > 0 && size < 64u * 1024 * 1024)
                         ? (unsigned char *)malloc(size) : NULL;
    if (buf == NULL ||
            RegQueryValueExA(k, "AppCompatCache", NULL, NULL, buf, &size) != ERROR_SUCCESS) {
        fprintf(stderr, "shimcache: cannot read the AppCompatCache value%s\n",
                rc == ERROR_ACCESS_DENIED ? " (access denied - run elevated)" : "");
        free(buf);
        RegCloseKey(k);
        return 1;
    }
    RegCloseKey(k);

    if (c.mode == 0) {
        puts("shimcache (AppCompatCache, newest first)\n");
        puts("  note: written at shutdown only; on Windows 10+ an entry shows the file");
        puts("        existed, not that it ran. Time = file last-modified, not run time.\n");
        printf("  %4s  %-19s  %s\n", "pos", "file modified (UTC)", "path");
    } else if (c.mode == 2) {
        puts("position,file_modified,path,user_writable_dir");
    } else {
        putchar('[');
    }

    int n = shim_parse(buf, size, on_entry, &c);
    free(buf);

    if (c.mode == 1) {
        puts("]");
    } else if (c.mode == 0) {
        if (n == -1) {
            puts("  (not the Windows 10/11 layout - older formats are not parsed)");
        } else {
            printf("\n%u entr%s, %u in user-writable dirs%s\n", c.idx, c.idx == 1 ? "y" : "ies",
                   c.flagged, n == -2 ? "  (stopped at a malformed entry)" : "");
        }
    }
    if (n == -1 && c.mode != 0) {
        fputs("shimcache: not the Windows 10/11 layout\n", stderr);
    }
    return 0;
}
