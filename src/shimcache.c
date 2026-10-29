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
// We parse the Windows 10/11 and Windows 7 / 2008 R2 layouts (portable parser
// in artparse.c, unit-tested). On Windows 7 each entry also carries an
// "executed" InsertFlag, shown as yes/no; on 10/11 it is "-" (unknown).
// --hive reads an offline SYSTEM hive (control set from Select\Current).
// Reading the live value normally needs elevation.

#include "shimcache.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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

static void on_entry(const char *path, uint64_t modified, int executed, void *vctx)
{
    const char *ex = executed < 0 ? "-" : executed ? "yes" : "no";
    shim_ctx *c = (shim_ctx *)vctx;
    char ts[32];
    ft_str(modified, ts, sizeof ts);
    int uw = ioc_user_writable(path);
    c->flagged += (unsigned)uw;
    if (c->mode == 0) {
        printf("  %4u  %-19s  %-4s %s%s\n", c->idx, ts, ex, path, uw ? "   [user-writable dir]" : "");
    } else if (c->mode == 2) {
        printf("%u,", c->idx);
        csv_str(ts);   putchar(',');
        csv_str(path);
        fputs(uw ? ",true," : ",false,", stdout);
        puts(executed < 0 ? "" : executed ? "true" : "false");
    } else {
        printf("%s{\"position\":%u,\"file_modified\":", c->idx ? "," : "", c->idx);
        json_str(ts);
        fputs(",\"path\":", stdout);
        json_str(path);
        printf(",\"user_writable_dir\":%s,\"executed\":%s}", uw ? "true" : "false",
               executed < 0 ? "null" : executed ? "true" : "false");
    }
    c->idx++;
}

int cmd_shimcache(int argc, char **argv)
{
    shim_ctx c = { 0, 0, 0 };
    const char *hive = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "--hive") == 0 && a + 1 < argc) hive = argv[++a];
        else {
            fprintf(stderr, "shimcache: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    regsrc src;
    if (hive != NULL) {
        char err[512];
        if (regsrc_open_hive(&src, hive, err, sizeof err) != 0) {
            fprintf(stderr, "shimcache: %s\n", err);
            return 1;
        }
        if (regsrc_dirty(&src)) fputs("shimcache: note: hive is dirty (transaction logs not replayed)\n", stderr);
    } else if (regsrc_open_live(&src, HKEY_LOCAL_MACHINE, "SYSTEM", "HKLM\\SYSTEM") != ERROR_SUCCESS) {
        fputs("shimcache: cannot open HKLM\\SYSTEM\n", stderr);
        return 1;
    }
    char cs[32], path[200];
    regsrc_control_set(&src, cs, sizeof cs);
    snprintf(path, sizeof path, "%s\\Control\\Session Manager\\AppCompatCache", cs);
    rkey k;
    int rc = rk_open(&src, path, &k);
    if (rc != 0) {
        fprintf(stderr, "shimcache: cannot open AppCompatCache key%s\n",
                rc == ERROR_ACCESS_DENIED ? " (access denied - run elevated)" : "");
        regsrc_close(&src);
        return 1;
    }
    // Value size first, then the data (it is usually a few hundred KB).
    uint32_t type = 0;
    unsigned char probe[1];
    long size = rk_get(&src, &k, "AppCompatCache", &type, probe, 0);
    unsigned char *buf = (size > 0 && size < 64L * 1024 * 1024) ? (unsigned char *)malloc((size_t)size) : NULL;
    if (buf == NULL || rk_get(&src, &k, "AppCompatCache", &type, buf, (size_t)size) != size) {
        fputs("shimcache: cannot read the AppCompatCache value\n", stderr);
        free(buf);
        rk_close(&k);
        regsrc_close(&src);
        return 1;
    }
    rk_close(&k);

    if (c.mode == 0) {
        printf("shimcache (AppCompatCache in %s, newest first)\n\n", src.label);
        puts("  note: written at shutdown only; on Windows 10+ an entry shows the file");
        puts("        existed, not that it ran. Time = file last-modified, not run time.");
        puts("        'exec' is the Windows 7 InsertFlags executed bit ('-' = not recorded).\n");
        printf("  %4s  %-19s  %-4s %s\n", "pos", "file modified (UTC)", "exec", "path");
    } else if (c.mode == 2) {
        puts("position,file_modified,path,user_writable_dir,executed");
    } else {
        putchar('[');
    }

    const char *fmt = "";
    int n = shim_parse_ex(buf, (size_t)size, on_entry, &c, &fmt);
    free(buf);
    regsrc_close(&src);

    if (c.mode == 1) {
        puts("]");
    } else if (c.mode == 0) {
        if (n == -1) {
            puts("  (layout not supported: only Windows 7 and 10/11 caches are parsed)");
        } else {
            printf("\n%u entr%s (%s layout), %u in user-writable dirs%s\n", c.idx, c.idx == 1 ? "y" : "ies",
                   fmt, c.flagged, n == -2 ? "  (stopped at a malformed entry)" : "");
        }
    }
    if (n == -1 && c.mode != 0) {
        fputs("shimcache: layout not supported (only Windows 7 and 10/11)\n", stderr);
    }
    return 0;
}
