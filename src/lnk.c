// winspect lnk - shortcut (.lnk) files as evidence and as launchers
//
// Shortcuts matter twice in an investigation:
//   * Evidence: Windows drops a .lnk into %APPDATA%\Microsoft\Windows\Recent
//     for every file/folder a user opens. Each records the target's path and
//     timestamps AS THEY WERE when the link was made - even if the target was
//     on a USB stick that is long gone. (LECmd reads the same structure.)
//   * Launcher: a malicious .lnk (mailed, on a USB stick, in Startup) can run
//     "powershell -enc ..." while showing a harmless icon.
// Parsing is done by the portable lnkparse.c ([MS-SHLLINK], unit-tested); this
// file only finds and reads the files. Flags, each with a reason:
//   * target is a script host / LOLBin (powershell, mshta, rundll32, ...)
//   * target lives in a user-writable directory
// Read-only: files are opened for reading only; nothing is resolved or run.

#include "lnk.h"
#include "lnkparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LNK_MAX_FILE (4u * 1024 * 1024)

typedef struct {
    int mode;
    int first;
    unsigned count, flagged, failed;
} lnk_ctx;

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

// Reads and parses one .lnk; returns 0 on success.
int lnk_load(const wchar_t *wpath, lnk_info *info)
{
    HANDLE h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE |
                           FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }
    LARGE_INTEGER sz;
    unsigned char *buf = NULL;
    DWORD got = 0;
    int rc = -1;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart <= LNK_MAX_FILE &&
            (buf = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL &&
            ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL) && got == (DWORD)sz.QuadPart) {
        rc = lnk_parse(buf, got, info);
        if (rc == -2 && info->target[0] != '\0') {
            rc = 0;     // truncated tail, but the useful part was read
        }
    }
    free(buf);
    CloseHandle(h);
    return rc;
}

static void report(lnk_ctx *c, const char *file, const lnk_info *li)
{
    char cmdline[3200];
    snprintf(cmdline, sizeof cmdline, "%s%s%s", li->target, li->arguments[0] ? " " : "",
             li->arguments);
    const char *reason = lnk_anomaly_reason(li->anomalies);
    if (reason == NULL && ioc_script_host(li->target))   reason = "target is a script host / LOLBin";
    else if (reason == NULL && ioc_user_writable(li->target)) reason = "target in user-writable dir";
    // Where the target lived: "removable, serial 1A2B-3C4D, label "USB"" -
    // a removable or network volume answers "was this opened from a stick /
    // a share?"; the tracker block names the machine the link was made on.
    char vol[160] = "";
    if (li->has_volume) {
        snprintf(vol, sizeof vol, "%s, serial %04X-%04X%s%s%s", lnk_drive_type_name(li->drive_type),
                 (unsigned)(li->drive_serial >> 16), (unsigned)(li->drive_serial & 0xFFFF),
                 li->volume_label[0] ? ", label \"" : "", li->volume_label,
                 li->volume_label[0] ? "\"" : "");
    }

    char cts[32], wts[32];
    ft_str(li->created, cts, sizeof cts);
    ft_str(li->written, wts, sizeof wts);
    c->count++;
    if (reason) { c->flagged++; }

    if (c->mode == 0) {
        printf("  %s%s\n", reason ? "[!] " : "    ", file);
        printf("        -> %s\n", cmdline[0] ? cmdline : "(no path - shell namespace target)");
        if (li->workdir[0]) {
            printf("        in %s\n", li->workdir);
        }
        printf("        target created %s, modified %s, %lu bytes\n", cts, wts,
               (unsigned long)li->file_size);
        if (vol[0])            printf("        volume %s\n", vol);
        if (li->net_share[0])  printf("        share  %s\n", li->net_share);
        if (li->machine_id[0] || li->mac[0])
            printf("        made on %s%s%s\n", li->machine_id[0] ? li->machine_id : "?",
                   li->mac[0] ? ", MAC " : "", li->mac);
        if (reason) {
            printf("        <- %s\n", reason);
        }
    } else if (c->mode == 2) {
        csv_str(file);          putchar(',');
        csv_str(li->target);    putchar(',');
        csv_str(li->arguments); putchar(',');
        csv_str(li->workdir);   putchar(',');
        csv_str(cts);           putchar(',');
        csv_str(wts);           printf(",%lu,", (unsigned long)li->file_size);
        csv_str(li->has_volume ? lnk_drive_type_name(li->drive_type) : ""); putchar(',');
        if (li->has_volume) printf("%08X", (unsigned)li->drive_serial);
        putchar(',');
        csv_str(li->volume_label); putchar(',');
        csv_str(li->net_share);    putchar(',');
        csv_str(li->machine_id);   putchar(',');
        csv_str(li->mac);          putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"file\":", c->first ? "" : ",");
        json_str(file);
        fputs(",\"target\":", stdout);         json_str(li->target);
        fputs(",\"arguments\":", stdout);      json_str(li->arguments);
        fputs(",\"working_dir\":", stdout);    json_str(li->workdir);
        fputs(",\"description\":", stdout);    json_str(li->name);
        fputs(",\"target_created\":", stdout); json_str(cts);
        fputs(",\"target_modified\":", stdout); json_str(wts);
        printf(",\"target_size\":%lu", (unsigned long)li->file_size);
        fputs(",\"drive_type\":", stdout);
        if (li->has_volume) json_str(lnk_drive_type_name(li->drive_type)); else fputs("null", stdout);
        fputs(",\"volume_serial\":", stdout);
        if (li->has_volume) printf("\"%08X\"", (unsigned)li->drive_serial); else fputs("null", stdout);
        fputs(",\"volume_label\":", stdout); json_str(li->volume_label);
        fputs(",\"network_share\":", stdout); json_str(li->net_share);
        fputs(",\"machine_id\":", stdout);   json_str(li->machine_id);
        fputs(",\"mac\":", stdout);          json_str(li->mac);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void one(lnk_ctx *c, const WCHAR *wpath)
{
    char file[1024];
    WideCharToMultiByte(CP_UTF8, 0, wpath, -1, file, sizeof file, NULL, NULL);
    lnk_info li;
    if (lnk_load(wpath, &li) != 0) {
        c->failed++;
        if (c->mode == 0) {
            printf("  ?   %s  (not a readable shell link)\n", file);
        }
        return;
    }
    report(c, file, &li);
}

int cmd_lnk(int argc, char **argv)
{
    lnk_ctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *target = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (target == NULL)                 target = argv[a];
        else {
            fprintf(stderr, "lnk: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    WCHAR wtarget[MAX_PATH];
    if (target != NULL) {
        MultiByteToWideChar(CP_UTF8, 0, target, -1, wtarget, MAX_PATH);
    } else {
        // Default: this user's Recent folder.
        DWORD n = GetEnvironmentVariableW(L"APPDATA", wtarget, MAX_PATH);
        if (n == 0 || n > MAX_PATH - 40) {
            fputs("lnk: cannot resolve %APPDATA%\n", stderr);
            return 1;
        }
        wcscat(wtarget, L"\\Microsoft\\Windows\\Recent");
    }

    DWORD attr = GetFileAttributesW(wtarget);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "lnk: cannot open '%s'\n", target ? target : "Recent folder");
        return 1;
    }

    if (c.mode == 2) {
        puts("file,target,arguments,working_dir,target_created,target_modified,target_size,"
             "drive_type,volume_serial,volume_label,network_share,machine_id,mac,reason");
    } else if (c.mode == 1) {
        putchar('[');
    }

    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        one(&c, wtarget);
    } else {
        if (c.mode == 0) {
            char u[1024];
            WideCharToMultiByte(CP_UTF8, 0, wtarget, -1, u, sizeof u, NULL, NULL);
            printf("lnk  %s\n\n", u);
        }
        WCHAR pattern[MAX_PATH + 8];
        _snwprintf(pattern, MAX_PATH + 8, L"%ls\\*.lnk", wtarget);
        pattern[MAX_PATH + 7] = 0;
        WIN32_FIND_DATAW fd;
        HANDLE fh = FindFirstFileW(pattern, &fd);
        if (fh != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    continue;
                }
                WCHAR full[MAX_PATH * 2];
                _snwprintf(full, MAX_PATH * 2, L"%ls\\%ls", wtarget, fd.cFileName);
                full[MAX_PATH * 2 - 1] = 0;
                one(&c, full);
            } while (FindNextFileW(fh, &fd));
            FindClose(fh);
        }
    }

    if (c.mode == 1) {
        puts("]");
    } else if (c.mode == 0) {
        printf("\n%u shortcut(s), %u flagged%s\n", c.count, c.flagged,
               c.failed ? ", some unreadable" : "");
    }
    return (c.count == 0 && c.failed > 0) ? 1 : 0;
}
