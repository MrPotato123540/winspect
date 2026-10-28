// winspect drivers - the kernel-mode modules loaded right now
//
// Unlike a process's DLLs, device drivers are global to the system, so PSAPI has
// a dedicated trio for them: EnumDeviceDrivers returns each driver's load
// address, and GetDeviceDriverBaseName / GetDeviceDriverFileName turn an address
// into a short name and a full path. Knowing what is loaded in the kernel - and
// where its file lives - is a standard baseline/triage question (a rogue or
// unsigned driver is a serious finding). This only reads the list; it loads
// nothing and touches no driver.
//
// --sig checks each driver file's signature (embedded or catalog - inbox
// drivers are catalog-signed). The kernel reports paths in its own forms
// (\SystemRoot\..., \??\C:\...), so they are normalised to Win32 paths first
// (drv_path_normalize, unit-tested). A driver file missing from disk or sitting
// in a user-writable directory is flagged as well.

#include "drivers.h"
#include "jsonutil.h"
#include "artparse.h"
#include "ioc.h"
#include "sign.h"

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>     // uintptr_t

#define DRV_MAX 4096

int cmd_drivers(int argc, char **argv)
{
    int mode = 0;   // 0 text, 1 json, 2 csv
    int sig = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--sig") == 0)  sig = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else {
            fprintf(stderr, "drivers: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    LPVOID bases[DRV_MAX];
    DWORD needed = 0;
    if (!EnumDeviceDrivers(bases, sizeof bases, &needed) || needed == 0) {
        fprintf(stderr, "drivers: EnumDeviceDrivers failed (error %lu)\n",
                (unsigned long)GetLastError());
        return 1;
    }
    unsigned n = needed / sizeof(LPVOID);
    if (n > DRV_MAX) {
        n = DRV_MAX;   // cap to what our fixed buffer actually holds
    }

    char windir[MAX_PATH] = "C:\\Windows";
    GetWindowsDirectoryA(windir, MAX_PATH);

    if (mode == 0) {
        printf("  %-18s %-24s %-5s %s\n", "base", "name", "flags", "path");
    } else if (mode == 2) {
        puts("base,name,path,missing_file,user_writable,signature");
    } else {
        putchar('[');
    }

    int first = 1;
    unsigned flagged = 0;
    for (unsigned i = 0; i < n; i++) {
        WCHAR wname[256] = L"", wraw[1024] = L"";
        GetDeviceDriverBaseNameW(bases[i], wname, 256);
        GetDeviceDriverFileNameW(bases[i], wraw, 1024);
        char name[512], raw[2048], path[2048];
        WideCharToMultiByte(CP_UTF8, 0, wname, -1, name, sizeof name, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, wraw, -1, raw, sizeof raw, NULL, NULL);
        drv_path_normalize(raw, windir, path, sizeof path);

        // Only judge paths we could turn into "X:\..." - an unfamiliar kernel
        // path form is reported as unknown ("?"), never as missing/unsigned.
        WCHAR wpath[1024];
        int resolvable = path[0] != '\0' && path[1] == ':' &&
                         MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 1024) > 0;
        int missing = resolvable && GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES;
        int uw = ioc_user_writable(path);
        const char *sigsrc = "";
        int trusted = 1;
        if (sig) {
            if (!resolvable) {
                sigsrc = "unknown";
            } else if (missing || !sign_file_trust(wpath, &sigsrc)) {
                trusted = 0;
                sigsrc = "untrusted";
            }
        }
        flagged += (unsigned)(missing || uw || !trusted);

        if (mode == 0) {
            char flags[8];
            snprintf(flags, sizeof flags, "%s%s%s", missing ? "M" : "-", uw ? "W" : "-",
                     !sig ? "" : (!resolvable ? "?" : (trusted ? "S" : "U")));
            printf("  0x%016llX %-24s %-5s %s\n",
                   (unsigned long long)(uintptr_t)bases[i],
                   name[0] ? name : "?", flags, path[0] ? path : "?");
        } else if (mode == 2) {
            printf("0x%016llX,", (unsigned long long)(uintptr_t)bases[i]);
            csv_str(name); putchar(',');
            csv_str(path);
            printf(",%d,%d,", missing ? 1 : 0, uw ? 1 : 0);
            csv_str(sigsrc); putchar('\n');
        } else {
            printf("%s{\"base\":\"0x%016llX\",\"name\":",
                   first ? "" : ",", (unsigned long long)(uintptr_t)bases[i]);
            json_str(name);
            fputs(",\"path\":", stdout); json_str(path);
            printf(",\"missing_file\":%s,\"user_writable\":%s,\"signature\":",
                   missing ? "true" : "false", uw ? "true" : "false");
            json_str(sigsrc);
            putchar('}');
            first = 0;
        }
    }

    if (mode == 0) {
        printf("\n%u driver(s), %u flagged   (flags: M=file missing, W=user-writable%s)\n",
               n, flagged, sig ? ", S=trusted signature, U=unsigned/untrusted, ?=path not resolvable" : "");
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
