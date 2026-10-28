// winspect modules - the loaded modules of a live process
//
// EnumProcessModulesEx lists every module mapped into a process (its EXE and all
// DLLs); GetModuleInformation gives each one's base and size, and
// GetModuleFileNameEx its path. Beyond a plain list, two cheap flags carry real
// signal: a module whose backing file is GONE from disk (loaded then deleted - a
// hollowing / anti-forensics tell) and a module loaded from a user-writable or
// temporary directory (unusual for a legitimate DLL). Read-only.

#include "modules.h"
#include "jsonutil.h"
#include "ioc.h"
#include "sign.h"

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define MODS_MAX 4096

int cmd_modules(int argc, char **argv)
{
    const char *pid_arg = NULL;
    int mode = 0;   // 0 text, 1 json, 2 csv
    int sig = 0, only_unsigned = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--sig") == 0)  sig = 1;
        else if (strcmp(argv[a], "--unsigned") == 0) { sig = 1; only_unsigned = 1; }
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else if (pid_arg == NULL)                pid_arg = argv[a];
        else {
            fprintf(stderr, "modules: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (pid_arg == NULL) {
        fputs("usage: winspect modules <pid> [--sig | --unsigned] [--json | --csv]\n", stderr);
        return 1;
    }
    char *end = NULL;
    unsigned long pid = strtoul(pid_arg, &end, 10);
    if (end == pid_arg || *end != '\0' || pid == 0) {
        fprintf(stderr, "modules: '%s' is not a valid pid\n", pid_arg);
        return 1;
    }

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h == NULL) {
        DWORD err = GetLastError();
        fprintf(stderr, "modules: cannot open pid %lu (error %lu)\n", pid, (unsigned long)err);
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "         (try an elevated console)\n");
        }
        return 1;
    }

    HMODULE mods[MODS_MAX];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(h, mods, sizeof mods, &needed, LIST_MODULES_ALL)) {
        fprintf(stderr, "modules: EnumProcessModulesEx failed (error %lu)\n",
                (unsigned long)GetLastError());
        CloseHandle(h);
        return 1;
    }
    unsigned n = needed / sizeof(HMODULE);
    if (n > MODS_MAX) {
        n = MODS_MAX;
    }

    if (mode == 0) {
        printf("process  pid %lu\n\n", pid);
        printf("  %-18s %-10s %-9s %s\n", "base", "size", "flags", "path");
    } else if (mode == 2) {
        puts("base,size,path,missing_file,user_writable,signature");
    } else {
        putchar('[');
    }

    unsigned count = 0, untrusted = 0;
    for (unsigned i = 0; i < n; i++) {
        // Wide API so non-ASCII paths survive (the -A variant mangles them).
        WCHAR wpath[1024] = L"";
        char path[2048] = "";
        if (GetModuleFileNameExW(h, mods[i], wpath, 1024) > 0) {
            WideCharToMultiByte(CP_UTF8, 0, wpath, -1, path, sizeof path, NULL, NULL);
        }
        MODULEINFO mi;
        ZeroMemory(&mi, sizeof mi);
        GetModuleInformation(h, mods[i], &mi, sizeof mi);

        int missing = (wpath[0] != 0) &&
                      (GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES);
        int uw = ioc_user_writable(path);

        // Optional signature check (ListDLLs -u idea): trusted embedded or
        // catalog signature. Off by default - WinVerifyTrust per module is slow.
        const char *sigsrc = "";
        int trusted = 1;
        if (sig) {
            trusted = !missing && wpath[0] != 0 && sign_file_trust(wpath, &sigsrc);
            if (!trusted) {
                sigsrc = "untrusted";
                untrusted++;
            }
            if (only_unsigned && trusted) {
                continue;
            }
        }

        count++;
        if (mode == 0) {
            char flags[16];
            snprintf(flags, sizeof flags, "%s%s%s",
                     missing ? "M" : "-", uw ? "W" : "-", !sig ? "" : (trusted ? "S" : "U"));
            printf("  0x%016llX %-10lu %-9s %s%s\n",
                   (unsigned long long)(uintptr_t)mi.lpBaseOfDll,
                   (unsigned long)mi.SizeOfImage, flags,
                   path[0] ? path : "(unknown)",
                   missing ? "   <= file missing from disk" : "");
        } else if (mode == 2) {
            printf("0x%016llX,%lu,", (unsigned long long)(uintptr_t)mi.lpBaseOfDll,
                   (unsigned long)mi.SizeOfImage);
            csv_str(path);
            printf(",%d,%d,", missing ? 1 : 0, uw ? 1 : 0);
            csv_str(sigsrc);
            putchar('\n');
        } else {
            printf("%s{\"base\":\"0x%016llX\",\"size\":%lu,\"path\":",
                   count > 1 ? "," : "",
                   (unsigned long long)(uintptr_t)mi.lpBaseOfDll,
                   (unsigned long)mi.SizeOfImage);
            json_str(path);
            printf(",\"missing_file\":%s,\"user_writable\":%s,\"signature\":",
                   missing ? "true" : "false", uw ? "true" : "false");
            json_str(sigsrc);
            putchar('}');
        }
    }

    CloseHandle(h);
    if (mode == 0) {
        printf("\n%u module(s)   (flags: M=file missing, W=user-writable path%s)\n", count,
               sig ? ", S=trusted signature, U=unsigned/untrusted" : "");
        if (sig) {
            printf("%u module(s) without a trusted signature\n", untrusted);
        }
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
