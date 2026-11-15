// pidarg - PID or image name -> PID. See inc/pidarg.h.

#include "pidarg.h"

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// "explorer" matches "explorer.exe"; "explorer.exe" matches itself.
static int name_matches(const char *want, const char *image)
{
    size_t w = strlen(want);
    if (_stricmp(want, image) == 0) return 1;
    return _strnicmp(want, image, w) == 0 && _stricmp(image + w, ".exe") == 0;
}

int pid_from_arg(const char *cmd, const char *arg, unsigned long *pid)
{
    char *end = NULL;
    unsigned long n = strtoul(arg, &end, 10);
    if (end != arg && *end == '\0') {
        if (n == 0) { fprintf(stderr, "%s: '%s' is not a valid pid\n", cmd, arg); return 0; }
        *pid = n;
        return 1;
    }
    if (arg[0] == '\0' || (arg[0] >= '0' && arg[0] <= '9')) {     // "12ab"
        fprintf(stderr, "%s: '%s' is not a valid pid or process name\n", cmd, arg);
        return 0;
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "%s: cannot list processes to find '%s' (error %lu)\n", cmd, arg, (unsigned long)GetLastError());
        return 0;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof pe;
    unsigned long found[64];
    unsigned count = 0;
    char image[MAX_PATH] = "";
    if (Process32First(snap, &pe)) {
        do {
            if (!name_matches(arg, pe.szExeFile)) continue;
            if (count < sizeof found / sizeof found[0]) found[count] = pe.th32ProcessID;
            if (count == 0) snprintf(image, sizeof image, "%s", pe.szExeFile);
            count++;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    if (count == 1) { *pid = found[0]; return 1; }
    if (count == 0) {
        fprintf(stderr, "%s: no running process is named '%s' (give a pid or an image name such as explorer.exe)\n", cmd, arg);
        return 0;
    }
    fprintf(stderr, "%s: %u processes are named %s - give one pid:", cmd, count, image);
    for (unsigned i = 0; i < count && i < sizeof found / sizeof found[0]; i++) fprintf(stderr, " %lu", found[i]);
    if (count > sizeof found / sizeof found[0]) fputs(" ...", stderr);
    fputc('\n', stderr);
    return 0;
}
