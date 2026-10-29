// winspect pshistory - PSReadLine command history
//
// Since Windows 10 / PowerShell 5, PSReadLine appends every interactive
// command to a plain text file per user and host:
//   %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\<Host>_history.txt
// (ConsoleHost_history.txt for powershell.exe / pwsh). Commands that span
// several lines end their inner lines with a backtick. The file survives
// logoff and is a first stop when an intruder had an interactive session;
// its last-write time is roughly the time of the last command. Lines are
// judged by ioc_ps_reason (ioc.c, unit-tested). Read-only.

#include "pshistory.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PS_REL "Microsoft\\Windows\\PowerShell\\PSReadLine"
#define MAX_FILE (64u * 1024 * 1024)

typedef struct {
    int mode, first, only_flagged;
    unsigned lines, flagged, files;
} pctx;

static void ft_str(const FILETIME *f, char *out, size_t n)
{
    SYSTEMTIME st;
    if ((f->dwLowDateTime == 0 && f->dwHighDateTime == 0) || !FileTimeToSystemTime(f, &st)) {
        snprintf(out, n, "-");
        return;
    }
    snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

static void one_file(pctx *c, const char *path, const char *user)
{
    WCHAR w[MAX_PATH * 2];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, w, MAX_PATH * 2);
    HANDLE h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz;
    FILETIME lw = { 0, 0 };
    GetFileTime(h, NULL, NULL, &lw);
    char *buf = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart >= 0 && sz.QuadPart <= MAX_FILE &&
            (buf = (char *)malloc((size_t)sz.QuadPart + 1)) != NULL) {
        if (!ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL)) got = 0;
        buf[got] = '\0';
    }
    CloseHandle(h);
    if (buf == NULL) return;
    c->files++;
    char when[32];
    ft_str(&lw, when, sizeof when);
    if (c->mode == 0) printf("\n%s  (%s, last written %s)\n", path, user, when);
    // UTF-8 (optionally with BOM); lines end with \n or \r\n.
    char *p = buf;
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) p += 3;
    unsigned lineno = 0;
    while (*p) {
        char *e = strchr(p, '\n');
        if (e) *e = '\0';
        size_t L = strlen(p);
        if (L && p[L - 1] == '\r') p[--L] = '\0';
        lineno++;
        if (L) {
            const char *reason = ioc_ps_reason(p);
            c->lines++;
            if (reason) c->flagged++;
            if (!(c->only_flagged && reason == NULL)) {
                if (c->mode == 0) {
                    printf("  %s%5u  %s\n", reason ? "[!] " : "    ", lineno, p);
                    if (reason) printf("               <- %s\n", reason);
                } else if (c->mode == 2) {
                    csv_str(user); putchar(',');
                    csv_str(path); printf(",%u,", lineno);
                    csv_str(p); putchar(',');
                    csv_str(reason ? reason : ""); putchar('\n');
                } else {
                    printf("%s{\"user\":", c->first ? "" : ",");
                    json_str(user);
                    fputs(",\"file\":", stdout);         json_str(path);
                    fputs(",\"file_written\":", stdout); json_str(when);
                    printf(",\"line\":%u,\"command\":", lineno);
                    json_str(p);
                    printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
                    json_str(reason ? reason : "");
                    putchar('}');
                    c->first = 0;
                }
            }
        }
        if (!e) break;
        p = e + 1;
    }
    free(buf);
}

// Every *_history.txt in a PSReadLine folder.
static void scan_dir(pctx *c, const char *dir, const char *user)
{
    char pat[MAX_PATH * 2];
    snprintf(pat, sizeof pat, "%s\\*_history.txt", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char full[MAX_PATH * 2];
        snprintf(full, sizeof full, "%s\\%s", dir, fd.cFileName);
        one_file(c, full, user);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int cmd_pshistory(int argc, char **argv)
{
    pctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *target = NULL;
    int all = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)            c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)        c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)    c.only_flagged = 1;
        else if (strcmp(argv[a], "--all-users") == 0)  all = 1;
        else if (target == NULL)                       target = argv[a];
        else {
            fprintf(stderr, "pshistory: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (c.mode == 0) {
        puts("pshistory  (PSReadLine command history, oldest first)");
    } else if (c.mode == 2) {
        puts("user,file,line,command,reason");
    } else {
        putchar('[');
    }
    if (target != NULL) {
        DWORD attr = GetFileAttributesA(target);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            if (c.mode == 1) puts("]");
            fprintf(stderr, "pshistory: cannot open '%s'\n", target);
            return 1;
        }
        if (attr & FILE_ATTRIBUTE_DIRECTORY) scan_dir(&c, target, "-");
        else one_file(&c, target, "-");
    } else if (all) {
        // Every profile folder under the Users directory (default C:\Users).
        char users[MAX_PATH] = "C:\\Users";
        DWORD n = GetEnvironmentVariableA("PUBLIC", users, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            char *s = strrchr(users, '\\');
            if (s) *s = '\0';
        }
        char pat[MAX_PATH + 4];
        snprintf(pat, sizeof pat, "%s\\*", users);
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(pat, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.') continue;
                char dir[MAX_PATH * 2];
                snprintf(dir, sizeof dir, "%s\\%s\\AppData\\Roaming\\" PS_REL, users, fd.cFileName);
                scan_dir(&c, dir, fd.cFileName);
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
    } else {
        char base[MAX_PATH], dir[MAX_PATH * 2], user[128] = "";
        DWORD ul = sizeof user;
        GetUserNameA(user, &ul);
        if (GetEnvironmentVariableA("APPDATA", base, MAX_PATH) > 0) {
            snprintf(dir, sizeof dir, "%s\\" PS_REL, base);
            scan_dir(&c, dir, user);
        }
    }
    if (c.mode == 1) {
        puts("]");
    } else if (c.mode == 0) {
        printf("\n%u command(s) in %u file(s), %u flagged\n", c.lines, c.files, c.flagged);
    }
    return 0;
}
