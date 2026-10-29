// winspect tasks - scheduled tasks, read straight from their XML on disk
//
// The Task Scheduler keeps each task as an XML file under
// %SystemRoot%\System32\Tasks (the folder tree mirrors the task paths). Reading
// those files is a COM-free, read-only way to see what runs on a schedule: the
// command, its arguments and the author. Scheduled tasks are a favourite
// persistence spot, so we flag any whose command lives in a user-writable or
// temporary directory. The XML is stored as UTF-16, so we convert it before
// scanning. We only read the files.
//
// Flags carry a reason:
//   * command or COM handler DLL in a user-writable / temporary directory
//   * COM handler registered under HKCU: for a task running as that user the
//     per-user registration wins over the machine one, a known way to hijack
//     a legitimate (even Microsoft) task without touching its XML (T1546.015)
// and, only for tasks OUTSIDE the Microsoft\ folder (many built-in tasks are
// legitimately <Hidden> or launch rundll32/powershell, so flagging those
// would bury real findings in noise):
//   * hidden task       - <Settings><Hidden>true</Hidden> keeps it out of the
//                         default Task Scheduler view
//   * script host       - the action starts powershell / wscript / cscript /
//                         mshta / rundll32 / regsvr32 (common living-off-the-
//                         land launchers)
// The XML fields are read by task_parse (artparse.c, unit-tested), which also
// decodes entities: arguments like /c &quot;x&quot; used to be shown raw.
// --dir reads a copied Tasks folder; COM handlers are then left unresolved,
// because this machine's registry is not the image's.

#include "tasks.h"
#include "jsonutil.h"
#include "ioc.h"
#include "artparse.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Reads a (possibly UTF-16) text file into a UTF-8 heap string; caller frees.
static char *read_text(const char *path)
{
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    LARGE_INTEGER sz;
    char *raw = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(f, &sz) && sz.QuadPart > 0 && sz.QuadPart < (4 << 20)) {
        raw = (char *)malloc((size_t)sz.QuadPart + 2);
        if (raw != NULL && !ReadFile(f, raw, (DWORD)sz.QuadPart, &got, NULL)) {
            free(raw); raw = NULL;
        }
    }
    CloseHandle(f);
    if (raw == NULL) {
        return NULL;
    }
    raw[got] = '\0';
    raw[got + 1] = '\0';

    // UTF-16LE BOM? Convert the whole thing to UTF-8.
    if (got >= 2 && (unsigned char)raw[0] == 0xFF && (unsigned char)raw[1] == 0xFE) {
        const WCHAR *w = (const WCHAR *)(raw + 2);
        int wchars = (int)((got - 2) / 2);
        int need = WideCharToMultiByte(CP_UTF8, 0, w, wchars, NULL, 0, NULL, NULL);
        char *utf8 = (char *)malloc((size_t)need + 1);
        if (utf8 != NULL) {
            WideCharToMultiByte(CP_UTF8, 0, w, wchars, utf8, need, NULL, NULL);
            utf8[need] = '\0';
        }
        free(raw);
        return utf8;
    }
    return raw;
}

struct tctx { int mode; int first; unsigned count; unsigned flagged; size_t root_len; int only_flagged; int offline; };
#define TK_TEXT 0
#define TK_JSON 1
#define TK_CSV  2

// COM handler task: the CLSID's in-process server DLL. A per-user (HKCU)
// registration takes precedence over the machine one when the task runs as
// that user - a known way to hijack a legitimate task (T1546.015) - so it is
// looked up first and reported as such. Live registry only.
static void com_dll(const char *clsid, char *out, size_t n, int *per_user)
{
    out[0] = '\0';
    *per_user = 0;
    char key[160], raw[MAX_PATH];
    snprintf(key, sizeof key, "Software\\Classes\\CLSID\\%s\\InprocServer32", clsid);
    // REG_EXPAND_SZ is only accepted together with RRF_NOEXPAND (else
    // ERROR_INVALID_PARAMETER); expand it ourselves afterwards.
    const DWORD fl = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
    DWORD sz = sizeof raw;
    if (RegGetValueA(HKEY_CURRENT_USER, key, NULL, fl, NULL, raw, &sz) == ERROR_SUCCESS) {
        *per_user = 1;
    } else {
        sz = sizeof raw;
        if (RegGetValueA(HKEY_LOCAL_MACHINE, key, NULL, fl, NULL, raw, &sz) != ERROR_SUCCESS) return;
    }
    DWORD got = ExpandEnvironmentStringsA(raw, out, (DWORD)n);
    if (got == 0 || got > n) snprintf(out, n, "%s", raw);
}

static void handle_file(struct tctx *c, const char *full)
{
    char *xml = read_text(full);
    if (xml == NULL) {
        return;
    }
    task_info t;
    int ok = task_parse(xml, &t);
    free(xml);
    if (ok != 0 || (t.command[0] == '\0' && t.com_clsid[0] == '\0')) {
        return;   // not a task definition, or no action we can describe
    }
    const char *name = full + c->root_len;   // path relative to the Tasks root
    while (*name == '\\' || *name == '/') { name++; }
    int highest = _stricmp(t.run_level, "HighestAvailable") == 0;
    int builtin = _strnicmp(name, "Microsoft\\", 10) == 0;
    char dll[MAX_PATH] = "";
    int per_user = 0;
    if (t.command[0] == '\0' && !c->offline) com_dll(t.com_clsid, dll, sizeof dll, &per_user);
    const char *reason = NULL;
    if (t.command[0] && ioc_user_writable(t.command))  reason = "command in user-writable dir";
    else if (dll[0] && ioc_user_writable(dll))         reason = "COM handler DLL in user-writable dir";
    else if (per_user)                                 reason = "COM handler registered per-user (HKCU overrides HKLM)";
    else if (!builtin && t.hidden)                     reason = "hidden task outside Microsoft\\ folder";
    else if (!builtin && t.command[0] && ioc_script_host(t.command)) reason = "launches a script host / LOLBin";

    // What runs, as one string: the command line, or "COM {clsid} -> dll".
    char what[1600];
    if (t.command[0]) snprintf(what, sizeof what, "%s%s%s", t.command, t.arguments[0] ? " " : "", t.arguments);
    else snprintf(what, sizeof what, "COM %s%s%s", t.com_clsid, dll[0] ? " -> " : "", dll);

    c->count++;
    if (reason) { c->flagged++; }
    if (c->only_flagged && reason == NULL) {
        return;
    }
    if (c->mode == TK_TEXT) {
        printf("  %s%s%s%s%s\n", reason ? "[!] " : "    ", name,
               t.hidden ? "  [hidden]" : "", highest ? "  [highest]" : "", t.enabled ? "" : "  [disabled]");
        printf("        %s\n", what);
        printf("        as %s; triggers %s; registered %s by %s\n", t.user[0] ? t.user : "-",
               t.triggers[0] ? t.triggers : "none", t.date[0] ? t.date : "-", t.author[0] ? t.author : "-");
        if (reason) {
            printf("        <- %s\n", reason);
        }
    } else if (c->mode == TK_CSV) {
        csv_str(name);   putchar(',');
        csv_str(t.command);    putchar(',');
        csv_str(t.arguments);   putchar(',');
        csv_str(t.author);
        printf(",%s,%s,%d,", t.hidden ? "true" : "false", highest ? "true" : "false",
               reason ? 1 : 0);
        csv_str(reason ? reason : ""); putchar(',');
        csv_str(t.user); putchar(',');
        csv_str(t.triggers); putchar(',');
        csv_str(t.date); printf(",%s,", t.enabled ? "true" : "false");
        csv_str(t.com_clsid); putchar(',');
        csv_str(dll); putchar('\n');
    } else {
        printf("%s{\"task\":", c->first ? "" : ",");
        json_str(name);
        fputs(",\"command\":", stdout);   json_str(t.command);
        fputs(",\"arguments\":", stdout); json_str(t.arguments);
        fputs(",\"author\":", stdout);    json_str(t.author);
        fputs(",\"registered\":", stdout); json_str(t.date);
        fputs(",\"run_as\":", stdout);    json_str(t.user);
        fputs(",\"triggers\":", stdout);  json_str(t.triggers);
        fputs(",\"com_clsid\":", stdout); json_str(t.com_clsid);
        fputs(",\"com_dll\":", stdout);   json_str(dll);
        printf(",\"actions\":%d,\"enabled\":%s,\"hidden\":%s,\"highest_privileges\":%s,\"suspicious\":%s,\"reason\":",
               t.actions, t.enabled ? "true" : "false", t.hidden ? "true" : "false",
               highest ? "true" : "false", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void walk(const char *dir, struct tctx *c)
{
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof pattern, "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
            continue;
        }
        char full[MAX_PATH];
        snprintf(full, sizeof full, "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk(full, c);
        } else {
            handle_file(c, full);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int cmd_tasks(int argc, char **argv)
{
    int mode = TK_TEXT, only_flagged = 0;
    const char *dir = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--dir") == 0 && a + 1 < argc) dir = argv[++a];
        else if (strcmp(argv[a], "--json") == 0) mode = TK_JSON;
        else if (strcmp(argv[a], "--flagged") == 0) only_flagged = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = TK_CSV;
        else {
            fprintf(stderr, "tasks: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    char root[MAX_PATH];
    if (dir != NULL) {
        // A copied Tasks folder (e.g. from a disk image); COM handlers are
        // not resolved because this machine's registry is not that one's.
        DWORD at = GetFileAttributesA(dir);
        if (at == INVALID_FILE_ATTRIBUTES || !(at & FILE_ATTRIBUTE_DIRECTORY)) {
            fprintf(stderr, "tasks: '%s' is not a folder\n", dir);
            return 1;
        }
        snprintf(root, sizeof root, "%s", dir);
        size_t L = strlen(root);
        while (L > 3 && (root[L - 1] == '\\' || root[L - 1] == '/')) root[--L] = '\0';
    } else {
        UINT wl = GetSystemWindowsDirectoryA(root, MAX_PATH);
        if (wl == 0 || wl >= MAX_PATH) {
            fputs("tasks: cannot resolve the Windows directory\n", stderr);
            return 1;
        }
        snprintf(root + wl, sizeof root - wl, "\\System32\\Tasks");
    }

    struct tctx c;
    c.mode = mode; c.first = 1; c.count = 0; c.flagged = 0; c.root_len = strlen(root);
    c.only_flagged = only_flagged;
    c.offline = dir != NULL;

    if (mode == TK_TEXT) {
        printf("tasks  %s\n\n", root);
    } else if (mode == TK_CSV) {
        puts("task,command,arguments,author,hidden,highest_privileges,suspicious,reason,run_as,triggers,registered,enabled,com_clsid,com_dll");
    } else {
        putchar('[');
    }

    walk(root, &c);

    if (mode == TK_TEXT) {
        printf("\n%u task(s) with a command or COM handler, %u flagged\n",
               c.count, c.flagged);
    } else if (mode == TK_JSON) {
        puts("]");
    }
    return 0;
}
