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
// Flags carry a reason. Besides user-writable commands we look at two
// settings, but only for tasks OUTSIDE the Microsoft\ folder: many built-in
// Windows tasks are legitimately <Hidden> or launch rundll32/powershell, so
// flagging those would bury real findings in noise.
//   * hidden task       - <Settings><Hidden>true</Hidden> keeps it out of the
//                         default Task Scheduler view
//   * script host       - the action starts powershell / wscript / cscript /
//                         mshta / rundll32 / regsvr32 (common living-off-the-
//                         land launchers)

#include "tasks.h"
#include "jsonutil.h"
#include "ioc.h"

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

// Copies the text between <tag> and </tag> into out (trimmed). Empty if absent.
static void extract_tag(const char *xml, const char *tag, char *out, size_t n)
{
    out[0] = '\0';
    char open[64], close[64];
    snprintf(open, sizeof open, "<%s>", tag);
    snprintf(close, sizeof close, "</%s>", tag);
    const char *a = strstr(xml, open);
    if (a == NULL) {
        return;
    }
    a += strlen(open);
    const char *b = strstr(a, close);
    if (b == NULL) {
        return;
    }
    size_t len = (size_t)(b - a);
    if (len >= n) { len = n - 1; }
    // Trim leading/trailing whitespace.
    while (len > 0 && (*a == ' ' || *a == '\t' || *a == '\r' || *a == '\n')) { a++; len--; }
    while (len > 0 && (a[len - 1] == ' ' || a[len - 1] == '\t' ||
                       a[len - 1] == '\r' || a[len - 1] == '\n')) { len--; }
    memcpy(out, a, len);
    out[len] = '\0';
}

struct tctx { int mode; int first; unsigned count; unsigned flagged; size_t root_len; int only_flagged; };
#define TK_TEXT 0
#define TK_JSON 1
#define TK_CSV  2

static void handle_file(struct tctx *c, const char *full)
{
    char *xml = read_text(full);
    if (xml == NULL) {
        return;
    }
    char cmd[1024], args[1024], author[256], hidden[16], level[32];
    extract_tag(xml, "Command", cmd, sizeof cmd);
    extract_tag(xml, "Arguments", args, sizeof args);
    extract_tag(xml, "Author", author, sizeof author);
    extract_tag(xml, "Hidden", hidden, sizeof hidden);
    extract_tag(xml, "RunLevel", level, sizeof level);
    free(xml);

    if (cmd[0] == '\0') {
        return;   // no Exec action we can read: skip (could be a COM/handler task)
    }
    const char *name = full + c->root_len;   // path relative to the Tasks root
    while (*name == '\\' || *name == '/') { name++; }
    int is_hidden = _stricmp(hidden, "true") == 0;
    int highest = _stricmp(level, "HighestAvailable") == 0;
    int builtin = _strnicmp(name, "Microsoft\\", 10) == 0;
    int script_host = ioc_script_host(cmd);
    const char *reason = NULL;
    if (ioc_user_writable(cmd))          reason = "command in user-writable dir";
    else if (!builtin && is_hidden)      reason = "hidden task outside Microsoft\\ folder";
    else if (!builtin && script_host)    reason = "launches a script host / LOLBin";

    c->count++;
    if (reason) { c->flagged++; }
    if (c->only_flagged && reason == NULL) {
        return;
    }
    if (c->mode == TK_TEXT) {
        printf("  %s%s%s%s\n", reason ? "[!] " : "    ", name,
               is_hidden ? "  [hidden]" : "", highest ? "  [highest]" : "");
        printf("        %s %s\n", cmd, args);
        if (reason) {
            printf("        <- %s\n", reason);
        }
    } else if (c->mode == TK_CSV) {
        csv_str(name);   putchar(',');
        csv_str(cmd);    putchar(',');
        csv_str(args);   putchar(',');
        csv_str(author);
        printf(",%s,%s,%d,", is_hidden ? "true" : "false", highest ? "true" : "false",
               reason ? 1 : 0);
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"task\":", c->first ? "" : ",");
        json_str(name);
        fputs(",\"command\":", stdout);   json_str(cmd);
        fputs(",\"arguments\":", stdout); json_str(args);
        fputs(",\"author\":", stdout);    json_str(author);
        printf(",\"hidden\":%s,\"highest_privileges\":%s,\"suspicious\":%s,\"reason\":",
               is_hidden ? "true" : "false", highest ? "true" : "false",
               reason ? "true" : "false");
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
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = TK_JSON;
        else if (strcmp(argv[a], "--flagged") == 0) only_flagged = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = TK_CSV;
        else {
            fprintf(stderr, "tasks: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    char root[MAX_PATH];
    UINT wl = GetSystemWindowsDirectoryA(root, MAX_PATH);
    if (wl == 0 || wl >= MAX_PATH) {
        fputs("tasks: cannot resolve the Windows directory\n", stderr);
        return 1;
    }
    snprintf(root + wl, sizeof root - wl, "\\System32\\Tasks");

    struct tctx c;
    c.mode = mode; c.first = 1; c.count = 0; c.flagged = 0; c.root_len = strlen(root);
    c.only_flagged = only_flagged;

    if (mode == TK_TEXT) {
        printf("tasks  %s\n\n", root);
    } else if (mode == TK_CSV) {
        puts("task,command,arguments,author,hidden,highest_privileges,suspicious,reason");
    } else {
        putchar('[');
    }

    walk(root, &c);

    if (mode == TK_TEXT) {
        printf("\n%u task(s) with a runnable command, %u flagged\n",
               c.count, c.flagged);
    } else if (mode == TK_JSON) {
        puts("]");
    }
    return 0;
}
