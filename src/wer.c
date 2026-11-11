// winspect wer - Windows Error Reporting reports as execution evidence
//
// Each report is a folder (named after the event type, program and a hash)
// holding Report.wer, a UTF-16 "Key=Value" file. werparse.c (portable,
// unit-tested) reads it; this file finds the folders and prints.

#include "wer.h"
#include "werparse.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"
#include "textfile.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    wer_report r;
    char time[24];
    char folder[MAX_PATH * 2];
    char user[128];
    const char *reason;
} wrow;

typedef struct {
    wrow *v;
    size_t n, cap;
    unsigned files;
} wlist;

static void one_report(wlist *l, const char *path, const char *folder, const char *user)
{
    char *t = read_text_file(path);
    if (t == NULL) return;
    l->files++;
    wrow w;
    memset(&w, 0, sizeof w);
    if (wer_parse(t, &w.r) == 0) {
        if (w.r.event_time) {
            char iso[40];
            filetime_utc_str(w.r.event_time, iso, sizeof iso);
            snprintf(w.time, sizeof w.time, "%.19s", iso);
        } else {
            // No EventTime (very old reports): the file's own write time.
            WIN32_FILE_ATTRIBUTE_DATA fa;
            if (GetFileAttributesExA(path, GetFileExInfoStandard, &fa)) {
                char iso[40];
                filetime_utc_str((uint64_t)fa.ftLastWriteTime.dwHighDateTime << 32 | fa.ftLastWriteTime.dwLowDateTime, iso, sizeof iso);
                snprintf(w.time, sizeof w.time, "%.19s", iso);
            }
        }
        snprintf(w.folder, sizeof w.folder, "%s", folder);
        snprintf(w.user, sizeof w.user, "%s", user);
        w.reason = wer_reason(&w.r);
        if (l->n == l->cap) {
            size_t nc = l->cap ? l->cap * 2 : 64;
            wrow *nv = (wrow *)realloc(l->v, nc * sizeof *nv);
            if (nv != NULL) { l->v = nv; l->cap = nc; }
        }
        if (l->n < l->cap) l->v[l->n++] = w;
    }
    free(t);
}

// Report.wer directly in dir, or in its sub-folders (two levels: the WER
// root holds ReportArchive / ReportQueue, which hold one folder per report).
static void scan(wlist *l, const char *dir, const char *user, int depth)
{
    char path[MAX_PATH * 2];
    snprintf(path, sizeof path, "%s\\Report.wer", dir);
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) one_report(l, path, dir, user);
    if (depth == 0) return;
    char pat[MAX_PATH * 2];
    snprintf(pat, sizeof pat, "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.') continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;       // do not follow junctions
        char sub[MAX_PATH * 2];
        if (snprintf(sub, sizeof sub, "%s\\%s", dir, fd.cFileName) >= (int)sizeof sub) continue;
        scan(l, sub, user, depth - 1);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static int newest_first(const void *a, const void *b)
{
    return -strcmp(((const wrow *)a)->time, ((const wrow *)b)->time);
}

int cmd_wer(int argc, char **argv)
{
    int mode = 0, only_flagged = 0, modules = 0;
    const char *dir = NULL, *find = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)          mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)      mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)  only_flagged = 1;
        else if (strcmp(argv[a], "--modules") == 0)  modules = 1;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc) find = argv[++a];
        else if (dir == NULL && argv[a][0] != '-')   dir = argv[a];
        else {
            fprintf(stderr, "wer: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    wlist l;
    memset(&l, 0, sizeof l);
    if (dir != NULL) {
        DWORD at = GetFileAttributesA(dir);
        if (at == INVALID_FILE_ATTRIBUTES || !(at & FILE_ATTRIBUTE_DIRECTORY)) {
            if (mode == 1) puts("[]");
            fprintf(stderr, "wer: no folder '%s'\n", dir);
            return 1;
        }
        scan(&l, dir, "-", 3);
    } else {
        char base[MAX_PATH], root[MAX_PATH * 2];
        if (GetEnvironmentVariableA("ProgramData", base, MAX_PATH) > 0) {
            snprintf(root, sizeof root, "%s\\Microsoft\\Windows\\WER", base);
            scan(&l, root, "(system)", 2);
        }
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
                snprintf(root, sizeof root, "%s\\%s\\AppData\\Local\\Microsoft\\Windows\\WER", users, fd.cFileName);
                scan(&l, root, fd.cFileName, 2);
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
    }
    if (l.n > 1) qsort(l.v, l.n, sizeof *l.v, newest_first);

    if (mode == 0) {
        puts("wer  (crash / hang reports, newest first, UTC)\n");
        printf("    %-19s  %-14s %-28s %-24s %-11s %s\n", "time", "event", "program", "fault module", "exception", "path");
    } else if (mode == 2) {
        puts("time,event_type,program,path,fault_module,exception_code,modules,writable_modules,first_writable_module,user,report_folder,reason");
    } else {
        putchar('[');
    }
    unsigned shown = 0, flagged = 0;
    for (size_t i = 0; i < l.n; i++) {
        const wrow *w = &l.v[i];
        const wer_report *r = &w->r;
        if (only_flagged && w->reason == NULL) continue;
        if (find && !ioc_contains_ci(r->app_path, find) && !ioc_contains_ci(r->app_name, find) &&
                !ioc_contains_ci(r->fault_module, find) && !ioc_contains_ci(r->event_type, find)) continue;
        shown++;
        if (w->reason) flagged++;
        if (mode == 0) {
            printf("%s %-19s  %-14s %-28s %-24s %-11s %s\n", w->reason ? "[!]" : "   ", w->time[0] ? w->time : "-",
                   r->event_type, r->app_name, r->fault_module[0] ? r->fault_module : "-",
                   r->exc_code[0] ? r->exc_code : "-", r->app_path);
            if (w->reason) printf("        <- %s\n", w->reason);
            if (modules && r->modules_writable)
                printf("        %u of %u module(s) from user-writable folders, first: %s\n", r->modules_writable, r->modules,
                       r->first_writable_module);
        } else if (mode == 2) {
            printf("%s,", w->time);
            csv_str(r->event_type); putchar(',');
            csv_str(r->app_name); putchar(',');
            csv_str(r->app_path); putchar(',');
            csv_str(r->fault_module); putchar(',');
            csv_str(r->exc_code);
            printf(",%u,%u,", r->modules, r->modules_writable);
            csv_str(r->first_writable_module); putchar(',');
            csv_str(w->user); putchar(',');
            csv_str(w->folder); putchar(',');
            csv_str(w->reason ? w->reason : ""); putchar('\n');
        } else {
            printf("%s{\"time\":\"%s\",\"event_type\":", shown > 1 ? "," : "", w->time);
            json_str(r->event_type);
            fputs(",\"program\":", stdout);        json_str(r->app_name);
            fputs(",\"path\":", stdout);           json_str(r->app_path);
            fputs(",\"fault_module\":", stdout);   json_str(r->fault_module);
            fputs(",\"exception_code\":", stdout); json_str(r->exc_code);
            printf(",\"modules\":%u,\"writable_modules\":%u,\"first_writable_module\":", r->modules, r->modules_writable);
            json_str(r->first_writable_module);
            fputs(",\"user\":", stdout);           json_str(w->user);
            fputs(",\"report_folder\":", stdout);  json_str(w->folder);
            printf(",\"suspicious\":%s,\"reason\":", w->reason ? "true" : "false");
            json_str(w->reason ? w->reason : "");
            putchar('}');
        }
    }
    if (mode == 1) puts("]");
    else if (mode == 0) printf("\n%u report(s), %u flagged\n", shown, flagged);
    free(l.v);
    return 0;
}
