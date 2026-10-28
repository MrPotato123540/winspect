// winspect mru - "most recently used" lists Explorer keeps per user
//
// Three small registry lists show what a person did by hand:
//   Explorer\RunMRU      commands typed into the Run box (Win+R). Values a..z
//                        hold the text (ending in "\1"), MRUList is the order
//                        as a string of value letters, newest first.
//   Explorer\TypedPaths  paths typed into the Explorer address bar,
//                        url1 (newest) .. url25.
//   Explorer\RecentDocs  recently opened documents. Values "0".."N" are binary:
//                        the name as UTF-16 followed by a shell item; the
//                        order is MRUListEx, a u32 array ending in 0xFFFFFFFF.
// An intruder at the keyboard (or a remote-desktop session) often leaves a
// Run-box trace such as "powershell -nop -w hidden -enc ...". The key's
// last-write time is when its NEWEST entry was added, so that one entry per
// list gets a timestamp. Format helpers live in artparse.c (unit-tested).
//
// Read-only: registry reads only. Only the current user's hive is loaded.

#include "mru.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPLORER L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"

typedef struct { int mode, first; unsigned count, flagged; } mctx;

static void key_time(HKEY k, char *out, size_t n)
{
    FILETIME ft;
    SYSTEMTIME st;
    out[0] = '\0';
    if (RegQueryInfoKeyW(k, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &ft) ==
            ERROR_SUCCESS && FileTimeToSystemTime(&ft, &st)) {
        snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond);
    }
}

static void emit(mctx *c, const char *list, unsigned pos, const char *value, const char *when)
{
    const char *reason = NULL;
    if (strcmp(list, "RunMRU") == 0) {
        if (strcmp(ioc_classify(value), "encoded-cmd") == 0) reason = "encoded PowerShell command typed into Run";
        else if (ioc_script_host(value))                   reason = "script host / LOLBin started from Run";
    }
    c->count++;
    if (reason) c->flagged++;
    if (c->mode == 0) {
        printf("  %s%-11s %3u  %-19s  %s\n", reason ? "[!] " : "    ", list, pos,
               when[0] ? when : "", value);
        if (reason) printf("        <- %s\n", reason);
    } else if (c->mode == 2) {
        csv_str(list); printf(",%u,", pos);
        csv_str(when); putchar(',');
        csv_str(value); putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"list\":", c->first ? "" : ",");
        json_str(list);
        printf(",\"position\":%u,\"time\":", pos);
        json_str(when);
        fputs(",\"value\":", stdout); json_str(value);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void run_mru(mctx *c)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, EXPLORER L"RunMRU", 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    char when[32];
    key_time(k, when, sizeof when);
    WCHAR order[64];
    DWORD ol = sizeof order;
    if (RegGetValueW(k, NULL, L"MRUList", RRF_RT_REG_SZ, NULL, order, &ol) == ERROR_SUCCESS) {
        for (unsigned i = 0; order[i] != 0 && i < 26; i++) {
            WCHAR name[2] = { order[i], 0 };
            WCHAR val[2048];
            DWORD vl = sizeof val;
            if (RegGetValueW(k, NULL, name, RRF_RT_REG_SZ, NULL, val, &vl) != ERROR_SUCCESS) continue;
            char u8[4096];
            WideCharToMultiByte(CP_UTF8, 0, val, -1, u8, sizeof u8, NULL, NULL);
            runmru_clean(u8);
            emit(c, "RunMRU", i, u8, i == 0 ? when : "");
        }
    }
    RegCloseKey(k);
}

static void typed_paths(mctx *c)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, EXPLORER L"TypedPaths", 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    char when[32];
    key_time(k, when, sizeof when);
    for (unsigned i = 1; i <= 50; i++) {
        WCHAR name[16], val[2048];
        _snwprintf(name, 16, L"url%u", i);
        name[15] = 0;
        DWORD vl = sizeof val;
        if (RegGetValueW(k, NULL, name, RRF_RT_REG_SZ, NULL, val, &vl) != ERROR_SUCCESS) continue;
        char u8[4096];
        WideCharToMultiByte(CP_UTF8, 0, val, -1, u8, sizeof u8, NULL, NULL);
        emit(c, "TypedPaths", i - 1, u8, i == 1 ? when : "");
    }
    RegCloseKey(k);
}

static void recent_docs(mctx *c)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, EXPLORER L"RecentDocs", 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    char when[32];
    key_time(k, when, sizeof when);
    BYTE ex[4096];
    DWORD el = sizeof ex;
    if (RegGetValueW(k, NULL, L"MRUListEx", RRF_RT_REG_BINARY, NULL, ex, &el) == ERROR_SUCCESS) {
        uint32_t order[1024];
        size_t n = mrulistex_order(ex, el, order, 1024);
        for (size_t i = 0; i < n; i++) {
            WCHAR name[16];
            _snwprintf(name, 16, L"%lu", (unsigned long)order[i]);
            name[15] = 0;
            BYTE data[4096];
            DWORD dl = sizeof data;
            if (RegGetValueW(k, NULL, name, RRF_RT_REG_BINARY, NULL, data, &dl) != ERROR_SUCCESS) continue;
            char doc[2048];
            if (!recentdocs_name(data, dl, doc, sizeof doc)) continue;
            emit(c, "RecentDocs", (unsigned)i, doc, i == 0 ? when : "");
        }
    }
    RegCloseKey(k);
}

int cmd_mru(int argc, char **argv)
{
    mctx c = { 0, 1, 0, 0 };
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else {
            fprintf(stderr, "mru: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (c.mode == 0) {
        puts("mru  (current user, newest first; time = when the newest entry was added)\n");
        printf("      %-11s %3s  %-19s  %s\n", "list", "pos", "time (UTC)", "value");
    } else if (c.mode == 2) {
        puts("list,position,time,value,reason");
    } else {
        putchar('[');
    }
    run_mru(&c);
    typed_paths(&c);
    recent_docs(&c);
    if (c.mode == 0) {
        printf("\n%u entr%s, %u flagged\n", c.count, c.count == 1 ? "y" : "ies", c.flagged);
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
