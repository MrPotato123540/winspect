// winspect mru - "most recently used" lists Explorer keeps per user
//
// Four small registry lists show what a person did by hand:
//   Explorer\RunMRU      commands typed into the Run box (Win+R). Values a..z
//                        hold the text (ending in "\1"), MRUList is the order
//                        as a string of value letters, newest first.
//   Explorer\TypedPaths  paths typed into the Explorer address bar,
//                        url1 (newest) .. url25.
//   Explorer\RecentDocs  recently opened documents. Values "0".."N" are binary:
//                        the name as UTF-16 followed by a shell item; the
//                        order is MRUListEx, a u32 array ending in 0xFFFFFFFF.
//   Explorer\WordWheelQuery  terms typed into the Explorer search box; values
//                        "0".."N" hold UTF-16 text, ordered by MRUListEx.
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
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPLORER "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"

typedef struct { int mode, first; unsigned count, flagged; regsrc *src; } mctx;

static void key_time(mctx *c, const rkey *k, char *out, size_t n)
{
    uint64_t t = rk_lastwrite(c->src, k);
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = (DWORD)t;
    ft.dwHighDateTime = (DWORD)(t >> 32);
    out[0] = '\0';
    if (t != 0 && FileTimeToSystemTime(&ft, &st)) {
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
    rkey k;
    if (rk_open(c->src, EXPLORER "RunMRU", &k) != 0) return;
    char when[32], order[64];
    key_time(c, &k, when, sizeof when);
    if (rk_get_str(c->src, &k, "MRUList", order, sizeof order)) {
        for (unsigned i = 0; order[i] != '\0' && i < 26; i++) {
            char name[2] = { order[i], 0 }, u8[4096];
            if (!rk_get_str(c->src, &k, name, u8, sizeof u8)) continue;
            runmru_clean(u8);
            emit(c, "RunMRU", i, u8, i == 0 ? when : "");
        }
    }
    rk_close(&k);
}

static void typed_paths(mctx *c)
{
    rkey k;
    if (rk_open(c->src, EXPLORER "TypedPaths", &k) != 0) return;
    char when[32];
    key_time(c, &k, when, sizeof when);
    for (unsigned i = 1; i <= 50; i++) {
        char name[16], u8[4096];
        snprintf(name, sizeof name, "url%u", i);
        if (!rk_get_str(c->src, &k, name, u8, sizeof u8)) continue;
        emit(c, "TypedPaths", i - 1, u8, i == 1 ? when : "");
    }
    rk_close(&k);
}

static void recent_docs(mctx *c)
{
    rkey k;
    if (rk_open(c->src, EXPLORER "RecentDocs", &k) != 0) return;
    char when[32];
    key_time(c, &k, when, sizeof when);
    unsigned char ex[4096];
    uint32_t type = 0;
    long el = rk_get(c->src, &k, "MRUListEx", &type, ex, sizeof ex);
    if (el > 0 && type == REG_BINARY) {
        uint32_t order[1024];
        size_t n = mrulistex_order(ex, (size_t)el < sizeof ex ? (size_t)el : sizeof ex, order, 1024);
        for (size_t i = 0; i < n; i++) {
            char name[16], doc[2048];
            snprintf(name, sizeof name, "%lu", (unsigned long)order[i]);
            unsigned char data[4096];
            long dl = rk_get(c->src, &k, name, &type, data, sizeof data);
            if (dl <= 0 || type != REG_BINARY) continue;
            if (!recentdocs_name(data, (size_t)dl < sizeof data ? (size_t)dl : sizeof data, doc, sizeof doc)) continue;
            emit(c, "RecentDocs", (unsigned)i, doc, i == 0 ? when : "");
        }
    }
    rk_close(&k);
}

// WordWheelQuery: terms typed into the Explorer search box. Values "0", "1",
// ... hold the UTF-16 term; MRUListEx gives the order, newest first.
static void word_wheel(mctx *c)
{
    rkey k;
    if (rk_open(c->src, EXPLORER "WordWheelQuery", &k) != 0) return;
    char when[32];
    key_time(c, &k, when, sizeof when);
    unsigned char ex[4096];
    uint32_t type = 0;
    long el = rk_get(c->src, &k, "MRUListEx", &type, ex, sizeof ex);
    if (el > 0 && type == REG_BINARY) {
        uint32_t order[1024];
        size_t n = mrulistex_order(ex, (size_t)el < sizeof ex ? (size_t)el : sizeof ex, order, 1024);
        for (size_t i = 0; i < n; i++) {
            char name[16], term[2048];
            snprintf(name, sizeof name, "%lu", (unsigned long)order[i]);
            unsigned char data[4096];
            long dl = rk_get(c->src, &k, name, &type, data, sizeof data);
            if (dl <= 0 || type != REG_BINARY) continue;
            regsrc_u16(data, (size_t)dl < sizeof data ? (size_t)dl : sizeof data, term, sizeof term);
            if (term[0]) emit(c, "WordWheel", (unsigned)i, term, i == 0 ? when : "");
        }
    }
    rk_close(&k);
}

int cmd_mru(int argc, char **argv)
{
    mctx c = { 0, 1, 0, 0, NULL };
    const char *hive = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "--hive") == 0 && a + 1 < argc) hive = argv[++a];
        else {
            fprintf(stderr, "mru: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    regsrc src;
    if (hive != NULL) {
        char err[512];
        if (regsrc_open_hive(&src, hive, err, sizeof err) != 0) {
            fprintf(stderr, "mru: %s\n", err);
            return 1;
        }
        if (regsrc_dirty(&src))
            fputs("mru: note: hive is dirty (transaction logs not replayed)\n", stderr);
    } else {
        regsrc_open_live(&src, HKEY_CURRENT_USER, NULL, "HKCU");
    }
    c.src = &src;
    if (c.mode == 0) {
        printf("mru  (%s, newest first; time = when the newest entry was added)\n\n", src.label);
        printf("      %-11s %3s  %-19s  %s\n", "list", "pos", "time (UTC)", "value");
    } else if (c.mode == 2) {
        puts("list,position,time,value,reason");
    } else {
        putchar('[');
    }
    run_mru(&c);
    typed_paths(&c);
    recent_docs(&c);
    word_wheel(&c);
    if (c.mode == 0) {
        printf("\n%u entr%s, %u flagged\n", c.count, c.count == 1 ? "y" : "ies", c.flagged);
    } else if (c.mode == 1) {
        puts("]");
    }
    regsrc_close(&src);
    return 0;
}
