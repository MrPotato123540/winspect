// winspect jumplist - recent items per application (Jump Lists)
//
// Right-click an app on the taskbar and Windows shows "Recent" files: the
// Jump List. Behind it are two kinds of files per application, named after
// the application's AppID (a hash, e.g. 5f7b5f1e01b83767.automaticDestinations-ms):
//   Recent\AutomaticDestinations\*.automaticDestinations-ms
//       a Compound File (OLE storage, read by src/cfb.c); every stream except
//       "DestList" is one shell link (.lnk) to an item the app opened
//   Recent\CustomDestinations\*.customDestinations-ms
//       shell links stored back to back, found by their 0x4C + CLSID header
// Each link is parsed by the portable lnkparse.c. Like Recent\*.lnk this is
// evidence of what a user opened - per program, often many more items, and it
// survives the target being deleted or the USB stick being removed. (JLECmd is
// the well-known tool for this; only the idea is borrowed.)
//
// AppIDs are printed as they are; mapping them to program names needs a list
// we could not verify, so none is shipped. The DestList stream (MRU order and
// access times) is not decoded yet.
//
// Read-only: files are opened for reading only.

#include "jumplist.h"
#include "cfb.h"
#include "lnkparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JL_MAX_FILE (32u * 1024 * 1024)

static const unsigned char LNK_HDR[20] = {
    0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

typedef struct {
    int mode, first;
    unsigned items, flagged, files;
    char appid[64];
    const char *kind;
} jctx;

static void ft_str(uint64_t t, char *out, size_t n)
{
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = (DWORD)t;
    ft.dwHighDateTime = (DWORD)(t >> 32);
    if (t == 0 || !FileTimeToSystemTime(&ft, &st)) { snprintf(out, n, "-"); return; }
    snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

static void report(jctx *c, const char *entry, const lnk_info *li)
{
    const char *target = li->target[0] ? li->target : li->relative;
    if (target[0] == '\0') return;          // shell-namespace item with no path
    const char *reason = lnk_anomaly_reason(li->anomalies);
    if (reason == NULL)
        reason = ioc_script_host(target) ? "target is a script host / LOLBin"
               : ioc_user_writable(target) ? "target in user-writable dir" : NULL;
    char cts[32], wts[32];
    ft_str(li->created, cts, sizeof cts);
    ft_str(li->written, wts, sizeof wts);
    c->items++;
    if (reason) c->flagged++;
    if (c->mode == 0) {
        printf("  %s%-18s %-6s %-6s %s%s%s\n", reason ? "[!] " : "    ", c->appid, c->kind, entry,
               target, li->arguments[0] ? " " : "", li->arguments);
        printf("        target created %s, modified %s%s%s%s\n", cts, wts,
               li->has_volume ? ", " : "", li->has_volume ? lnk_drive_type_name(li->drive_type) : "",
               li->has_volume ? " volume" : "");
        if (li->machine_id[0] || li->mac[0])
            printf("        made on %s%s%s\n", li->machine_id[0] ? li->machine_id : "?",
                   li->mac[0] ? ", MAC " : "", li->mac);
        if (reason) printf("        <- %s\n", reason);
    } else if (c->mode == 2) {
        csv_str(c->appid); putchar(',');
        csv_str(c->kind); putchar(',');
        csv_str(entry); putchar(',');
        csv_str(target); putchar(',');
        csv_str(li->arguments); putchar(',');
        csv_str(cts); putchar(',');
        csv_str(wts); putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"appid\":", c->first ? "" : ",");
        json_str(c->appid);
        fputs(",\"kind\":", stdout);    json_str(c->kind);
        fputs(",\"entry\":", stdout);   json_str(entry);
        fputs(",\"target\":", stdout);  json_str(target);
        fputs(",\"arguments\":", stdout); json_str(li->arguments);
        fputs(",\"target_created\":", stdout);  json_str(cts);
        fputs(",\"target_modified\":", stdout); json_str(wts);
        fputs(",\"drive_type\":", stdout);
        if (li->has_volume) json_str(lnk_drive_type_name(li->drive_type)); else fputs("null", stdout);
        fputs(",\"machine_id\":", stdout); json_str(li->machine_id);
        fputs(",\"mac\":", stdout);        json_str(li->mac);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void on_stream(const char *name, const unsigned char *data, size_t len, void *vctx)
{
    jctx *c = (jctx *)vctx;
    if (_stricmp(name, "DestList") == 0) return;
    lnk_info li;
    int rc = lnk_parse(data, len, &li);
    if (rc == 0 || (rc == -2 && li.target[0])) report(c, name, &li);
}

static unsigned char *slurp(const WCHAR *path, size_t *len)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    unsigned char *buf = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart <= JL_MAX_FILE &&
            (buf = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL &&
            !(ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL) && got == (DWORD)sz.QuadPart)) {
        free(buf);
        buf = NULL;
    }
    CloseHandle(h);
    *len = got;
    return buf;
}

static void one_file(jctx *c, const WCHAR *path)
{
    size_t len = 0;
    unsigned char *d = slurp(path, &len);
    if (d == NULL) return;
    c->files++;
    // AppID = file name up to the first dot.
    const WCHAR *base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    WideCharToMultiByte(CP_UTF8, 0, base, -1, c->appid, sizeof c->appid, NULL, NULL);
    char *dot = strchr(c->appid, '.');
    if (dot) *dot = '\0';

    cfb_file f;
    if (cfb_open(&f, d, len) == 0) {
        c->kind = "auto";
        cfb_streams(&f, on_stream, c);
        cfb_close(&f);
    } else {
        // Custom destinations: shell links stored back to back.
        c->kind = "custom";
        unsigned k = 0;
        for (size_t off = 0; off + sizeof LNK_HDR <= len; off++) {
            if (memcmp(d + off, LNK_HDR, sizeof LNK_HDR) != 0) continue;
            lnk_info li;
            int rc = lnk_parse(d + off, len - off, &li);
            if (rc == 0 || (rc == -2 && li.target[0])) {
                char entry[16];
                snprintf(entry, sizeof entry, "#%u", k++);
                report(c, entry, &li);
            }
            off += sizeof LNK_HDR - 1;
        }
    }
    free(d);
}

static void scan_dir(jctx *c, const WCHAR *dir, const WCHAR *pattern)
{
    WCHAR pat[MAX_PATH * 2];
    _snwprintf(pat, MAX_PATH * 2, L"%ls\\%ls", dir, pattern);
    pat[MAX_PATH * 2 - 1] = 0;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        WCHAR full[MAX_PATH * 2];
        _snwprintf(full, MAX_PATH * 2, L"%ls\\%ls", dir, fd.cFileName);
        full[MAX_PATH * 2 - 1] = 0;
        one_file(c, full);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

int cmd_jumplist(int argc, char **argv)
{
    jctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *target = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (target == NULL)                 target = argv[a];
        else {
            fprintf(stderr, "jumplist: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (c.mode == 0) {
        puts("jumplist  (recent items per application)\n");
        printf("      %-18s %-6s %-6s %s\n", "appid", "kind", "entry", "target");
    } else if (c.mode == 2) {
        puts("appid,kind,entry,target,arguments,target_created,target_modified,reason");
    } else {
        putchar('[');
    }

    if (target != NULL) {
        WCHAR w[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, target, -1, w, MAX_PATH);
        DWORD attr = GetFileAttributesW(w);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            if (c.mode == 1) puts("]");
            fprintf(stderr, "jumplist: cannot open '%s'\n", target);
            return 1;
        }
        if (attr & FILE_ATTRIBUTE_DIRECTORY) scan_dir(&c, w, L"*-ms");
        else one_file(&c, w);
    } else {
        WCHAR base[MAX_PATH], dir[MAX_PATH];
        DWORD n = GetEnvironmentVariableW(L"APPDATA", base, MAX_PATH);
        if (n > 0 && n < MAX_PATH - 64) {
            _snwprintf(dir, MAX_PATH, L"%ls\\Microsoft\\Windows\\Recent\\AutomaticDestinations", base);
            dir[MAX_PATH - 1] = 0;
            scan_dir(&c, dir, L"*.automaticDestinations-ms");
            _snwprintf(dir, MAX_PATH, L"%ls\\Microsoft\\Windows\\Recent\\CustomDestinations", base);
            dir[MAX_PATH - 1] = 0;
            scan_dir(&c, dir, L"*.customDestinations-ms");
        }
    }

    if (c.mode == 0) {
        printf("\n%u item(s) in %u jump list file(s), %u flagged\n", c.items, c.files, c.flagged);
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
