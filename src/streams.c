// winspect streams - alternate data streams and Mark-of-the-Web
//
// An NTFS file can carry extra named data streams ("file.txt:hidden") that
// Explorer and "dir" do not show - a well-known place to stash data
// (MITRE T1564.004). Most streams in the wild are benign metadata, the most
// common being Zone.Identifier: browsers and mail clients add it on download
// ("Mark-of-the-Web"), recording the security zone and the URLs involved:
//   [ZoneTransfer]  ZoneId=3  ReferrerUrl=...  HostUrl=https://.../file.exe
// For an investigator that answers "where did this file come from?".
// (The Sysinternals Streams tool lists the same streams; the idea is theirs.)
//
// FindFirstStreamW enumerates the streams; the default unnamed "::$DATA"
// stream is the file content and is skipped. The Zone.Identifier stream is
// read (a few hundred bytes, capped) and parsed by the portable motw_parse.
// Flags, with reasons:
//   * executable/script content whose MOTW zone is internet or restricted
//   * any other named stream that is not a known benign metadata stream
// Read-only: streams are enumerated and Zone.Identifier is opened for reading.

#include "streams.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define MAX_FILES 200000

typedef struct {
    int mode, first, recurse;
    unsigned files, with_streams, flagged;
} sctx;

static int is_exec_ext(const WCHAR *path)
{
    static const WCHAR *const ext[] = {
        L".exe", L".dll", L".scr", L".msi", L".bat", L".cmd", L".ps1", L".vbs", L".js",
        L".jse", L".wsf", L".hta", L".lnk", L".iso", L".img", L".vhd", L".vhdx",
        L".docm", L".xlsm", L".one", NULL
    };
    const WCHAR *dot = wcsrchr(path, L'.');
    if (dot == NULL) return 0;
    for (int i = 0; ext[i] != NULL; i++) {
        if (_wcsicmp(dot, ext[i]) == 0) return 1;
    }
    return 0;
}

// Metadata streams Windows and common software add routinely.
static int benign_stream(const WCHAR *name)
{
    static const WCHAR *const ok[] = {
        L":Zone.Identifier:$DATA", L":SmartScreen:$DATA", L":encryptable:$DATA",
        L":com.dropbox.attrs:$DATA", L":com.dropbox.attributes:$DATA",
        L":OECustomProperty:$DATA", L":ms-properties:$DATA", L":AFP_AfpInfo:$DATA",
        L":AFP_Resource:$DATA", L":{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}:$DATA", NULL
    };
    for (int i = 0; ok[i] != NULL; i++) {
        if (_wcsicmp(name, ok[i]) == 0) return 1;
    }
    return 0;
}

static void read_motw(const WCHAR *file, motw_info *m)
{
    m->zone = -1;
    m->referrer[0] = m->host[0] = '\0';
    WCHAR sp[MAX_PATH * 2];
    _snwprintf(sp, MAX_PATH * 2, L"%ls:Zone.Identifier", file);
    sp[MAX_PATH * 2 - 1] = 0;
    HANDLE h = CreateFileW(sp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[4096];
    DWORD got = 0;
    if (ReadFile(h, buf, sizeof buf - 1, &got, NULL)) {
        buf[got] = '\0';
        motw_parse(buf, m);
    }
    CloseHandle(h);
}

static void emit(sctx *c, const char *file, const char *stream, unsigned long long size,
                 const motw_info *m, const char *reason)
{
    if (reason) c->flagged++;
    if (c->mode == 0) {
        printf("  %s%s\n", reason ? "[!] " : "    ", file);
        printf("        stream %s  (%llu bytes)\n", stream, size);
        if (m != NULL && m->zone >= 0) {
            printf("        zone %d (%s)%s%s%s%s\n", m->zone, zone_name(m->zone),
                   m->host[0] ? "  from " : "", m->host,
                   m->referrer[0] ? "  via " : "", m->referrer);
        }
        if (reason) printf("        <- %s\n", reason);
    } else if (c->mode == 2) {
        csv_str(file); putchar(',');
        csv_str(stream);
        printf(",%llu,", size);
        if (m != NULL && m->zone >= 0) printf("%d,", m->zone); else fputs(",", stdout);
        csv_str(m ? m->host : ""); putchar(',');
        csv_str(m ? m->referrer : ""); putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"file\":", c->first ? "" : ",");
        json_str(file);
        fputs(",\"stream\":", stdout); json_str(stream);
        printf(",\"size\":%llu,\"zone\":", size);
        if (m != NULL && m->zone >= 0) printf("%d", m->zone); else fputs("null", stdout);
        fputs(",\"host_url\":", stdout);     json_str(m ? m->host : "");
        fputs(",\"referrer_url\":", stdout); json_str(m ? m->referrer : "");
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void scan_file(sctx *c, const WCHAR *path)
{
    c->files++;
    WIN32_FIND_STREAM_DATA sd;
    HANDLE h = FindFirstStreamW(path, FindStreamInfoStandard, &sd, 0);
    if (h == INVALID_HANDLE_VALUE) return;
    int any = 0;
    char file[2048];
    WideCharToMultiByte(CP_UTF8, 0, path, -1, file, sizeof file, NULL, NULL);
    do {
        if (_wcsicmp(sd.cStreamName, L"::$DATA") == 0) continue;     // the file itself
        any = 1;
        char sname[600];
        WideCharToMultiByte(CP_UTF8, 0, sd.cStreamName, -1, sname, sizeof sname, NULL, NULL);
        unsigned long long size = (unsigned long long)sd.StreamSize.QuadPart;
        if (_wcsicmp(sd.cStreamName, L":Zone.Identifier:$DATA") == 0) {
            motw_info m;
            read_motw(path, &m);
            const char *reason = (m.zone >= 3 && is_exec_ext(path))
                ? "executable content downloaded from the internet (Mark-of-the-Web)" : NULL;
            emit(c, file, sname, size, &m, reason);
        } else {
            emit(c, file, sname, size, NULL,
                 benign_stream(sd.cStreamName) ? NULL
                     : "unusual alternate data stream (could hide data)");
        }
    } while (FindNextStreamW(h, &sd));
    FindClose(h);
    if (any) c->with_streams++;
}

static void scan_dir(sctx *c, const WCHAR *dir, int depth)
{
    if (depth > 32 || c->files >= MAX_FILES) return;
    WCHAR pat[MAX_PATH * 2];
    _snwprintf(pat, MAX_PATH * 2, L"%ls\\*", dir);
    pat[MAX_PATH * 2 - 1] = 0;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        WCHAR full[MAX_PATH * 2];
        _snwprintf(full, MAX_PATH * 2, L"%ls\\%ls", dir, fd.cFileName);
        full[MAX_PATH * 2 - 1] = 0;
        // Directories can carry streams too; scan them, but never follow
        // junctions/symlinks (loops, and they point outside the tree).
        scan_file(c, full);
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && c->recurse &&
                !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            scan_dir(c, full, depth + 1);
        }
    } while (FindNextFileW(h, &fd) && c->files < MAX_FILES);
    FindClose(h);
}

int cmd_streams(int argc, char **argv)
{
    sctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *target = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)         c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)     c.mode = 2;
        else if (strcmp(argv[a], "--recurse") == 0) c.recurse = 1;
        else if (target == NULL)                    target = argv[a];
        else {
            fprintf(stderr, "streams: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (target == NULL) {
        fputs("usage: winspect streams <file | folder> [--recurse] [--json | --csv]\n", stderr);
        return 1;
    }
    WCHAR wt[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, target, -1, wt, MAX_PATH) == 0) {
        fprintf(stderr, "streams: bad path '%s'\n", target);
        return 1;
    }
    size_t L = wcslen(wt);
    while (L > 3 && (wt[L - 1] == L'\\' || wt[L - 1] == L'/')) wt[--L] = 0;
    DWORD attr = GetFileAttributesW(wt);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "streams: cannot open '%s'\n", target);
        return 1;
    }

    if (c.mode == 0) {
        printf("streams  %s%s\n\n", target, c.recurse ? "  (recursive)" : "");
    } else if (c.mode == 2) {
        puts("file,stream,size,zone,host_url,referrer_url,reason");
    } else {
        putchar('[');
    }
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        scan_dir(&c, wt, 0);
    } else {
        scan_file(&c, wt);
    }
    if (c.mode == 0) {
        printf("\n%u file(s) scanned, %u with alternate streams, %u flagged%s\n", c.files,
               c.with_streams, c.flagged, c.files >= MAX_FILES ? "  (stopped at the file cap)" : "");
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
