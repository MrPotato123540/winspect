// winspect magic - file type by content, name / content mismatches
//
// The signature table and the name checks are in magicparse.c (portable,
// unit-tested). This file reads the head of each file and walks folders.

#include "magic.h"
#include "magicparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEAD (36u * 1024u)          // covers the ISO 9660 signature at 0x8001

typedef struct {
    int mode, first, only_flagged, recurse;
    unsigned files, flagged, unreadable, dirs;
    unsigned char *buf;
} mctx;

static void one_file(mctx *c, const char *path, const char *name, uint64_t size)
{
    const char *type = "", *group = NULL, *reason;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        // In use or no access: the name can still be judged.
        c->unreadable++;
        type = "(cannot open)";
    } else {
        DWORD got = 0;
        if (!ReadFile(h, c->buf, HEAD, &got, NULL)) got = 0;
        CloseHandle(h);
        type = magic_sniff(c->buf, got, &group);
    }
    reason = magic_name_reason(name, group);
    c->files++;
    if (reason) c->flagged++;
    if (c->only_flagged && reason == NULL) return;
    if (c->mode == 0) {
        printf("%s %-46s %12llu  %s\n", reason ? "[!]" : "   ", type, (unsigned long long)size, path);
        if (reason) printf("        <- %s\n", reason);
    } else if (c->mode == 2) {
        csv_str(path); putchar(',');
        csv_str(type); putchar(',');
        csv_str(group ? group : "");
        printf(",%llu,", (unsigned long long)size);
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"path\":", c->first ? "" : ",");
        json_str(path);
        fputs(",\"type\":", stdout);  json_str(type);
        fputs(",\"group\":", stdout); json_str(group ? group : "");
        printf(",\"size\":%llu,\"suspicious\":%s,\"reason\":", (unsigned long long)size, reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

static void walk(mctx *c, const char *dir, int depth)
{
    char pat[MAX_PATH * 2];
    if (snprintf(pat, sizeof pat, "%s\\*", dir) >= (int)sizeof pat) return;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    c->dirs++;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char full[MAX_PATH * 2];
        if (snprintf(full, sizeof full, "%s\\%s", dir, fd.cFileName) >= (int)sizeof full) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Junctions and symlinks are not followed: no loops, no leaving the tree.
            if (c->recurse && depth < 64 && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) walk(c, full, depth + 1);
            continue;
        }
        one_file(c, full, fd.cFileName, (uint64_t)fd.nFileSizeHigh << 32 | fd.nFileSizeLow);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int cmd_magic(int argc, char **argv)
{
    mctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *target = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)          c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)      c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)  c.only_flagged = 1;
        else if (strcmp(argv[a], "-r") == 0 || strcmp(argv[a], "--recursive") == 0) c.recurse = 1;
        else if (target == NULL && argv[a][0] != '-') target = argv[a];
        else {
            fprintf(stderr, "magic: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (target == NULL) {
        fputs("magic: give a file or a folder\n", stderr);
        return 1;
    }
    DWORD at = GetFileAttributesA(target);
    if (at == INVALID_FILE_ATTRIBUTES) {
        if (c.mode == 1) puts("[]");
        fprintf(stderr, "magic: cannot find '%s' (error %lu)\n", target, (unsigned long)GetLastError());
        return 1;
    }
    c.buf = (unsigned char *)malloc(HEAD);
    if (c.buf == NULL) { fputs("magic: out of memory\n", stderr); return 1; }
    if (c.mode == 0) printf("    %-46s %12s  %s\n", "type", "size", "path");
    else if (c.mode == 2) puts("path,type,group,size,reason");
    else putchar('[');
    if (at & FILE_ATTRIBUTE_DIRECTORY) {
        // Drop a trailing backslash so paths do not show "dir\\file".
        char dir[MAX_PATH * 2];
        snprintf(dir, sizeof dir, "%s", target);
        size_t L = strlen(dir);
        while (L > 3 && (dir[L - 1] == '\\' || dir[L - 1] == '/')) dir[--L] = '\0';
        walk(&c, dir, 0);
    } else {
        WIN32_FILE_ATTRIBUTE_DATA fa;
        uint64_t size = 0;
        if (GetFileAttributesExA(target, GetFileExInfoStandard, &fa)) size = (uint64_t)fa.nFileSizeHigh << 32 | fa.nFileSizeLow;
        const char *b1 = strrchr(target, '\\'), *b2 = strrchr(target, '/');
        const char *base = b1 > b2 ? b1 : b2;
        one_file(&c, target, base ? base + 1 : target, size);
    }
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) {
        printf("\n%u file(s), %u flagged", c.files, c.flagged);
        if (c.unreadable) printf(", %u could not be opened", c.unreadable);
        putchar('\n');
    }
    free(c.buf);
    return 0;
}
