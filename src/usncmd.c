// winspect usn - change journal listing
//
// Records come from usn.c (unit-tested, checked against plaso's test journal).
// A file's RENAME_OLD_NAME record is remembered per file reference so that the
// matching RENAME_NEW_NAME can be judged ("renamed into a program"). With
// --mft, parent references are resolved through mft.c's path builder, checking
// the sequence number so a reused folder record is not mistaken for the
// original. Read-only.

#include "usncmd.h"
#include "usn.h"
#include "mft.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *slurp(const char *path, size_t *n)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    unsigned char *d = NULL;
    size_t got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && (unsigned long long)sz.QuadPart < ((size_t)-1 >> 1) &&
            (d = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL) {
        while (got < (size_t)sz.QuadPart) {
            DWORD part = 0, want = (DWORD)(((size_t)sz.QuadPart - got) > (1u << 30) ? (1u << 30) : ((size_t)sz.QuadPart - got));
            if (!ReadFile(h, d + got, want, &part, NULL) || part == 0) break;
            got += part;
        }
    }
    CloseHandle(h);
    if (d && got == 0) { free(d); d = NULL; }
    *n = got;
    return d;
}

static int is_prog(const char *n) { return rb_reason(n) != NULL; }

static int ci_contains(const char *h, const char *n)
{
    size_t L = strlen(n);
    for (; *h; h++) if (_strnicmp(h, n, L) == 0) return 1;
    return 0;
}

// --reason words -> mask
static uint32_t reason_mask(const char *words)
{
    static const struct { const char *w; uint32_t m; } map[] = {
        { "create", 0x100 }, { "delete", 0x200 }, { "rename", 0x3000 }, { "data", 0x77 },
        { "security", 0x800 }, { "basic", 0x8000 }, { "close", 0x80000000 }, { "stream", 0x200000 },
        { "objectid", 0x80000 }, { "hardlink", 0x10000 },
    };
    uint32_t m = 0;
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) if (ci_contains(words, map[i].w)) m |= map[i].m;
    return m;
}

#define OLD_SLOTS 4096
typedef struct { uint64_t ref; char name[260]; } oldname;

int cmd_usn(int argc, char **argv)
{
    int mode = 0, only_flagged = 0;
    const char *file = NULL, *mftfile = NULL, *find = NULL, *rwords = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                       mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                   mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)               only_flagged = 1;
        else if (strcmp(argv[a], "--mft") == 0 && a + 1 < argc)   mftfile = argv[++a];
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc)  find = argv[++a];
        else if (strcmp(argv[a], "--reason") == 0 && a + 1 < argc) rwords = argv[++a];
        else if (file == NULL && argv[a][0] != '-')               file = argv[a];
        else {
            fprintf(stderr, "usn: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (file == NULL) {
        fputs("usn: give a copied $UsnJrnl:$J file\n", stderr);
        return 1;
    }
    uint32_t want = rwords ? reason_mask(rwords) : 0;
    if (rwords && want == 0) {
        fprintf(stderr, "usn: unknown --reason '%s' (create, delete, rename, data, security, basic, close, stream, objectid, hardlink)\n", rwords);
        return 1;
    }
    size_t n = 0;
    unsigned char *d = slurp(file, &n);
    if (d == NULL) {
        fprintf(stderr, "usn: cannot read '%s'\n", file);
        return 1;
    }
    // Optional $MFT for folder paths.
    mft_node *nodes = NULL;
    size_t nn = 0;
    unsigned char *md = NULL;
    static mft_entry e;
    if (mftfile) {
        size_t mn = 0;
        md = slurp(mftfile, &mn);
        size_t rs = md ? mft_file_record_size(md, mn) : 0;
        if (rs == 0) {
            fprintf(stderr, "usn: '%s' is not an $MFT copy\n", mftfile);
            free(md);
            free(d);
            return 1;
        }
        nn = mn / rs;
        nodes = (mft_node *)calloc(nn, sizeof *nodes);
        for (size_t i = 0; nodes && i < nn; i++) {
            if (mft_parse(md + i * rs, rs, (uint32_t)i, &e) != 0) continue;
            nodes[i] = (mft_node){ e.parent, e.seq, 1, (uint8_t)e.in_use, (uint8_t)e.dir, e.name[0] ? _strdup(e.name) : NULL };
        }
    }
    if (mode == 0) printf("usn  %s  (oldest first, UTC)\n\n", file);
    else if (mode == 2) puts("usn,time,file_ref,parent_ref,reasons,name,folder,reason");
    else putchar('[');
    static oldname olds[OLD_SLOTS];
    memset(olds, 0, sizeof olds);
    size_t off = 0;
    usn_rec r;
    unsigned long count = 0, shown = 0, flagged = 0;
    int first = 1;
    static char folder[8192];
    while (usn_next(d, n, &off, &r)) {
        count++;
        oldname *slot = &olds[(r.file_ref * 2654435761u) % OLD_SLOTS];
        const char *old = (slot->ref == r.file_ref && slot->name[0]) ? slot->name : NULL;
        const char *reason = usn_flag(r.reason, r.name, old, is_prog);
        if (r.reason & 0x1000) { slot->ref = r.file_ref; snprintf(slot->name, sizeof slot->name, "%s", r.name); }
        if (reason) flagged++;
        if (only_flagged && reason == NULL) continue;
        if (want && !(r.reason & want)) continue;
        if (find && !ci_contains(r.name, find)) continue;
        folder[0] = 0;
        if (nodes) {
            uint32_t p = (uint32_t)(r.parent_ref & 0xFFFFFFFFFFFFULL);
            uint16_t ps = (uint16_t)(r.parent_ref >> 48);
            if (p < nn && nodes[p].valid && (nodes[p].seq == ps || (!nodes[p].in_use && nodes[p].seq == (uint16_t)(ps + 1))))
                mft_path(nodes, nn, p, folder, sizeof folder);
            else
                snprintf(folder, sizeof folder, "(folder record %u reused or missing)", p);
        }
        char when[32], rs[512];
        filetime_utc_str(r.time, when, sizeof when);
        usn_reason_str(r.reason, rs, sizeof rs);
        shown++;
        if (mode == 0) {
            printf("%s %-19s %-40s %s%s%s\n", reason ? "[!]" : "   ", when, rs, folder, folder[0] && strcmp(folder, "\\") ? "\\" : "", r.name);
            if (reason) printf("        <- %s%s%s\n", reason, old && (r.reason & 0x2000) ? ", was " : "", old && (r.reason & 0x2000) ? old : "");
        } else if (mode == 2) {
            printf("%llu,%s,0x%llx,0x%llx,%s,", (unsigned long long)r.usn, when, (unsigned long long)r.file_ref,
                   (unsigned long long)r.parent_ref, rs);
            csv_str(r.name); putchar(',');
            csv_str(folder); putchar(',');
            csv_str(reason ? reason : ""); putchar('\n');
        } else {
            printf("%s{\"usn\":%llu,\"time\":\"%s\",\"file_ref\":\"0x%llx\",\"parent_ref\":\"0x%llx\",\"reasons\":\"%s\",\"name\":",
                   first ? "" : ",", (unsigned long long)r.usn, when, (unsigned long long)r.file_ref,
                   (unsigned long long)r.parent_ref, rs);
            json_str(r.name);
            fputs(",\"folder\":", stdout);
            json_str(folder);
            fputs(",\"old_name\":", stdout);
            json_str(old && (r.reason & 0x2000) ? old : "");
            printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
            json_str(reason ? reason : "");
            putchar('}');
            first = 0;
        }
    }
    if (mode == 1) puts("]");
    else if (mode == 0) printf("\n%lu record(s), %lu shown, %lu flagged\n", count, shown, flagged);
    for (size_t i = 0; nodes && i < nn; i++) free((void *)nodes[i].name);
    free(nodes);
    free(md);
    free(d);
    return 0;
}
