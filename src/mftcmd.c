// winspect mft - $MFT file listing with timestomping hints
//
// Pass 1 reads every record (mft.c applies the fixups and decodes the
// attributes) into a compact table; pass 2 prints each file record with its
// path rebuilt from the parent references. Extension records (a file whose
// attributes did not fit one record) are skipped as rows: their base record
// is the file. Read-only.

#include "mftcmd.h"
#include "mft.h"
#include "destlist.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t si[4], fn[4], size;
    unsigned char objid[16];
    uint8_t has_fn, has_objid, extension;
} rowinfo;

static int ci_contains(const char *h, const char *n)
{
    size_t L = strlen(n);
    for (; *h; h++) if (_strnicmp(h, n, L) == 0) return 1;
    return 0;
}

int cmd_mft(int argc, char **argv)
{
    int mode = 0, deleted = 0, only_hint = 0;
    const char *file = NULL, *find = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                     mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                 mode = 2;
        else if (strcmp(argv[a], "--deleted") == 0)             deleted = 1;
        else if (strcmp(argv[a], "--timestomp") == 0)           only_hint = 1;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc) find = argv[++a];
        else if (file == NULL && argv[a][0] != '-')             file = argv[a];
        else {
            fprintf(stderr, "mft: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (file == NULL) {
        fputs("mft: give a copied $MFT file (the live one is not readable as a file)\n", stderr);
        return 1;
    }
    HANDLE h = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "mft: cannot open '%s' (error %lu)\n", file, (unsigned long)GetLastError());
        return 1;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 1024) {
        CloseHandle(h);
        fprintf(stderr, "mft: '%s' is too small to be an $MFT\n", file);
        return 1;
    }
    static unsigned char first[65536];
    DWORD got = 0;
    size_t rs = 0;
    if (!ReadFile(h, first, sizeof first, &got, NULL) || (rs = mft_file_record_size(first, got)) == 0) {
        CloseHandle(h);
        fprintf(stderr, "mft: '%s' has no FILE record near its start (not an $MFT copy?)\n", file);
        return 1;
    }
    size_t count = (size_t)(sz.QuadPart / (LONGLONG)rs);
    mft_node *nodes = (mft_node *)calloc(count, sizeof *nodes);
    rowinfo *info = (rowinfo *)calloc(count, sizeof *info);
    unsigned char *chunk = (unsigned char *)malloc(rs * 1024);
    if (nodes == NULL || info == NULL || chunk == NULL) {
        CloseHandle(h);
        free(nodes); free(info); free(chunk);
        fputs("mft: out of memory\n", stderr);
        return 1;
    }
    LARGE_INTEGER zero = { 0 };
    SetFilePointerEx(h, zero, NULL, FILE_BEGIN);
    size_t rec = 0, bad = 0;
    static mft_entry e;
    while (rec < count) {
        if (!ReadFile(h, chunk, (DWORD)(rs * 1024), &got, NULL) || got < rs) break;
        for (size_t k = 0; k + rs <= got && rec < count; k += rs, rec++) {
            if (mft_parse(chunk + k, rs, (uint32_t)rec, &e) != 0) {
                if (memcmp(chunk + k, "FILE", 4) == 0) bad++;
                continue;
            }
            mft_node *nd = &nodes[rec];
            nd->parent = e.parent;
            nd->seq = e.seq;
            nd->valid = 1;
            nd->in_use = (uint8_t)e.in_use;
            nd->dir = (uint8_t)e.dir;
            nd->name = e.name[0] ? _strdup(e.name) : NULL;
            rowinfo *ri = &info[rec];
            memcpy(ri->si, e.si, sizeof ri->si);
            memcpy(ri->fn, e.fn, sizeof ri->fn);
            ri->size = e.size;
            ri->has_fn = (uint8_t)e.has_fn;
            ri->extension = (uint8_t)e.extension;
            ri->has_objid = (uint8_t)e.has_objid;
            memcpy(ri->objid, e.objid, 16);
        }
    }
    CloseHandle(h);
    free(chunk);

    if (mode == 0) {
        printf("mft  %s  (%zu records of %zu bytes, times UTC)\n\n", file, rec, rs);
    } else if (mode == 2) {
        puts("record,path,in_use,directory,size,si_created,si_modified,si_mft_changed,si_accessed,fn_created,objid_created,objid_mac,timestomp_hint");
    } else {
        putchar('[');
    }
    unsigned shown = 0, hinted = 0;
    int firstrow = 1;
    static char path[8192];
    for (size_t i = 0; i < rec; i++) {
        const mft_node *nd = &nodes[i];
        const rowinfo *ri = &info[i];
        if (!nd->valid || !ri->has_fn || ri->extension || nd->name == NULL) continue;
        if (deleted && nd->in_use) continue;
        mft_path(nodes, rec, (uint32_t)i, path, sizeof path);
        if (find && !ci_contains(path, find)) continue;
        // A hint, not a flag: on a real system most of these are files from
        // install media or archives that keep their original creation time.
        const char *hint = nd->dir ? NULL : mft_timestomp_reason(ri->si, ri->fn);
        if (hint) hinted++;
        if (only_hint && hint == NULL) continue;
        char t[5][32], oc[32] = "", mac[18] = "";
        for (int k = 0; k < 4; k++) filetime_utc_str(ri->si[k], t[k], sizeof t[k]);
        filetime_utc_str(ri->fn[0], t[4], sizeof t[4]);
        if (ri->has_objid) {
            uint64_t ot = uuid1_info(ri->objid, mac);
            if (ot) filetime_utc_str(ot, oc, sizeof oc);
        }
        shown++;
        if (mode == 0) {
            printf("    %8zu %s%s%s\n", i, path, nd->dir ? "\\" : "", nd->in_use ? "" : "  (deleted)");
            printf("             created %s  modified %s  size %llu%s%s\n", t[0], t[1], (unsigned long long)ri->size,
                   strcmp(t[0], t[4]) ? "  | $FN created " : "", strcmp(t[0], t[4]) ? t[4] : "");
            if (oc[0]) printf("             object id created %s on %s\n", oc, mac[0] ? mac : "?");
            if (hint) printf("             note: %s\n", hint);
        } else if (mode == 2) {
            printf("%zu,", i);
            csv_str(path);
            printf(",%d,%d,%llu,%s,%s,%s,%s,%s,%s,%s,", nd->in_use, nd->dir, (unsigned long long)ri->size,
                   t[0], t[1], t[2], t[3], t[4], oc, mac);
            csv_str(hint ? hint : ""); putchar('\n');
        } else {
            printf("%s{\"record\":%zu,\"path\":", firstrow ? "" : ",", i);
            json_str(path);
            printf(",\"in_use\":%s,\"directory\":%s,\"size\":%llu,\"si_created\":\"%s\",\"si_modified\":\"%s\","
                   "\"si_mft_changed\":\"%s\",\"si_accessed\":\"%s\",\"fn_created\":\"%s\",\"objid_created\":\"%s\","
                   "\"objid_mac\":\"%s\",\"timestomp_hint\":",
                   nd->in_use ? "true" : "false", nd->dir ? "true" : "false", (unsigned long long)ri->size,
                   t[0], t[1], t[2], t[3], t[4], oc, mac);
            json_str(hint ? hint : "");
            putchar('}');
            firstrow = 0;
        }
    }
    if (mode == 1) puts("]");
    else if (mode == 0) printf("\n%u file(s) listed, %u with a timestomp hint%s\n", shown, hinted,
                               bad ? " (some records failed their fixup check)" : "");
    for (size_t i = 0; i < count; i++) free((void *)nodes[i].name);
    free(nodes);
    free(info);
    return 0;
}
