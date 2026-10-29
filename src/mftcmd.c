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

// ---- MFT byte sources ---------------------------------------------------------

#define CHUNK (1u << 20)            // multiple of every sector and record size

typedef struct {
    HANDLE h;
    int live;
    size_t record_size;
    uint64_t total;                 // bytes of MFT available
    // live: the $MFT extents and where reading has got to
    mft_run runs[512];
    int nruns, run;
    uint64_t run_done, done;
    uint32_t cluster;
} mftsrc;

static int src_open_file(mftsrc *s, const char *file, char *err, size_t en)
{
    memset(s, 0, sizeof *s);
    s->h = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (s->h == INVALID_HANDLE_VALUE) { snprintf(err, en, "cannot open '%s' (error %lu)", file, (unsigned long)GetLastError()); return -1; }
    LARGE_INTEGER sz;
    static unsigned char first[65536];
    DWORD got = 0;
    if (!GetFileSizeEx(s->h, &sz) || sz.QuadPart < 1024 || !ReadFile(s->h, first, sizeof first, &got, NULL) ||
            (s->record_size = mft_file_record_size(first, got)) == 0) {
        CloseHandle(s->h);
        snprintf(err, en, "'%s' has no FILE record near its start (not an $MFT copy?)", file);
        return -1;
    }
    s->total = (uint64_t)sz.QuadPart;
    LARGE_INTEGER zero = { 0 };
    SetFilePointerEx(s->h, zero, NULL, FILE_BEGIN);
    return 0;
}

// Live: \\.\C: opened read-only; boot sector -> $MFT's first record ->
// its $DATA runs. Reads go through the volume handle in aligned chunks.
static int src_open_live(mftsrc *s, const char *drive, char *err, size_t en)
{
    memset(s, 0, sizeof *s);
    s->live = 1;
    char d = (char)(drive[0] & ~0x20);
    if (d < 'A' || d > 'Z' || (drive[1] && drive[1] != ':')) { snprintf(err, en, "--live takes a drive letter such as C:"); return -1; }
    char vp[8] = { '\\', '\\', '.', '\\', d, ':', 0 };
    s->h = CreateFileA(vp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (s->h == INVALID_HANDLE_VALUE) {
        DWORD er = GetLastError();
        snprintf(err, en, "cannot open volume %c: (%s, error %lu)", d, er == ERROR_ACCESS_DENIED ? "run as administrator" : "not available",
                 (unsigned long)er);
        return -1;
    }
    unsigned char *buf = (unsigned char *)VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD got = 0;
    ntfs_boot nb;
    if (buf == NULL || !ReadFile(s->h, buf, 4096, &got, NULL) || ntfs_parse_boot(buf, got, &nb) != 0) {
        snprintf(err, en, "%c: is not an NTFS volume", d);
        goto fail;
    }
    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG)(nb.mft_lcn * nb.cluster_size);
    if (!SetFilePointerEx(s->h, pos, NULL, FILE_BEGIN) || !ReadFile(s->h, buf, 65536, &got, NULL) || got < nb.record_size) {
        snprintf(err, en, "cannot read the $MFT of %c: (error %lu)", d, (unsigned long)GetLastError());
        goto fail;
    }
    mft_entry e0;
    uint64_t real = 0;
    if (mft_parse(buf, nb.record_size, 0, &e0) != 0 ||
            (s->nruns = mft_data_runs(buf, nb.record_size, s->runs, 512, &real)) <= 0) {
        snprintf(err, en, "the $MFT record of %c: could not be decoded", d);
        goto fail;
    }
    s->record_size = nb.record_size;
    s->cluster = nb.cluster_size;
    s->total = real;
    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
fail:
    if (buf) VirtualFree(buf, 0, MEM_RELEASE);
    CloseHandle(s->h);
    return -1;
}

// Next bytes of the MFT into buf (cap: a multiple of the cluster size).
static size_t src_read(mftsrc *s, unsigned char *buf, size_t cap)
{
    DWORD got = 0;
    if (!s->live) return ReadFile(s->h, buf, (DWORD)cap, &got, NULL) ? got : 0;
    while (s->run < s->nruns) {
        mft_run *r = &s->runs[s->run];
        uint64_t run_bytes = r->clusters * s->cluster;
        if (s->run_done >= run_bytes || r->lcn < 0) { s->run++; s->run_done = 0; continue; }
        uint64_t want = run_bytes - s->run_done;
        if (want > cap) want = cap;
        if (s->done + want > s->total) want = s->total - s->done;
        if (want == 0) return 0;
        LARGE_INTEGER pos;
        pos.QuadPart = (LONGLONG)((uint64_t)r->lcn * s->cluster + s->run_done);
        // Volume reads must cover whole sectors: round the length up.
        DWORD len = (DWORD)((want + 4095) & ~(uint64_t)4095);
        if (len > cap) len = (DWORD)cap;
        if (!SetFilePointerEx(s->h, pos, NULL, FILE_BEGIN) || !ReadFile(s->h, buf, len, &got, NULL) || got == 0) return 0;
        if (got > want) got = (DWORD)want;
        s->run_done += got;
        s->done += got;
        return got;
    }
    return 0;
}

static void src_close(mftsrc *s)
{
    if (s->h && s->h != INVALID_HANDLE_VALUE) CloseHandle(s->h);
}

static int ci_contains(const char *h, const char *n)
{
    size_t L = strlen(n);
    for (; *h; h++) if (_strnicmp(h, n, L) == 0) return 1;
    return 0;
}

int cmd_mft(int argc, char **argv)
{
    int mode = 0, deleted = 0, only_hint = 0;
    const char *file = NULL, *find = NULL, *live = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                     mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                 mode = 2;
        else if (strcmp(argv[a], "--deleted") == 0)             deleted = 1;
        else if (strcmp(argv[a], "--timestomp") == 0)           only_hint = 1;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc) find = argv[++a];
        else if (strcmp(argv[a], "--live") == 0 && a + 1 < argc) live = argv[++a];
        else if (file == NULL && argv[a][0] != '-')             file = argv[a];
        else {
            fprintf(stderr, "mft: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (file == NULL && live == NULL) {
        fputs("mft: give a copied $MFT file, or --live <drive> (administrator)\n", stderr);
        return 1;
    }
    // A source of consecutive MFT bytes: the copied file, or the extents
    // (data runs) of the live volume's $MFT read through the volume handle.
    mftsrc src;
    char err[256] = "";
    if ((live ? src_open_live(&src, live, err, sizeof err) : src_open_file(&src, file, err, sizeof err)) != 0) {
        fprintf(stderr, "mft: %s\n", err);
        return 1;
    }
    size_t rs = src.record_size, count = (size_t)(src.total / rs);
    mft_node *nodes = (mft_node *)calloc(count ? count : 1, sizeof *nodes);
    rowinfo *info = (rowinfo *)calloc(count ? count : 1, sizeof *info);
    unsigned char *chunk = (unsigned char *)VirtualAlloc(NULL, CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (nodes == NULL || info == NULL || chunk == NULL) {
        src_close(&src);
        free(nodes); free(info);
        if (chunk) VirtualFree(chunk, 0, MEM_RELEASE);
        fputs("mft: out of memory\n", stderr);
        return 1;
    }
    size_t rec = 0, bad = 0, got;
    static mft_entry e;
    while (rec < count && (got = src_read(&src, chunk, CHUNK)) >= rs) {
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
    src_close(&src);
    VirtualFree(chunk, 0, MEM_RELEASE);
    if (live) file = live;

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
