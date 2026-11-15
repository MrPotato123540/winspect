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

#define MFT_MAX_RUNS 8192          // a badly fragmented $MFT has thousands of extents
#define CHUNK (1u << 20)            // multiple of every sector and record size

typedef struct {
    HANDLE h;
    int live;
    size_t record_size;
    uint64_t total;                 // bytes of MFT available
    // live: the $MFT extents and where reading has got to
    mft_run runs[MFT_MAX_RUNS];
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

// Reads len bytes at byte offset off of the volume. A volume handle only
// accepts sector-aligned offsets and lengths, so the request is widened to
// 4 KiB boundaries and bounced through an aligned buffer.
static int vol_read(HANDLE h, uint64_t off, unsigned char *dst, size_t len)
{
    static unsigned char *bounce;
    enum { BOUNCE = 1 << 17 };
    if (bounce == NULL) bounce = (unsigned char *)VirtualAlloc(NULL, BOUNCE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (bounce == NULL) return 0;
    // Already aligned (the bulk read of the $MFT into a page-aligned chunk):
    // read straight into the destination.
    if ((off & 4095) == 0 && (len & 4095) == 0 && ((uintptr_t)dst & 4095) == 0 && len <= 0x7FFFF000u) {
        LARGE_INTEGER pos;
        DWORD got = 0;
        pos.QuadPart = (LONGLONG)off;
        return SetFilePointerEx(h, pos, NULL, FILE_BEGIN) && ReadFile(h, dst, (DWORD)len, &got, NULL) && got == len;
    }
    while (len) {
        uint64_t base = off & ~(uint64_t)4095;
        size_t skip = (size_t)(off - base);
        size_t want = skip + len;
        if (want > BOUNCE) want = BOUNCE;
        DWORD ask = (DWORD)((want + 4095) & ~(size_t)4095), got = 0;
        LARGE_INTEGER pos;
        pos.QuadPart = (LONGLONG)base;
        if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN) || !ReadFile(h, bounce, ask, &got, NULL) || got <= skip) return 0;
        size_t take = got - skip;
        if (take > len) take = len;
        memcpy(dst, bounce + skip, take);
        dst += take; off += take; len -= take;
    }
    return 1;
}

// Reads len bytes at byte offset off INSIDE the $MFT, through the extents
// known so far. 0 when the range is not mapped (yet) or sparse.
static int mft_read_at(mftsrc *s, uint64_t off, unsigned char *dst, size_t len)
{
    uint64_t run_start = 0;
    for (int i = 0; i < s->nruns && len; i++) {
        uint64_t run_bytes = s->runs[i].clusters * s->cluster;
        if (off < run_start + run_bytes) {
            if (s->runs[i].lcn < 0) return 0;
            uint64_t in = off - run_start;
            size_t take = (size_t)(run_bytes - in < len ? run_bytes - in : len);
            if (!vol_read(s->h, (uint64_t)s->runs[i].lcn * s->cluster + in, dst, take)) return 0;
            dst += take; off += take; len -= take;
        }
        run_start += run_bytes;
    }
    return len == 0;
}

// A fragmented $MFT does not fit its run list in record 0: the rest is in
// extension records named by record 0's $ATTRIBUTE_LIST. NTFS keeps those
// records inside the part of the $MFT that record 0 itself maps (otherwise
// it could not find them either), so each one can be read with the extents
// collected so far. Without this step only the first part of the $MFT would
// be read and later files would be silently missing.
static void follow_attribute_list(mftsrc *s, unsigned char *rec0, char *warn, size_t wn)
{
    const unsigned char *list = NULL;
    size_t ln = 0;
    unsigned char *heap = NULL;
    int r = mft_attr_resident(rec0, s->record_size, 0x20, &list, &ln);
    if (r < 0) return;                                   // no attribute list: record 0 has it all
    if (r == 1) {
        // The list itself is non-resident: read it from the volume.
        mft_run lr[64];
        uint64_t lsize = 0;
        int n = mft_attr_runs(rec0, s->record_size, 0x20, lr, 64, &lsize, NULL);
        if (n <= 0 || lsize == 0 || lsize > (4u << 20) || (heap = (unsigned char *)malloc((size_t)lsize)) == NULL) {
            snprintf(warn, wn, "the $MFT's attribute list could not be read; later parts of the $MFT may be missing");
            return;
        }
        size_t done = 0;
        for (int i = 0; i < n && done < lsize; i++) {
            size_t take = (size_t)(lr[i].clusters * s->cluster);
            if (take > lsize - done) take = (size_t)(lsize - done);
            if (lr[i].lcn < 0 || !vol_read(s->h, (uint64_t)lr[i].lcn * s->cluster, heap + done, take)) break;
            done += take;
        }
        list = heap;
        ln = done;
    }
    static mft_ext ext[1024];
    int ne = mft_alist_data(list, ln, 0, ext, 1024);
    if (ne > 1024) ne = 1024;
    unsigned char *er = (unsigned char *)malloc(s->record_size);
    for (int i = 0; i < ne && er != NULL; i++) {
        uint64_t mapped = 0;
        for (int k = 0; k < s->nruns; k++) mapped += s->runs[k].clusters;
        if (ext[i].start_vcn != mapped) {
            if (ext[i].start_vcn < mapped) continue;     // already covered
            snprintf(warn, wn, "gap in the $MFT's extents at cluster %llu; later parts are missing",
                     (unsigned long long)mapped);
            break;
        }
        mft_entry ee;
        uint64_t real = 0, vcn = 0;
        int room = MFT_MAX_RUNS - s->nruns;
        int n = -1;
        if (mft_read_at(s, ext[i].recno * s->record_size, er, s->record_size) &&
                mft_parse(er, s->record_size, (uint32_t)ext[i].recno, &ee) == 0) {
            n = mft_attr_runs(er, s->record_size, 0x80, s->runs + s->nruns, room, &real, &vcn);
        }
        if (n <= 0 || vcn != ext[i].start_vcn) {
            snprintf(warn, wn, "extension record %llu of the $MFT could not be decoded; later parts are missing",
                     (unsigned long long)ext[i].recno);
            break;
        }
        s->nruns += n;
    }
    free(er);
    free(heap);
}

// A volume: \\.\C: opened read-only (live), or a raw image of one NTFS
// partition (a file). Boot sector -> the $MFT's first record -> its $DATA
// runs (+ the attribute list's extension records).
static int src_open_volume(mftsrc *s, const char *what, int image, char *err, size_t en, char *warn, size_t wn)
{
    memset(s, 0, sizeof *s);
    s->live = 1;
    char label[MAX_PATH + 8];
    if (image) {
        snprintf(label, sizeof label, "'%s'", what);
        s->h = CreateFileA(what, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (s->h == INVALID_HANDLE_VALUE) {
            snprintf(err, en, "cannot open %s (error %lu)", label, (unsigned long)GetLastError());
            return -1;
        }
    } else {
        char d = (char)(what[0] & ~0x20);
        if (d < 'A' || d > 'Z' || (what[1] && (what[1] != ':' || what[2]))) { snprintf(err, en, "--live takes a drive letter such as C:"); return -1; }
        snprintf(label, sizeof label, "%c:", d);
        char vp[8] = { '\\', '\\', '.', '\\', d, ':', 0 };
        s->h = CreateFileA(vp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (s->h == INVALID_HANDLE_VALUE) {
            DWORD er = GetLastError();
            snprintf(err, en, "cannot open volume %s (%s, error %lu)", label, er == ERROR_ACCESS_DENIED ? "run as administrator" : "not available",
                     (unsigned long)er);
            return -1;
        }
    }
    unsigned char *buf = (unsigned char *)VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ntfs_boot nb;
    if (buf == NULL || !vol_read(s->h, 0, buf, 512) || ntfs_parse_boot(buf, 512, &nb) != 0) {
        snprintf(err, en, image ? "%s is not an image of an NTFS volume (no NTFS boot sector; for a whole-disk image, extract the partition first)"
                                : "%s is not an NTFS volume", label);
        goto fail;
    }
    if (!vol_read(s->h, nb.mft_lcn * nb.cluster_size, buf, nb.record_size)) {
        snprintf(err, en, "cannot read the $MFT of %s (error %lu)", label, (unsigned long)GetLastError());
        goto fail;
    }
    mft_entry e0;
    uint64_t real = 0;
    if (mft_parse(buf, nb.record_size, 0, &e0) != 0 ||
            (s->nruns = mft_data_runs(buf, nb.record_size, s->runs, MFT_MAX_RUNS, &real)) <= 0) {
        snprintf(err, en, "the $MFT record of %s could not be decoded", label);
        goto fail;
    }
    s->record_size = nb.record_size;
    s->cluster = nb.cluster_size;
    s->total = real;
    follow_attribute_list(s, buf, warn, wn);
    // Never claim more than the extents really cover.
    uint64_t mapped = 0;
    for (int k = 0; k < s->nruns; k++) mapped += s->runs[k].clusters * s->cluster;
    if (mapped < s->total) {
        if (warn[0] == 0) {
            snprintf(warn, wn, "only %llu of %llu bytes of the $MFT are mapped by its extents; later records are missing",
                     (unsigned long long)mapped, (unsigned long long)s->total);
        }
        s->total = mapped;
    }
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
        if (!vol_read(s->h, (uint64_t)r->lcn * s->cluster + s->run_done, buf, (size_t)want)) return 0;
        got = (DWORD)want;
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
    long long want_rec = -1;          // --record N: only that record, whatever it holds now
    const char *file = NULL, *find = NULL, *live = NULL, *image = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                     mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                 mode = 2;
        else if (strcmp(argv[a], "--deleted") == 0)             deleted = 1;
        else if (strcmp(argv[a], "--timestomp") == 0)           only_hint = 1;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc) find = argv[++a];
        else if (strcmp(argv[a], "--record") == 0 && a + 1 < argc) {
            char *end = NULL;
            const char *v = argv[++a];
            // decimal, or the hex file reference usn prints (0x...): the low
            // 48 bits are the record number, the top 16 its sequence
            unsigned long long x = strtoull(v, &end, 0);
            if (end == v || *end != '\0') { fprintf(stderr, "mft: --record needs a record number\n"); return 1; }
            want_rec = (long long)(x & 0xFFFFFFFFFFFFULL);
        }
        else if (strcmp(argv[a], "--live") == 0 && a + 1 < argc) live = argv[++a];
        else if (strcmp(argv[a], "--image") == 0 && a + 1 < argc) image = argv[++a];
        else if (file == NULL && argv[a][0] != '-')             file = argv[a];
        else {
            fprintf(stderr, "mft: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if ((file != NULL) + (live != NULL) + (image != NULL) != 1) {
        fputs("mft: give ONE of: a copied $MFT file, --live <drive> (administrator), --image <raw NTFS volume image>\n", stderr);
        return 1;
    }
    // A source of consecutive MFT bytes: the copied file, or the extents
    // (data runs) of the live volume's $MFT read through the volume handle.
    static mftsrc src;
    char err[MAX_PATH + 200] = "", warn[256] = "";
    int orc = live  ? src_open_volume(&src, live, 0, err, sizeof err, warn, sizeof warn)
            : image ? src_open_volume(&src, image, 1, err, sizeof err, warn, sizeof warn)
                    : src_open_file(&src, file, err, sizeof err);
    if (orc != 0) {
        fprintf(stderr, "mft: %s\n", err);
        return 1;
    }
    // Said on stderr so --json / --csv stay clean, and said BEFORE the rows: an
    // incomplete read must not look like "the file is not there".
    if (warn[0]) fprintf(stderr, "mft: WARNING: %s\n", warn);
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
        if (want_rec >= 0 && (long long)i != want_rec) continue;
        if (!nd->valid || !ri->has_fn || ri->extension || nd->name == NULL) {
            if (want_rec >= 0 && mode == 0)
                printf("    %8zu (no file name in this record now: free, never used, or an extension record)\n", i);
            continue;
        }
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
            if (want_rec >= 0) printf("             sequence %u (a journal reference with another sequence meant an earlier file in this record)\n", (unsigned)nd->seq);
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
    if (want_rec >= 0 && (size_t)want_rec >= rec && mode == 0) printf("    record %lld is past the end of this $MFT\n", want_rec);
    if (mode == 1) puts("]");
    else if (mode == 0) printf("\n%u file(s) listed, %u with a timestomp hint%s\n", shown, hinted,
                               bad ? " (some records failed their fixup check)" : "");
    for (size_t i = 0; i < count; i++) free((void *)nodes[i].name);
    free(nodes);
    free(info);
    return 0;
}
