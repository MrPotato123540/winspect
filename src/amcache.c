// winspect amcache - file inventory from Amcache.hve
//
// The Program Compatibility Assistant keeps an inventory of executables in a
// registry hive of its own, %SystemRoot%\AppCompat\Programs\Amcache.hve. For
// every file it records the full path and - unlike Prefetch, BAM or ShimCache
// - the file's SHA-1, so a program can be identified (and looked up in threat
// intel) even after it was deleted. Two layouts exist, often side by side:
//
//   Root\File\{volume}\{file reference}      (Windows 8 - early 10)
//       value "15"  full path      "101" "0000" + SHA-1     "17" last modified
//       value "0"   product name   "1"   company name       "100" program id
//   Root\InventoryApplicationFile\{name|hash}  (Windows 10 1607+)
//       LowerCaseLongPath, FileId ("0000" + SHA-1), Publisher, ProductName,
//       Version, Size, LinkDate (PE link time as text), ProgramId
//
// In both, the entry key's last-write time is when Windows recorded the file
// (close to first execution / install, but not proof of execution by
// itself). Value meanings come from public research (e.g. Yogesh Khatri's
// and the SANS DFIR community's write-ups); only the idea is borrowed.
//
// The hive is read with winspect's own offline reader (src/regf.c). Read-only.

#include "amcache.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t when;              // key last write (FILETIME)
    uint64_t modified;          // Root\File value "17" (FILETIME), 0 if none
    const char *layout;         // "File" / "Inventory"
    char path[1024];
    char sha1[41];
    char publisher[256];
    char product[256];
    char version[64];
    char link_date[32];
    const char *reason;
} amrow;

typedef struct {
    regsrc *src;
    amrow *rows;
    size_t n, cap;
    char base[600];             // key path of the entry being read
} amctx;

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

static amrow *new_row(amctx *c)
{
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 256;
        amrow *nr = (amrow *)realloc(c->rows, nc * sizeof *nr);
        if (nr == NULL) return NULL;
        c->rows = nr;
        c->cap = nc;
    }
    amrow *r = &c->rows[c->n];
    memset(r, 0, sizeof *r);
    return r;
}

static void finish(amctx *c, amrow *r)
{
    if (r->path[0] == '\0') return;      // nothing useful recorded
    r->reason = ioc_user_writable(r->path) ? "file in a user-writable dir" : NULL;
    c->n++;
}

// Root\File\{volume}\{file reference}
static void on_file_ref(const char *name, void *vctx)
{
    amctx *c = (amctx *)vctx;
    char path[800];
    snprintf(path, sizeof path, "%s\\%s", c->base, name);
    rkey k;
    if (rk_open(c->src, path, &k) != 0) return;
    amrow *r = new_row(c);
    if (r != NULL) {
        char id[96];
        r->layout = "File";
        r->when = rk_lastwrite(c->src, &k);
        rk_get_str(c->src, &k, "15", r->path, sizeof r->path);
        if (rk_get_str(c->src, &k, "101", id, sizeof id)) amcache_sha1(id, r->sha1);
        rk_get_str(c->src, &k, "1", r->publisher, sizeof r->publisher);
        rk_get_str(c->src, &k, "0", r->product, sizeof r->product);
        rk_get_str(c->src, &k, "5", r->version, sizeof r->version);
        unsigned char ft[8];
        uint32_t type = 0;
        if (rk_get(c->src, &k, "17", &type, ft, sizeof ft) == 8 && type == REG_QWORD) {
            for (int i = 7; i >= 0; i--) r->modified = (r->modified << 8) | ft[i];
        }
        finish(c, r);
    }
    rk_close(&k);
}

static void on_volume(const char *name, void *vctx)
{
    amctx *c = (amctx *)vctx;
    char saved[600];
    snprintf(saved, sizeof saved, "%s", c->base);
    snprintf(c->base, sizeof c->base, "Root\\File\\%s", name);
    rkey k;
    if (rk_open(c->src, c->base, &k) == 0) {
        rk_subkeys(c->src, &k, on_file_ref, c);
        rk_close(&k);
    }
    snprintf(c->base, sizeof c->base, "%s", saved);
}

// Root\InventoryApplicationFile\{entry}
static void on_inventory(const char *name, void *vctx)
{
    amctx *c = (amctx *)vctx;
    char path[800];
    snprintf(path, sizeof path, "Root\\InventoryApplicationFile\\%s", name);
    rkey k;
    if (rk_open(c->src, path, &k) != 0) return;
    amrow *r = new_row(c);
    if (r != NULL) {
        char id[96];
        r->layout = "Inventory";
        r->when = rk_lastwrite(c->src, &k);
        rk_get_str(c->src, &k, "LowerCaseLongPath", r->path, sizeof r->path);
        if (rk_get_str(c->src, &k, "FileId", id, sizeof id)) amcache_sha1(id, r->sha1);
        rk_get_str(c->src, &k, "Publisher", r->publisher, sizeof r->publisher);
        rk_get_str(c->src, &k, "ProductName", r->product, sizeof r->product);
        rk_get_str(c->src, &k, "Version", r->version, sizeof r->version);
        rk_get_str(c->src, &k, "LinkDate", r->link_date, sizeof r->link_date);
        finish(c, r);
    }
    rk_close(&k);
}

static int newest_first(const void *a, const void *b)
{
    uint64_t x = ((const amrow *)a)->when, y = ((const amrow *)b)->when;
    return (x < y) - (x > y);
}

int cmd_amcache(int argc, char **argv)
{
    int mode = 0, only_flagged = 0;
    const char *file = NULL, *want_sha1 = NULL, *find = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0) only_flagged = 1;
        else if (strcmp(argv[a], "--sha1") == 0 && a + 1 < argc) want_sha1 = argv[++a];
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc) find = argv[++a];
        else if (file == NULL)                   file = argv[a];
        else {
            fprintf(stderr, "amcache: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    char deflt[MAX_PATH];
    if (file == NULL) {
        UINT wl = GetSystemWindowsDirectoryA(deflt, MAX_PATH);
        if (wl == 0 || wl > MAX_PATH - 40) return 1;
        snprintf(deflt + wl, sizeof deflt - wl, "\\AppCompat\\Programs\\Amcache.hve");
        file = deflt;
    }
    regsrc src;
    char err[512];
    if (regsrc_open_hive(&src, file, err, sizeof err) != 0) {
        fprintf(stderr, "amcache: %s\n", err);
        return 1;
    }
    if (regsrc_dirty(&src))
        fputs("amcache: note: hive is dirty (transaction logs not replayed) - newest entries may be missing\n", stderr);

    amctx c;
    memset(&c, 0, sizeof c);
    c.src = &src;
    rkey k;
    if (rk_open(&src, "Root\\File", &k) == 0) {
        rk_subkeys(&src, &k, on_volume, &c);
        rk_close(&k);
    }
    if (rk_open(&src, "Root\\InventoryApplicationFile", &k) == 0) {
        rk_subkeys(&src, &k, on_inventory, &c);
        rk_close(&k);
    }
    regsrc_close(&src);
    qsort(c.rows, c.n, sizeof *c.rows, newest_first);

    if (mode == 0) {
        printf("amcache  %s  (newest first; time = when the entry was recorded)\n\n", file);
        printf("    %-19s  %-9s %-40s  %s\n", "recorded (UTC)", "layout", "sha1", "path");
    } else if (mode == 2) {
        puts("recorded,layout,sha1,path,publisher,product,version,link_date,file_modified,reason");
    } else {
        putchar('[');
    }
    unsigned shown = 0, flagged = 0;
    for (size_t i = 0; i < c.n; i++) {
        const amrow *r = &c.rows[i];
        if (r->reason) flagged++;
        if (only_flagged && r->reason == NULL) continue;
        if (want_sha1 && _stricmp(r->sha1, want_sha1) != 0) continue;
        if (find && !ioc_contains_ci(r->path, find)) continue;
        char when[32], mod[32];
        ft_str(r->when, when, sizeof when);
        ft_str(r->modified, mod, sizeof mod);
        if (mode == 0) {
            printf("%s%-19s  %-9s %-40s  %s\n", r->reason ? "[!] " : "    ", when, r->layout,
                   r->sha1[0] ? r->sha1 : "-", r->path);
            if (r->publisher[0] || r->product[0] || r->version[0])
                printf("        %s%s%s%s%s\n", r->publisher, r->publisher[0] && r->product[0] ? " / " : "",
                       r->product, r->version[0] ? "  v" : "", r->version);
            if (r->reason) printf("        <- %s\n", r->reason);
        } else if (mode == 2) {
            csv_str(when); putchar(',');
            csv_str(r->layout); putchar(',');
            csv_str(r->sha1); putchar(',');
            csv_str(r->path); putchar(',');
            csv_str(r->publisher); putchar(',');
            csv_str(r->product); putchar(',');
            csv_str(r->version); putchar(',');
            csv_str(r->link_date); putchar(',');
            csv_str(r->modified ? mod : ""); putchar(',');
            csv_str(r->reason ? r->reason : ""); putchar('\n');
        } else {
            printf("%s{\"recorded\":", shown ? "," : "");
            json_str(when);
            fputs(",\"layout\":", stdout);    json_str(r->layout);
            fputs(",\"sha1\":", stdout);      json_str(r->sha1);
            fputs(",\"path\":", stdout);      json_str(r->path);
            fputs(",\"publisher\":", stdout); json_str(r->publisher);
            fputs(",\"product\":", stdout);   json_str(r->product);
            fputs(",\"version\":", stdout);   json_str(r->version);
            fputs(",\"link_date\":", stdout); json_str(r->link_date);
            fputs(",\"file_modified\":", stdout);
            if (r->modified) json_str(mod); else fputs("null", stdout);
            printf(",\"suspicious\":%s,\"reason\":", r->reason ? "true" : "false");
            json_str(r->reason ? r->reason : "");
            putchar('}');
        }
        shown++;
    }
    if (mode == 1) {
        puts("]");
    } else if (mode == 0) {
        printf("\n%lu entr%s, %u shown, %u in user-writable dirs\n", (unsigned long)c.n,
               c.n == 1 ? "y" : "ies", shown, flagged);
    }
    free(c.rows);
    return 0;
}
