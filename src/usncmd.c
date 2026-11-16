// winspect usn - change journal listing
//
// Records come from usn.c (unit-tested, checked against plaso's test journal).
// A file's RENAME_OLD_NAME record is remembered per file reference so that the
// matching RENAME_NEW_NAME can be judged ("renamed into a program"). With
// --mft, parent references are resolved through mft.c's path builder, checking
// the sequence number so a reused folder record is not mistaken for the
// original. Read-only.

#include "usncmd.h"
#include "ioc.h"
#include "usn.h"
#include "mft.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <winioctl.h>
#include <stdint.h>
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

// ---- live volumes ------------------------------------------------------------
// The documented V0 request layouts, declared here because SDKs name them
// differently (READ_USN_JOURNAL_DATA vs ..._V0).
typedef struct { uint64_t journal_id; int64_t first, next, lowest, max; uint64_t max_size, delta; } jdata_v0;
typedef struct { int64_t start; uint32_t mask, only_on_close; uint64_t timeout, bytes_to_wait, journal_id; } jread_v0;
typedef struct { uint64_t start_frn; int64_t low, high; } menum_v0;

typedef struct { uint64_t frn, parent; uint16_t seq; char *name; } lnode;
typedef struct { lnode *v; size_t n, cap; } ltab;

static int lnode_cmp(const void *a, const void *b)
{
    uint64_t x = ((const lnode *)a)->frn, y = ((const lnode *)b)->frn;
    return x < y ? -1 : x > y;
}

static const lnode *ltab_find(const ltab *t, uint64_t frn)
{
    lnode key = { frn & 0xFFFFFFFFFFFFULL, 0, 0, NULL };
    return (const lnode *)bsearch(&key, t->v, t->n, sizeof *t->v, lnode_cmp);
}

// Every file / folder of the volume (FSCTL_ENUM_USN_DATA): number -> parent + name.
static void live_names(HANDLE vol, ltab *t)
{
    static unsigned char buf[1 << 16];
    menum_v0 med = { 0, 0, INT64_MAX };
    DWORD got = 0;
    int full = 0;
    while (!full && DeviceIoControl(vol, FSCTL_ENUM_USN_DATA, &med, sizeof med, buf, sizeof buf, &got, NULL) && got > 8) {
        size_t off = 8;
        usn_rec r;
        while (usn_next(buf, got, &off, &r)) {
            if (t->n == t->cap) {
                size_t nc = t->cap ? t->cap * 2 : 65536;
                lnode *nv = (lnode *)realloc(t->v, nc * sizeof *nv);
                if (nv == NULL) { full = 1; break; }       // keep what we have; still sorted below
                t->v = nv;
                t->cap = nc;
            }
            char *nm = _strdup(r.name);
            if (nm == NULL) { full = 1; break; }
            t->v[t->n++] = (lnode){ r.file_ref & 0xFFFFFFFFFFFFULL, r.parent_ref & 0xFFFFFFFFFFFFULL, (uint16_t)(r.file_ref >> 48), nm };
        }
        med.start_frn = *(uint64_t *)buf;                 // the next file reference to ask for
    }
    // bsearch in live_path needs the table sorted, whatever happened above.
    if (t->n > 1) qsort(t->v, t->n, sizeof *t->v, lnode_cmp);
}

// Full path of the folder whose file reference (number + sequence) is ref.
// The live table holds the volume as it is NOW: a folder deleted since the
// journal record was written may have its number reused by another file, so
// the sequence number must match, or the path would be someone else's.
// Returns 0 with "" when the folder no longer exists.
static int live_path(const ltab *t, char drive, uint64_t ref, char *out, size_t n)
{
    const char *parts[64];
    int np = 0;
    uint64_t cur = ref & 0xFFFFFFFFFFFFULL;
    out[0] = 0;
    const lnode *e = ltab_find(t, cur);
    if (e == NULL || e->seq != (uint16_t)(ref >> 48)) return 0;
    for (int d = 0; d < 64 && e != NULL; d++) {
        if (e->parent == cur) break;                       // the root's parent is itself
        parts[np++] = e->name;
        cur = e->parent;
        e = ltab_find(t, cur);
    }
    size_t o = (size_t)snprintf(out, n, "%c:", drive);
    for (int k = np - 1; k >= 0 && o + 2 < n; k--) {
        int w = snprintf(out + o, n - o, "\\%s", parts[k]);
        if (w < 0) break;
        o += (size_t)w;
    }
    return 1;
}

// Names of files that Windows itself creates and deletes all the time.
static int routine_name(const char *name)
{
    return _strnicmp(name, "__PSScriptPolicyTest_", 21) == 0;   // every PowerShell start
}

// Old names installers and updaters write before renaming into place.
static int staging_name(const char *old)
{
    size_t L = strlen(old);
    return (L >= 4 && _stricmp(old + L - 4, ".tmp") == 0) || (L >= 5 && _stricmp(old + L - 5, ".temp") == 0);
}

#define OLD_SLOTS 4096
#define DEL_SLOTS 65536

// Identity of "this name in this folder" for counting repeated deletions:
// FNV-1a over the parent reference and the lower-cased name.
static uint64_t del_key(uint64_t parent, const char *name)
{
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < 8; i++) { h ^= (parent >> (8 * i)) & 0xFF; h *= 1099511628211ULL; }
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}
typedef struct { uint64_t ref; char name[260]; char folder[1024]; int flagged; } oldname;

int cmd_usn(int argc, char **argv)
{
    int mode = 0, only_flagged = 0;
    const char *file = NULL, *mftfile = NULL, *find = NULL, *rwords = NULL, *live = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)                       mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                   mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)               only_flagged = 1;
        else if (strcmp(argv[a], "--mft") == 0 && a + 1 < argc)   mftfile = argv[++a];
        else if (strcmp(argv[a], "--live") == 0 && a + 1 < argc)  live = argv[++a];
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc)  find = argv[++a];
        else if (strcmp(argv[a], "--reason") == 0 && a + 1 < argc) rwords = argv[++a];
        else if (file == NULL && argv[a][0] != '-')               file = argv[a];
        else {
            fprintf(stderr, "usn: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (file == NULL && live == NULL) {
        fputs("usn: give a copied $UsnJrnl:$J file, or --live <drive> (needs administrator)\n", stderr);
        return 1;
    }
    uint32_t want = rwords ? reason_mask(rwords) : 0;
    if (rwords && want == 0) {
        fprintf(stderr, "usn: unknown --reason '%s' (create, delete, rename, data, security, basic, close, stream, objectid, hardlink)\n", rwords);
        return 1;
    }
    size_t n = 0;
    unsigned char *d = NULL;
    static ltab lt;
    char drive = 0;
    if (live) {
        // Read the live journal through the documented FSCTLs: the records
        // come back in the same USN_RECORD layout as a copied $J.
        drive = (char)(live[0] & ~0x20);
        if (drive < 'A' || drive > 'Z' || (live[1] && live[1] != ':')) {
            fprintf(stderr, "usn: --live takes a drive letter such as C:\n");
            return 1;
        }
        char vp[8] = { '\\', '\\', '.', '\\', drive, ':', 0 };
        HANDLE vol = CreateFileA(vp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (vol == INVALID_HANDLE_VALUE) {
            DWORD er = GetLastError();
            fprintf(stderr, "usn: cannot open volume %c: (%s, error %lu)\n", drive,
                    er == ERROR_ACCESS_DENIED ? "run as administrator" : "not available", (unsigned long)er);
            return 1;
        }
        jdata_v0 jd;
        DWORD got = 0;
        if (!DeviceIoControl(vol, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &jd, sizeof jd, &got, NULL)) {
            fprintf(stderr, "usn: %c: has no change journal (error %lu)\n", drive, (unsigned long)GetLastError());
            CloseHandle(vol);
            return 1;
        }
        size_t cap = 1 << 22;
        d = (unsigned char *)malloc(cap);
        static unsigned char buf[1 << 16];
        jread_v0 rq = { jd.first, 0xFFFFFFFF, 0, 0, 0, jd.journal_id };
        while (d && DeviceIoControl(vol, FSCTL_READ_USN_JOURNAL, &rq, sizeof rq, buf, sizeof buf, &got, NULL) && got > 8) {
            if (n + got > cap) {
                size_t nc = cap * 2;
                while (nc < n + got) nc *= 2;
                unsigned char *nd = (unsigned char *)realloc(d, nc);
                if (nd == NULL) break;
                d = nd;
                cap = nc;
            }
            // First 8 bytes: the USN to continue from; records follow, 8-aligned.
            memcpy(d + n, buf + 8, got - 8);
            n += (got - 8 + 7) & ~(size_t)7;
            int64_t next = *(int64_t *)buf;
            if (next <= rq.start) break;
            rq.start = next;
        }
        live_names(vol, &lt);
        CloseHandle(vol);
        if (d == NULL) { fputs("usn: out of memory\n", stderr); return 1; }
    } else if ((d = slurp(file, &n)) == NULL) {
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
    if (mode == 0) printf("usn  %s%s  (oldest first, UTC)\n\n", live ? "live journal of " : "", live ? live : file);
    else if (mode == 2) puts("usn,time,file_ref,parent_ref,reasons,name,folder,reason");
    else putchar('[');
    static oldname olds[OLD_SLOTS];
    memset(olds, 0, sizeof olds);
    // First pass: how often each (folder, name) is deleted, and the USN of the
    // last deletion. A program file deleted again and again is one that some
    // software regenerates (an updater's cache, a verification copy); it is
    // reported once, on its last deletion, with the count.
    static struct { uint64_t key, last_usn; unsigned count; } dels[DEL_SLOTS];
    memset(dels, 0, sizeof dels);
    {
        size_t o2 = 0;
        usn_rec q;
        while (usn_next(d, n, &o2, &q)) {
            if (!(q.reason & 0x00000200) || !is_prog(q.name)) continue;
            uint64_t key = del_key(q.parent_ref, q.name);
            size_t h = (size_t)(key % DEL_SLOTS);
            for (unsigned probe = 0; probe < 64; probe++, h = (h + 1) % DEL_SLOTS) {
                if (dels[h].count == 0 || dels[h].key == key) {
                    dels[h].key = key;
                    dels[h].count++;
                    dels[h].last_usn = q.usn;
                    break;
                }
            }
        }
    }
    static char recur[160];
    size_t off = 0;
    usn_rec r;
    unsigned long count = 0, shown = 0, flagged = 0, flagged_all = 0;
    static uint64_t track[1024];         // --find: file references already matched
    unsigned ntrack = 0;
    int first = 1;
    static char folder[8192];
    while (usn_next(d, n, &off, &r)) {
        count++;
        oldname *slot = &olds[(r.file_ref * 2654435761u) % OLD_SLOTS];
        const char *old = (slot->ref == r.file_ref && slot->name[0]) ? slot->name : NULL;
        folder[0] = 0;
        int known = 1;                                     // folder resolved (or not needed)
        if (live) {
            if (!live_path(&lt, drive, r.parent_ref, folder, sizeof folder)) {
                snprintf(folder, sizeof folder, "(folder no longer exists)");
                known = 0;
            }
        } else if (nodes) {
            uint32_t p = (uint32_t)(r.parent_ref & 0xFFFFFFFFFFFFULL);
            uint16_t ps = (uint16_t)(r.parent_ref >> 48);
            if (p < nn && nodes[p].valid && (nodes[p].seq == ps || (!nodes[p].in_use && nodes[p].seq == (uint16_t)(ps + 1))))
                mft_path(nodes, nn, p, folder, sizeof folder);
            else {
                snprintf(folder, sizeof folder, "(folder record %u reused or missing)", p);
                known = 0;
            }
        }
        // Deleted while still open: NTFS parks the file in \$Extend\$Deleted
        // under a hex name (its own file reference). Show where it was and
        // judge a later deletion by its real name and folder.
        int parked = usn_posix_deleted_name(r.name, r.file_ref);
        const char *judge_name = r.name;
        if (parked) {
            if (slot->ref == r.file_ref && slot->name[0]) {
                snprintf(folder, sizeof folder, "\\$Extend\\$Deleted (deleted while still open; was %s%s%s)",
                         slot->folder, slot->folder[0] && strcmp(slot->folder, "\\") ? "\\" : "", slot->name);
                judge_name = slot->name;
                known = slot->folder[0] && slot->folder[0] != '(';
            } else {
                snprintf(folder, sizeof folder, "\\$Extend\\$Deleted (deleted while still open)");
                known = 0;
            }
        }
        const char *reason = usn_flag(r.reason, judge_name, parked ? NULL : old, is_prog);
        // The move into $Deleted IS the deletion: the name leaves the folder
        // there, and the FILE_DELETE record only follows when the last handle
        // closes - possibly after this journal was read, possibly never in it.
        // So the move is judged as a deletion of the real name, and a later
        // FILE_DELETE of the same file is not flagged a second time.
        if (parked && (r.reason & 0x2000)) {
            reason = usn_flag(0x00000200, judge_name, NULL, is_prog)
                   ? "program or script deleted (while another program still had it open)" : NULL;
        } else if (parked && (r.reason & 0x00000200) && slot->ref == r.file_ref && slot->flagged) {
            reason = NULL;
        }
        if (reason && routine_name(r.name)) reason = NULL;
        if (reason && (r.reason & 0x2000) && old && staging_name(old)) reason = NULL;
        // With the folder known, only user-writable places count: deleting or
        // renaming programs under Program Files / Windows is what installers
        // and servicing do every day, and needs admin anyway.
        if (reason && (live || nodes)) {
            char full[8192 + 300];
            if (parked && slot->ref == r.file_ref) snprintf(full, sizeof full, "%s\\%s", slot->folder, slot->name);
            else snprintf(full, sizeof full, "%s\\%s", folder, r.name);
            if (!known || !ioc_user_writable(full)) reason = NULL;
        }
        // A reparse point is not a program's content: deleting one (the app
        // execution aliases in ...\Microsoft\WindowsApps are reparse points
        // that Windows recreates per user and per profile) removes no code.
        if (reason && (r.reason & 0x00000200) && (r.attributes & 0x00000400)) reason = NULL;
        if (reason && (r.reason & 0x00000200)) {
            uint64_t key = del_key(r.parent_ref, r.name);
            size_t h = (size_t)(key % DEL_SLOTS);
            for (unsigned probe = 0; probe < 64; probe++, h = (h + 1) % DEL_SLOTS) {
                if (dels[h].count == 0) break;
                if (dels[h].key != key) continue;
                if (dels[h].count > 1) {
                    if (r.usn != dels[h].last_usn) reason = NULL;
                    else {
                        snprintf(recur, sizeof recur, "program or script deleted (%u times in this journal - recreated and deleted repeatedly)", dels[h].count);
                        reason = recur;
                    }
                }
                break;
            }
        }
        // A rename is logged twice (RENAME_NEW_NAME, then with CLOSE): judge it once.
        if (reason && (r.reason & 0x2000) && slot->ref == r.file_ref && slot->flagged) reason = NULL;
        if (r.reason & 0x1000) {
            slot->ref = r.file_ref;
            snprintf(slot->name, sizeof slot->name, "%s", r.name);
            snprintf(slot->folder, sizeof slot->folder, "%s", folder);
            slot->flagged = 0;
        }
        if (reason && (r.reason & 0x2000)) slot->flagged = 1;
        if (reason) flagged_all++;
        if (only_flagged && reason == NULL) continue;
        if (want && !(r.reason & want)) continue;
        if (find) {
            // Follow a matched file by its reference: a rename or delete that
            // comes later under another name (deleted via a temporary name, or
            // renamed away) is shown too, from the first matching record on.
            int byname = ci_contains(r.name, find);
            int tracked = 0;
            for (unsigned k = 0; k < ntrack; k++) if (track[k] == r.file_ref) { tracked = 1; break; }
            if (!byname && !tracked) continue;
            if (byname && !tracked && ntrack < sizeof track / sizeof track[0]) track[ntrack++] = r.file_ref;
        }
        if (reason) flagged++;
        char when[32], rs[512];
        filetime_utc_str(r.time, when, sizeof when);
        usn_reason_str(r.reason, rs, sizeof rs);
        shown++;
        if (mode == 0) {
            printf("%s %-19s %-40s %s%s%s", reason ? "[!]" : "   ", when, rs, folder, folder[0] && strcmp(folder, "\\") ? "\\" : "", r.name);
            // With --find the rows are few: show which $MFT record (and
            // sequence) held the file, for "mft --record" to compare with.
            if (find) printf("   [record %llu seq %u]", (unsigned long long)(r.file_ref & 0xFFFFFFFFFFFFULL), (unsigned)(r.file_ref >> 48));
            putchar('\n');
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
    else if (mode == 0) {
        // flagged = among the rows shown; with a filter the journal may hold more.
        printf("\n%lu record(s), %lu shown, %lu of them flagged", count, shown, flagged);
        if (flagged_all != flagged) printf(" (%lu flagged in the whole journal)", flagged_all);
        putchar('\n');
    }
    for (size_t i = 0; i < lt.n; i++) free(lt.v[i].name);
    free(lt.v);
    lt.v = NULL; lt.n = lt.cap = 0;
    for (size_t i = 0; nodes && i < nn; i++) free((void *)nodes[i].name);
    free(nodes);
    free(md);
    free(d);
    return 0;
}
