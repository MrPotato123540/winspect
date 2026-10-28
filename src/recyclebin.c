// winspect recyclebin - Recycle Bin metadata
//
// Deleting a file to the bin moves it to <drive>:\$Recycle.Bin\<SID>\$R<rand>
// and writes a small $I<rand> file with the original path, size and deletion
// time (format in artparse.h, parsed by the unit-tested rb_parse_i). Emptying
// the bin removes both; restoring removes both too. A $I without its $R means
// the content is gone (for example deleted from the bin by hand) but the
// record of the deletion survived. The SID folder tells whose bin it is.
// Windows XP kept one INFO2 index per user in RECYCLER\<SID>\ instead.
// Read-only: files are opened for reading with full sharing.

#include "recyclebin.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_META (4u * 1024 * 1024)

typedef struct {
    int mode, first, only_flagged;
    unsigned items, flagged;
} rctx;

// Whole small file into a malloc'd buffer (NULL on error / too big).
static unsigned char *slurp(const char *path, size_t *n)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    unsigned char *b = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart <= MAX_META &&
            (b = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL) {
        if (!ReadFile(h, b, (DWORD)sz.QuadPart, &got, NULL)) got = 0;
    }
    CloseHandle(h);
    if (b && got == 0) { free(b); b = NULL; }
    *n = got;
    return b;
}

// "S-1-5-21-..." folder name -> DOMAIN\user, or the SID itself.
static void sid_owner(const char *sidstr, char *out, size_t n)
{
    snprintf(out, n, "%s", sidstr);
    PSID sid = NULL;
    if (!ConvertStringSidToSidA(sidstr, &sid)) return;
    char name[128], dom[128];
    DWORD nl = sizeof name, dl = sizeof dom;
    SID_NAME_USE use;
    if (LookupAccountSidA(NULL, sid, name, &nl, dom, &dl, &use))
        snprintf(out, n, "%s%s%s", dom, dom[0] ? "\\" : "", name);
    LocalFree(sid);
}

static void emit(rctx *c, const rb_entry *e, const char *meta, const char *owner, const char *content)
{
    const char *reason = rb_reason(e->path);
    c->items++;
    if (reason) c->flagged++;
    if (c->only_flagged && reason == NULL) return;
    char ts[32];
    filetime_utc_str(e->deleted, ts, sizeof ts);
    if (c->mode == 0) {
        printf("%s %-19s %12llu  %-7s %s  [%s]\n", reason ? "[!]" : "   ", ts,
               (unsigned long long)e->size, content, e->path, owner);
        if (reason) printf("    <- %s\n", reason);
    } else if (c->mode == 2) {
        printf("%s,%llu,", ts, (unsigned long long)e->size);
        csv_str(owner); putchar(',');
        csv_str(e->path); printf(",%s,", content);
        csv_str(meta); putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"deleted\":", c->first ? "" : ",");
        json_str(ts);
        printf(",\"size\":%llu,\"owner\":", (unsigned long long)e->size);
        json_str(owner);
        fputs(",\"path\":", stdout);    json_str(e->path);
        fputs(",\"content\":", stdout); json_str(content);
        fputs(",\"metadata\":", stdout); json_str(meta);
        printf(",\"format\":%d,\"suspicious\":%s,\"reason\":", e->version, reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

// One $I file. Its content twin is the same name with $R in place of $I.
static void one_i(rctx *c, const char *dir, const char *name, const char *owner)
{
    char full[MAX_PATH * 2];
    snprintf(full, sizeof full, "%s\\%s", dir, name);
    size_t n;
    unsigned char *b = slurp(full, &n);
    if (b == NULL) return;
    rb_entry e;
    if (rb_parse_i(b, n, &e) == 0) {
        char twin[MAX_PATH * 2];
        snprintf(twin, sizeof twin, "%s\\$R%s", dir, name + 2);
        const char *content = GetFileAttributesA(twin) != INVALID_FILE_ATTRIBUTES ? "present" : "gone";
        emit(c, &e, full, owner, content);
    }
    free(b);
}

static void one_info2(rctx *c, const char *full, const char *owner)
{
    size_t n;
    unsigned char *b = slurp(full, &n);
    if (b == NULL) return;
    size_t cnt = rb_info2_count(b, n);
    for (size_t i = 0; i < cnt; i++) {
        rb_entry e;
        if (rb_info2_record(b, n, i, &e) != 0) continue;
        // XP named the content D<drive letter><index>.<ext> next to INFO2.
        emit(c, &e, full, owner, e.purged ? "gone" : "in bin");
    }
    free(b);
}

// A per-user folder: every $I* file and an INFO2 if present.
static void scan_user_dir(rctx *c, const char *dir, const char *owner)
{
    char pat[MAX_PATH * 2];
    snprintf(pat, sizeof pat, "%s\\$I*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) one_i(c, dir, fd.cFileName, owner);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    char info2[MAX_PATH * 2];
    snprintf(info2, sizeof info2, "%s\\INFO2", dir);
    if (GetFileAttributesA(info2) != INVALID_FILE_ATTRIBUTES) one_info2(c, info2, owner);
}

// A bin root ($Recycle.Bin or RECYCLER): one folder per SID.
static void scan_root(rctx *c, const char *root)
{
    char pat[MAX_PATH * 2];
    snprintf(pat, sizeof pat, "%s\\*", root);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.') continue;
        char dir[MAX_PATH * 2], owner[300];
        snprintf(dir, sizeof dir, "%s\\%s", root, fd.cFileName);
        if (strncmp(fd.cFileName, "S-1-", 4) == 0) sid_owner(fd.cFileName, owner, sizeof owner);
        else snprintf(owner, sizeof owner, "%s", fd.cFileName);
        scan_user_dir(c, dir, owner);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int cmd_recyclebin(int argc, char **argv)
{
    rctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *target = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)          c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)      c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)  c.only_flagged = 1;
        else if (target == NULL)                     target = argv[a];
        else {
            fprintf(stderr, "recyclebin: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    DWORD tattr = INVALID_FILE_ATTRIBUTES;
    if (target != NULL && (tattr = GetFileAttributesA(target)) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "recyclebin: cannot open '%s'\n", target);
        return 1;
    }
    if (c.mode == 0) {
        puts("recyclebin  (deletion time is UTC; content: present = $R copy still in the bin)\n");
        printf("    %-19s %12s  %-7s %s\n", "deleted", "size", "content", "original path  [owner]");
    } else if (c.mode == 2) {
        puts("deleted,size,owner,path,content,metadata,reason");
    } else {
        putchar('[');
    }
    if (target != NULL) {
        if (!(tattr & FILE_ATTRIBUTE_DIRECTORY)) {
            char dir[MAX_PATH * 2];
            snprintf(dir, sizeof dir, "%s", target);
            char *sl = strrchr(dir, '\\');
            const char *base = sl ? sl + 1 : target;
            if (sl) *sl = '\0';
            else snprintf(dir, sizeof dir, ".");
            // The parent folder is normally the owner's SID.
            char owner[300] = "-";
            const char *pd = strrchr(dir, '\\');
            pd = pd ? pd + 1 : dir;
            if (strncmp(pd, "S-1-", 4) == 0) sid_owner(pd, owner, sizeof owner);
            if (_stricmp(base, "INFO2") == 0) one_info2(&c, target, owner);
            else one_i(&c, dir, base, owner);
        } else {
            // A bin root (one folder per SID) or a single SID folder.
            scan_root(&c, target);
            scan_user_dir(&c, target, "-");
        }
    } else {
        DWORD drives = GetLogicalDrives();
        for (int d = 0; d < 26; d++) {
            if (!(drives & (1u << d))) continue;
            char rootpath[4] = { (char)('A' + d), ':', '\\', 0 };
            UINT t = GetDriveTypeA(rootpath);
            if (t != DRIVE_FIXED && t != DRIVE_REMOVABLE) continue;
            char bin[16];
            snprintf(bin, sizeof bin, "%c:\\$Recycle.Bin", 'A' + d);
            scan_root(&c, bin);
            snprintf(bin, sizeof bin, "%c:\\RECYCLER", 'A' + d);
            scan_root(&c, bin);
        }
    }
    if (c.mode == 1) {
        puts("]");
    } else if (c.mode == 0) {
        printf("\n%u deleted item(s), %u flagged\n", c.items, c.flagged);
    }
    return 0;
}
