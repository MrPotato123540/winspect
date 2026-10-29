// winspect userassist - GUI program launches recorded by Explorer
//
// Explorer keeps per-user counters of what the user launched through the
// shell, under
//   HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
// The two GUIDs that matter on Windows 7+ are
//   {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}  executables
//   {F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}  shortcut (.lnk) launches
// Each VALUE NAME is the program, ROT13-encoded (an old, trivial obfuscation),
// and often starts with a Known Folder GUID instead of a drive path
// ("{6D809377-...}\app.exe" = Program Files\app.exe). The value DATA holds the
// run count and the last run time (layouts in artparse.c, unit-tested; the
// focus fields are skipped because public sources disagree on them).
//
// For an investigator this answers "did THIS user start that program, how
// often, and when last" - complementary to Prefetch (any user) and BAM.
// The live registry only has the current user's hive loaded; --hive reads
// another user's NTUSER.DAT (copied off the machine or out of a triage
// collection) through the offline reader (regsrc.c / regf.c). Known Folder
// GUIDs are only resolved in live mode - in a foreign hive they would be
// resolved against THIS machine's folders, so they are left as they are.
//
// Read-only: RegEnum/RegQuery or an in-memory copy of the hive file.

#include "userassist.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UA_ROOT "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

typedef struct {
    char time[24];
    unsigned runs;
    char program[1024];
    const char *kind;
    const char *reason;
} uarow;

static int by_time_desc(const void *a, const void *b)
{
    return -strcmp(((const uarow *)a)->time, ((const uarow *)b)->time);
}

// "{GUID}\rest" -> "<known folder path>\rest" when the GUID is a Known Folder.
static void resolve_known_folder(char *name, size_t n)
{
    if (name[0] != '{') return;
    char *close = strchr(name, '}');
    if (close == NULL || (size_t)(close - name) != 37) return;
    WCHAR wguid[40];
    char guid[40];
    memcpy(guid, name, 38);
    guid[38] = '\0';
    MultiByteToWideChar(CP_UTF8, 0, guid, -1, wguid, 40);
    KNOWNFOLDERID id;
    if (FAILED(CLSIDFromString(wguid, &id))) return;
    PWSTR folder = NULL;
    if (FAILED(SHGetKnownFolderPath(&id, 0, NULL, &folder)) || folder == NULL) return;
    char base[MAX_PATH * 2];
    WideCharToMultiByte(CP_UTF8, 0, folder, -1, base, sizeof base, NULL, NULL);
    CoTaskMemFree(folder);
    char out[2048];
    snprintf(out, sizeof out, "%s%s", base, close + 1);
    snprintf(name, n, "%s", out);
}

static void ft_str(uint64_t t, char *out, size_t n)
{
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = (DWORD)t;
    ft.dwHighDateTime = (DWORD)(t >> 32);
    if (t == 0 || !FileTimeToSystemTime(&ft, &st)) {
        snprintf(out, n, "-");
        return;
    }
    snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

typedef struct {
    uarow *rows;
    size_t n, cap;
    const char *kind;
    int resolve;            // resolve Known Folder GUIDs (live mode only)
} uactx;

static void on_value(const char *name, uint32_t type, const unsigned char *data, size_t len, void *vctx)
{
    uactx *c = (uactx *)vctx;
    uint32_t runs = 0;
    uint64_t last = 0;
    if (type != REG_BINARY || data == NULL || !userassist_record(data, len, &runs, &last)) return;
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 64;
        uarow *nr = (uarow *)realloc(c->rows, nc * sizeof *nr);
        if (nr == NULL) return;
        c->rows = nr;
        c->cap = nc;
    }
    uarow *r = &c->rows[c->n];
    snprintf(r->program, sizeof r->program, "%s", name);
    rot13_inplace(r->program);
    if (strncmp(r->program, "UEME_", 5) == 0) return;    // session bookkeeping, not a program
    if (c->resolve) resolve_known_folder(r->program, sizeof r->program);
    r->runs = runs;
    ft_str(last, r->time, sizeof r->time);
    r->kind = c->kind;
    r->reason = ioc_script_host(r->program) ? "script host / LOLBin started from the GUI"
              : ioc_user_writable(r->program) ? "program in a user-writable dir"
              : NULL;
    c->n++;
}

typedef struct { char guids[32][64]; int n; } guidlist;
static void on_guid(const char *name, void *vctx)
{
    guidlist *g = (guidlist *)vctx;
    if (g->n < 32) snprintf(g->guids[g->n++], sizeof g->guids[0], "%s", name);
}

int cmd_userassist(int argc, char **argv)
{
    int mode = 0;
    const char *hive = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else if (strcmp(argv[a], "--hive") == 0 && a + 1 < argc) hive = argv[++a];
        else {
            fprintf(stderr, "userassist: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    regsrc src;
    if (hive != NULL) {
        char err[512];
        if (regsrc_open_hive(&src, hive, err, sizeof err) != 0) {
            fprintf(stderr, "userassist: %s\n", err);
            return 1;
        }
        if (regsrc_dirty(&src))
            fprintf(stderr, "userassist: note: hive is dirty (transaction logs not replayed) - "
                            "the newest changes may be missing\n");
    } else {
        regsrc_open_live(&src, HKEY_CURRENT_USER, NULL, "HKCU");
    }
    rkey root;
    if (rk_open(&src, UA_ROOT, &root) != 0) {
        if (mode == 1)      puts("[]");
        else if (mode == 2) puts("last_run,runs,kind,program,reason");
        else                printf("userassist: no UserAssist data in %s\n", src.label);
        regsrc_close(&src);
        return 0;
    }
    if (hive == NULL) CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);    // for SHGetKnownFolderPath

    uactx c;
    memset(&c, 0, sizeof c);
    c.resolve = hive == NULL;
    static guidlist gl;
    gl.n = 0;
    rk_subkeys(&src, &root, on_guid, &gl);
    for (int g = 0; g < gl.n; g++) {
        const char *guid = gl.guids[g];
        c.kind = _stricmp(guid, "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}") == 0 ? "executable"
               : _stricmp(guid, "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}") == 0 ? "shortcut"
               : "other";
        char sub[160];
        snprintf(sub, sizeof sub, "%s\\%s\\Count", UA_ROOT, guid);
        rkey k;
        if (rk_open(&src, sub, &k) != 0) continue;
        rk_values(&src, &k, on_value, &c);
        rk_close(&k);
    }
    rk_close(&root);
    if (hive == NULL) CoUninitialize();
    uarow *rows = c.rows;
    size_t nrows = c.n;
    qsort(rows, nrows, sizeof *rows, by_time_desc);

    unsigned flagged = 0;
    if (mode == 0) {
        printf("userassist  (GUI launches recorded in %s, newest first)\n\n", src.label);
        printf("      %-19s  %5s  %-10s %s\n", "last run (UTC)", "runs", "kind", "program");
    } else if (mode == 2) {
        puts("last_run,runs,kind,program,reason");
    } else {
        putchar('[');
    }
    for (size_t i = 0; i < nrows; i++) {
        const uarow *r = &rows[i];
        flagged += r->reason != NULL;
        if (mode == 0) {
            printf("  %s%-19s  %5u  %-10s %s\n", r->reason ? "[!] " : "    ", r->time, r->runs,
                   r->kind, r->program);
            if (r->reason) printf("        <- %s\n", r->reason);
        } else if (mode == 2) {
            csv_str(r->time); printf(",%u,", r->runs);
            csv_str(r->kind); putchar(',');
            csv_str(r->program); putchar(',');
            csv_str(r->reason ? r->reason : ""); putchar('\n');
        } else {
            printf("%s{\"last_run\":", i ? "," : "");
            json_str(r->time);
            printf(",\"runs\":%u,\"kind\":", r->runs);
            json_str(r->kind);
            fputs(",\"program\":", stdout); json_str(r->program);
            printf(",\"suspicious\":%s,\"reason\":", r->reason ? "true" : "false");
            json_str(r->reason ? r->reason : "");
            putchar('}');
        }
    }
    if (mode == 0) {
        printf("\n%lu program(s), %u flagged\n", (unsigned long)nrows, flagged);
    } else if (mode == 1) {
        puts("]");
    }
    free(rows);
    regsrc_close(&src);
    return 0;
}
