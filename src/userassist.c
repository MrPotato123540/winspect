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
// Only the current user's hive is loaded by default, so only they are shown.
//
// Read-only: RegEnum/RegQuery only.

#include "userassist.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UA_ROOT L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

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

int cmd_userassist(int argc, char **argv)
{
    int mode = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else {
            fprintf(stderr, "userassist: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    HKEY root;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, UA_ROOT, 0, KEY_READ, &root) != ERROR_SUCCESS) {
        if (mode == 1)      puts("[]");
        else if (mode == 2) puts("last_run,runs,kind,program,reason");
        else                puts("userassist: no UserAssist data for this user");
        return 0;
    }
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);    // for SHGetKnownFolderPath

    uarow *rows = NULL;
    size_t nrows = 0, cap = 0;
    for (DWORD g = 0;; g++) {
        WCHAR guid[64];
        DWORD gl = 64;
        if (RegEnumKeyExW(root, g, guid, &gl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        const char *kind = _wcsicmp(guid, L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}") == 0 ? "executable"
                         : _wcsicmp(guid, L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}") == 0 ? "shortcut"
                         : "other";
        WCHAR sub[128];
        _snwprintf(sub, 128, L"%ls\\Count", guid);
        sub[127] = 0;
        HKEY k;
        if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) continue;
        for (DWORD i = 0;; i++) {
            WCHAR wname[1024];
            DWORD nl = 1024, dl = 128, type = 0;
            BYTE data[128];
            LONG rc = RegEnumValueW(k, i, wname, &nl, NULL, &type, data, &dl);
            if (rc == ERROR_MORE_DATA) continue;
            if (rc != ERROR_SUCCESS) break;
            uint32_t runs = 0;
            uint64_t last = 0;
            if (type != REG_BINARY || !userassist_record(data, dl, &runs, &last)) continue;
            if (nrows == cap) {
                size_t nc = cap ? cap * 2 : 64;
                uarow *nr = (uarow *)realloc(rows, nc * sizeof *nr);
                if (nr == NULL) break;
                rows = nr;
                cap = nc;
            }
            uarow *r = &rows[nrows];
            WideCharToMultiByte(CP_UTF8, 0, wname, -1, r->program, sizeof r->program, NULL, NULL);
            rot13_inplace(r->program);
            if (strncmp(r->program, "UEME_", 5) == 0) continue;    // session bookkeeping, not a program
            resolve_known_folder(r->program, sizeof r->program);
            r->runs = runs;
            ft_str(last, r->time, sizeof r->time);
            r->kind = kind;
            r->reason = ioc_script_host(r->program) ? "script host / LOLBin started from the GUI"
                      : ioc_user_writable(r->program) ? "program in a user-writable dir"
                      : NULL;
            nrows++;
        }
        RegCloseKey(k);
    }
    RegCloseKey(root);
    CoUninitialize();
    qsort(rows, nrows, sizeof *rows, by_time_desc);

    unsigned flagged = 0;
    if (mode == 0) {
        puts("userassist  (GUI launches by the current user, newest first)\n");
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
    return 0;
}
