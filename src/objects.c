// winspect objects - named kernel objects in the Object Manager namespace
//
// Everything a process creates by NAME - a mutex ("Mutant" to the kernel), an
// event, a shared-memory section, a semaphore - lives in an Object Manager
// directory. Desktop processes in session N use \Sessions\N\BaseNamedObjects;
// the global namespace is \BaseNamedObjects. Listing a directory is how
// WinObj and AccessChk -o see these names.
//
// Why it matters for triage: malware very often creates a uniquely-named mutex
// so a second copy of itself exits early ("single instance"), and those names
// are published as indicators. Seeing the names on a live machine is a cheap
// hunt. This is read-only: we open the directory with DIRECTORY_QUERY and only
// enumerate names; we never open the objects themselves.
//
// NtOpenDirectoryObject / NtQueryDirectoryObject are exported by ntdll but have
// no import library, so we resolve them at run time. The enumeration loop
// follows the documented contract: pass RestartScan=TRUE only on the first call
// and carry the Context value between calls until STATUS_NO_MORE_ENTRIES.

#include "objects.h"
#include "jsonutil.h"

#include <windows.h>
#include <winternl.h>   // UNICODE_STRING, OBJECT_ATTRIBUTES, InitializeObjectAttributes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WS_DIRECTORY_QUERY        0x0001
#define WS_STATUS_MORE_ENTRIES    ((LONG)0x00000105L)
#define WS_STATUS_NO_MORE_ENTRIES ((LONG)0x8000001AL)

// One directory entry as NtQueryDirectoryObject returns it (undocumented but
// stable: two UNICODE_STRINGs whose buffers point into the same output buffer).
typedef struct {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} WS_OBJDIR_INFO;

typedef LONG (NTAPI *NtOpenDirectoryObject_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef LONG (NTAPI *NtQueryDirectoryObject_t)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN,
                                                PULONG, PULONG);

static void us2u(const UNICODE_STRING *us, char *out, size_t n)
{
    out[0] = '\0';
    if (us->Buffer == NULL || us->Length == 0) {
        return;
    }
    int got = WideCharToMultiByte(CP_UTF8, 0, us->Buffer, us->Length / (int)sizeof(WCHAR),
                                  out, (int)n - 1, NULL, NULL);
    out[(got > 0) ? got : 0] = '\0';
}

int cmd_objects(int argc, char **argv)
{
    const char *dir_arg = NULL;
    const char *type_filter = NULL;
    int global = 0;
    int mode = 0;   // 0 text, 1 json, 2 csv
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)        mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)    mode = 2;
        else if (strcmp(argv[a], "--global") == 0) global = 1;
        else if (strcmp(argv[a], "--type") == 0) {
            if (a + 1 >= argc) { fputs("objects: --type needs a type name\n", stderr); return 1; }
            type_filter = argv[++a];
        }
        else if (dir_arg == NULL)                  dir_arg = argv[a];
        else {
            fprintf(stderr, "objects: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    // Pick the directory: explicit path, the global namespace, or (default)
    // this session's private BaseNamedObjects.
    char dir[512];
    if (dir_arg != NULL) {
        snprintf(dir, sizeof dir, "%s", dir_arg);
    } else if (global) {
        snprintf(dir, sizeof dir, "\\BaseNamedObjects");
    } else {
        DWORD sid = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &sid);
        snprintf(dir, sizeof dir, "\\Sessions\\%lu\\BaseNamedObjects", (unsigned long)sid);
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtOpenDirectoryObject_t NtOpenDir = ntdll ? (NtOpenDirectoryObject_t)(void(*)(void))
        GetProcAddress(ntdll, "NtOpenDirectoryObject") : NULL;
    NtQueryDirectoryObject_t NtQueryDir = ntdll ? (NtQueryDirectoryObject_t)(void(*)(void))
        GetProcAddress(ntdll, "NtQueryDirectoryObject") : NULL;
    if (NtOpenDir == NULL || NtQueryDir == NULL) {
        fputs("objects: Object Manager directory APIs not available\n", stderr);
        return 1;
    }

    WCHAR wdir[512];
    if (MultiByteToWideChar(CP_UTF8, 0, dir, -1, wdir, 512) == 0) {
        fprintf(stderr, "objects: cannot convert path '%s'\n", dir);
        return 1;
    }
    UNICODE_STRING us;
    us.Buffer = wdir;
    us.Length = (USHORT)(wcslen(wdir) * sizeof(WCHAR));
    us.MaximumLength = (USHORT)(us.Length + sizeof(WCHAR));
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hdir = NULL;
    LONG st = NtOpenDir(&hdir, WS_DIRECTORY_QUERY, &oa);
    if (st < 0 || hdir == NULL) {
        fprintf(stderr, "objects: cannot open '%s' (status 0x%08lX)\n", dir, (unsigned long)st);
        return 1;
    }

    if (mode == 0) {
        printf("objects  %s\n", dir);
        if (type_filter) { printf("  (only type %s)\n", type_filter); }
        printf("\n  %-22s %s\n", "type", "name");
    } else if (mode == 2) {
        puts("type,name");
    } else {
        putchar('[');
    }

    // 64 KB holds many entries per call; the loop continues for large dirs.
    ULONG bufsize = 64 * 1024;
    BYTE *buf = (BYTE *)malloc(bufsize);
    if (buf == NULL) {
        CloseHandle(hdir);
        return 1;
    }

    ULONG context = 0;
    unsigned count = 0;
    int failed = 0;
    int first_json = 1;
    for (int call = 0; call < 10000; call++) {
        ULONG retlen = 0;
        st = NtQueryDir(hdir, buf, bufsize, FALSE, (BOOLEAN)(call == 0), &context, &retlen);
        if (st == WS_STATUS_NO_MORE_ENTRIES) {
            break;
        }
        if (st < 0) {
            fprintf(stderr, "objects: NtQueryDirectoryObject failed (status 0x%08lX)\n",
                    (unsigned long)st);
            failed = 1;
            break;
        }
        // The buffer holds an array terminated by an all-zero entry.
        const WS_OBJDIR_INFO *e = (const WS_OBJDIR_INFO *)buf;
        for (; e->Name.Buffer != NULL; e++) {
            char name[512], type[64];
            us2u(&e->Name, name, sizeof name);
            us2u(&e->TypeName, type, sizeof type);
            if (type_filter != NULL && _stricmp(type, type_filter) != 0) {
                continue;
            }
            count++;
            if (mode == 0) {
                printf("  %-22s %s\n", type, name);
            } else if (mode == 2) {
                csv_str(type); putchar(',');
                csv_str(name); putchar('\n');
            } else {
                printf("%s{\"type\":", first_json ? "" : ",");
                json_str(type);
                fputs(",\"name\":", stdout); json_str(name);
                putchar('}');
                first_json = 0;
            }
        }
        // STATUS_MORE_ENTRIES or STATUS_SUCCESS: keep asking with the same
        // context; the call after the last batch reports NO_MORE_ENTRIES.
    }

    free(buf);
    CloseHandle(hdir);

    if (mode == 0) {
        printf("\n%u object(s)%s\n", count, failed ? "  (listing incomplete)" : "");
    } else if (mode == 1) {
        puts("]");
    }
    return failed ? 1 : 0;
}
