// winspect handles - the kernel object handles a live process holds
//
// Every open file, process, thread, event, mutex, registry key and so on is a
// kernel object, and a process reaches one through a HANDLE: a small integer
// that indexes a per-process handle table in the kernel. This command dumps
// that table for one PID - or, with --find, searches every process's table for
// an object name (the "who has this file open?" question Sysinternals Handle
// answers; only the idea is borrowed).
//
// We do NOT walk the target's memory. We ask the kernel for the WHOLE
// machine's handle table in one shot via NtQuerySystemInformation and filter.
// We use the EXTENDED class (SystemExtendedHandleInformation, 64): its entries
// carry the full pointer-sized PID and handle value. The legacy class (16)
// stores both in 16 bits, so on a busy machine a PID above 65535 aliases
// another process and a handle above 0xFFFF is truncated - the wrong handle
// would then be duplicated and described. The legacy class is only a fallback
// for systems that do not offer the extended one.
//
// Turning an entry into "File \Device\HarddiskVolume3\x.txt" means duplicating
// the handle into our process and asking NtQueryObject. The name query can
// BLOCK forever on a synchronous file object with an operation pending (a
// named pipe being read, typically), so for File objects it runs on a worker
// thread with a short timeout; a stuck worker is abandoned (never terminated)
// and after a few of those, file names are no longer queried at all.

#include "handles.h"
#include "jsonutil.h"
#include "rights.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>     // strtoul, malloc, free
#include <stdint.h>     // uintptr_t
#include <string.h>     // strcmp (option parsing)

// We do not include <winternl.h> here because it also declares
// SYSTEM_HANDLE_INFORMATION and would clash with our own definitions below.
// We only need the UNICODE_STRING shape, so we declare a matching one.
typedef struct { USHORT Length; USHORT MaximumLength; WCHAR *Buffer; } WS_USTR;

// --- Native structures not in the public headers -----------------------------
#define SystemHandleInformation         16
#define SystemExtendedHandleInformation 64
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)

// Legacy entry: 16-bit process id and handle value.
typedef struct {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} HANDLE_ENTRY_LEGACY;

// Extended entry: full-width process id and handle value.
typedef struct {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} HANDLE_ENTRY_EX;

// Resolved at run time from ntdll.
typedef LONG (NTAPI *NtQuerySystemInformation_t)(
    int SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

// NtQueryObject turns a handle into its object's type name ("File", "Key",
// "Event", ...) and its object name ("\Device\...\file.txt").
// Information classes: 1 = name, 2 = type.
typedef LONG (NTAPI *NtQueryObject_t)(
    HANDLE Handle, int ObjectInformationClass, PVOID ObjectInformation,
    ULONG Length, PULONG ReturnLength);
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

// Both queries return a leading UNICODE_STRING whose Buffer points back into the
// buffer we supplied, so a struct whose first field is that UNICODE_STRING is
// enough to read the text.
typedef struct { WS_USTR Name; }     OBJ_NAME_INFO;
typedef struct { WS_USTR TypeName; } OBJ_TYPE_INFO;

// Older tools skip every handle whose access is exactly 0x0012019F to dodge
// the blocking pipes - but that value is simply FILE_GENERIC_READ |
// FILE_GENERIC_WRITE, i.e. EVERY file opened for read+write, so the skip hid
// the names of ordinary files too. The timeout below protects us instead.
#define NAME_TIMEOUT_MS    200
#define MAX_STUCK          4

// One handle, independent of which information class produced it.
typedef struct {
    ULONG_PTR pid, value;
    ULONG access;
    USHORT type_index;
} hentry;

// Copies a UNICODE_STRING (already read into our buffer) to a UTF-8 C string.
static void ustr_to_utf8(const WS_USTR *us, char *out, size_t outsz)
{
    out[0] = '\0';
    if (us->Length == 0 || us->Buffer == NULL) {
        return;
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, us->Buffer, us->Length / (int)sizeof(WCHAR),
                                out, (int)outsz - 1, NULL, NULL);
    out[(n > 0) ? n : 0] = '\0';
}

// Fetch the whole system handle table, extended class first. Returns a
// malloc'd array (caller frees) and its length, or NULL.
static hentry *fetch_handles(NtQuerySystemInformation_t NtQSI, size_t *count, int *legacy)
{
    static const int classes[2] = { SystemExtendedHandleInformation, SystemHandleInformation };
    for (int c = 0; c < 2; c++) {
        // The table changes constantly, so grow the buffer while the kernel
        // answers STATUS_INFO_LENGTH_MISMATCH (with a ceiling).
        ULONG cap = 1u << 20;
        BYTE *buf = NULL;
        LONG st;
        for (;;) {
            BYTE *nb = (BYTE *)realloc(buf, cap);
            if (nb == NULL) { free(buf); return NULL; }
            buf = nb;
            ULONG need = 0;
            st = NtQSI(classes[c], buf, cap, &need);
            if (st != STATUS_INFO_LENGTH_MISMATCH) break;
            cap = (need > cap) ? need + (1u << 20) : cap * 2;
            if (cap > (512u << 20)) break;
        }
        if (st < 0) {
            free(buf);
            continue;
        }
        size_t n;
        hentry *out;
        if (classes[c] == SystemExtendedHandleInformation) {
            ULONG_PTR num;
            memcpy(&num, buf, sizeof num);
            const HANDLE_ENTRY_EX *e = (const HANDLE_ENTRY_EX *)(buf + 2 * sizeof(ULONG_PTR));
            n = (size_t)num;
            if ((size_t)(cap - 2 * sizeof(ULONG_PTR)) / sizeof *e < n) { free(buf); continue; }
            out = (hentry *)malloc((n ? n : 1) * sizeof *out);
            if (out == NULL) { free(buf); return NULL; }
            for (size_t i = 0; i < n; i++) {
                out[i].pid = e[i].UniqueProcessId;
                out[i].value = e[i].HandleValue;
                out[i].access = e[i].GrantedAccess;
                out[i].type_index = e[i].ObjectTypeIndex;
            }
        } else {
            ULONG num;
            memcpy(&num, buf, sizeof num);
            const HANDLE_ENTRY_LEGACY *e = (const HANDLE_ENTRY_LEGACY *)(buf + sizeof(ULONG_PTR));
            n = num;
            if ((size_t)(cap - sizeof(ULONG_PTR)) / sizeof *e < n) { free(buf); continue; }
            out = (hentry *)malloc((n ? n : 1) * sizeof *out);
            if (out == NULL) { free(buf); return NULL; }
            for (size_t i = 0; i < n; i++) {
                out[i].pid = e[i].UniqueProcessId;
                out[i].value = e[i].HandleValue;
                out[i].access = e[i].GrantedAccess;
                out[i].type_index = e[i].ObjectTypeIndex;
            }
        }
        free(buf);
        *count = n;
        *legacy = classes[c] == SystemHandleInformation;
        return out;
    }
    return NULL;
}

// --- name query with a timeout (File objects) ---------------------------------
// The worker owns its block: if it gets stuck we walk away and leak it (and the
// duplicated handle it uses) rather than free memory a blocked thread may still
// write to.
typedef struct {
    NtQueryObject_t fn;
    HANDLE h;
    LONG st;
    BYTE buf[2048];
} name_job;

static DWORD WINAPI name_worker(LPVOID p)
{
    name_job *j = (name_job *)p;
    j->st = j->fn(j->h, ObjectNameInformation, j->buf, sizeof j->buf, NULL);
    return 0;
}

typedef struct {
    NtQueryObject_t NtQO;
    unsigned stuck;         // abandoned workers so far
} resolver;

// Fills type and name for a duplicated handle. Returns 0 normally, or 1 when
// the name query was abandoned (dup must then NOT be closed).
static int describe_dup(resolver *r, HANDLE dup, char *type, size_t tn, char *name, size_t nn)
{
    BYTE tbuf[1024];
    if (r->NtQO(dup, ObjectTypeInformation, tbuf, sizeof tbuf, NULL) >= 0) {
        ustr_to_utf8(&((OBJ_TYPE_INFO *)tbuf)->TypeName, type, tn);
    }
    if (strcmp(type, "File") != 0) {
        BYTE nbuf[2048];
        if (r->NtQO(dup, ObjectNameInformation, nbuf, sizeof nbuf, NULL) >= 0) {
            ustr_to_utf8(&((OBJ_NAME_INFO *)nbuf)->Name, name, nn);
        }
        return 0;
    }
    if (r->stuck >= MAX_STUCK) {
        return 0;
    }
    name_job *j = (name_job *)malloc(sizeof *j);
    if (j == NULL) return 0;
    j->fn = r->NtQO;
    j->h = dup;
    j->st = -1;
    HANDLE th = CreateThread(NULL, 64 * 1024, name_worker, j, 0, NULL);
    if (th == NULL) {
        free(j);
        return 0;
    }
    if (WaitForSingleObject(th, NAME_TIMEOUT_MS) != WAIT_OBJECT_0) {
        CloseHandle(th);        // the thread keeps running; j and dup stay alive
        r->stuck++;
        return 1;
    }
    CloseHandle(th);
    if (j->st >= 0) {
        ustr_to_utf8(&((OBJ_NAME_INFO *)j->buf)->Name, name, nn);
    }
    free(j);
    return 0;
}

// The access mask, decoded for the handle's object type: the low 16 bits mean
// different things per type (0x10 is VM_READ on a process, SET_CONTEXT on a
// thread), so the type picks the table (rights.c, shared with secinfo and
// unit-tested). The raw hex is always printed too, so nothing is hidden.
static void print_access(const char *type, ULONG mask)
{
    char names[512];
    rights_decode(type, (uint32_t)mask, names, sizeof names);
    printf("0x%08lX (%s)", (unsigned long)mask, names);
}

static int contains_ci(const char *s, const char *needle)
{
    size_t n = strlen(needle);
    for (; *s; s++) {
        if (_strnicmp(s, needle, n) == 0) return 1;
    }
    return n == 0;
}

// --find: every process's handles whose object name contains the text.
static int find_mode(NtQueryObject_t NtQO, const hentry *h, size_t n, const char *needle,
                     const char *want_type, enum out_mode mode)
{
    resolver r = { NtQO, 0 };
    if (mode == OUT_TEXT) {
        printf("handles --find \"%s\"%s%s\n\n", needle, want_type ? "  type " : "",
               want_type ? want_type : "");
        printf("  %-7s %-22s %-10s %-12s %s\n", "pid", "process", "handle", "type", "name");
    } else if (mode == OUT_CSV) {
        puts("pid,process,handle,type,access,name");
    } else {
        putchar('[');
    }
    unsigned hits = 0, denied = 0;
    ULONG_PTR cur = (ULONG_PTR)-1;
    HANDLE proc = NULL;
    char pname[MAX_PATH] = "";
    DWORD self = GetCurrentProcessId();
    for (size_t i = 0; i < n; i++) {
        if (h[i].pid != cur) {
            if (proc != NULL) CloseHandle(proc);
            cur = h[i].pid;
            proc = NULL;
            pname[0] = '\0';
            if (cur == self || cur == 0 || cur == 4) continue;
            proc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               (DWORD)cur);
            if (proc == NULL) {
                denied++;
                continue;
            }
            WCHAR wp[MAX_PATH];
            DWORD wl = MAX_PATH;
            if (QueryFullProcessImageNameW(proc, 0, wp, &wl)) {
                const WCHAR *b = wcsrchr(wp, L'\\');
                WideCharToMultiByte(CP_UTF8, 0, b ? b + 1 : wp, -1, pname, sizeof pname, NULL, NULL);
            }
        }
        if (proc == NULL) continue;
        HANDLE dup = NULL;
        if (!DuplicateHandle(proc, (HANDLE)h[i].value, GetCurrentProcess(), &dup, 0, FALSE,
                             DUPLICATE_SAME_ACCESS)) {
            continue;
        }
        char type[64] = "", name[1024] = "";
        int abandoned = describe_dup(&r, dup, type, sizeof type, name, sizeof name);
        if (!abandoned) CloseHandle(dup);
        if (name[0] == '\0' || !contains_ci(name, needle)) continue;
        if (want_type != NULL && _stricmp(type, want_type) != 0) continue;
        if (mode == OUT_TEXT) {
            printf("  %-7lu %-22s 0x%-8lX %-12s %s\n", (unsigned long)cur, pname,
                   (unsigned long)h[i].value, type, name);
        } else if (mode == OUT_CSV) {
            printf("%lu,", (unsigned long)cur);
            csv_str(pname);
            printf(",0x%lX,", (unsigned long)h[i].value);
            csv_str(type);
            printf(",0x%08lX,", (unsigned long)h[i].access);
            csv_str(name);
            putchar('\n');
        } else {
            printf("%s{\"pid\":%lu,\"process\":", hits ? "," : "", (unsigned long)cur);
            json_str(pname);
            printf(",\"handle\":\"0x%lX\",\"type\":", (unsigned long)h[i].value);
            json_str(type);
            printf(",\"access\":\"0x%08lX\",\"name\":", (unsigned long)h[i].access);
            json_str(name);
            putchar('}');
        }
        hits++;
    }
    if (proc != NULL) CloseHandle(proc);
    if (mode == OUT_JSON) {
        puts("]");
    } else if (mode == OUT_TEXT) {
        printf("\n%u match(es)", hits);
        if (denied) printf(", %u process(es) not openable (run elevated to search them)", denied);
        if (r.stuck) printf(", %u file name(s) timed out", r.stuck);
        putchar('\n');
    }
    return 0;
}

int cmd_handles(int argc, char **argv)
{
    // Args: <pid> | --find <text> [--type <T>], plus --json / --csv.
    const char *pid_arg = NULL, *find = NULL, *want_type = NULL;
    enum out_mode mode = OUT_TEXT;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = OUT_JSON;
        else if (strcmp(argv[a], "--csv") == 0)  mode = OUT_CSV;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc)  find = argv[++a];
        else if (strcmp(argv[a], "--type") == 0 && a + 1 < argc)  want_type = argv[++a];
        else if (pid_arg == NULL)                pid_arg = argv[a];
        else {
            fprintf(stderr, "handles: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    unsigned long pid = 0;
    if (find == NULL) {
        if (pid_arg == NULL) {
            fputs("usage: winspect handles <pid> | --find <text> [--type <T>] [--json | --csv]\n", stderr);
            return 1;
        }
        char *end = NULL;
        pid = strtoul(pid_arg, &end, 10);
        if (end == pid_arg || *end != '\0' || pid == 0) {
            fprintf(stderr, "handles: '%s' is not a valid pid\n", pid_arg);
            return 1;
        }
    } else if (pid_arg != NULL) {
        fprintf(stderr, "handles: give either a pid or --find, not both\n");
        return 1;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    // Cast FARPROC to our type through the generic function pointer
    // void(*)(void): going through void* trips -Wpedantic (object<->function)
    // and a direct cast trips -Wcast-function-type (signatures differ), but
    // the generic-function-pointer hop keeps both quiet. (Same idiom as threads.c.)
    NtQuerySystemInformation_t NtQSI = ntdll ? (NtQuerySystemInformation_t)(void(*)(void))
            GetProcAddress(ntdll, "NtQuerySystemInformation") : NULL;
    NtQueryObject_t NtQO = ntdll ? (NtQueryObject_t)(void(*)(void))
            GetProcAddress(ntdll, "NtQueryObject") : NULL;
    if (NtQSI == NULL || NtQO == NULL) {
        fputs("handles: NtQuerySystemInformation / NtQueryObject not available\n", stderr);
        return 1;
    }

    size_t n = 0;
    int legacy = 0;
    hentry *h = fetch_handles(NtQSI, &n, &legacy);
    if (h == NULL) {
        fputs("handles: cannot read the system handle table\n", stderr);
        return 1;
    }
    if (find != NULL) {
        int rc = find_mode(NtQO, h, n, find, want_type, mode);
        free(h);
        return rc;
    }

    // To turn a handle value into a type/name we must bring the handle into OUR
    // process with DuplicateHandle, which needs PROCESS_DUP_HANDLE on the target.
    // If we can't get it (access denied), we still print the raw type index.
    HANDLE htgt = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pid);
    resolver r = { NtQO, 0 };
    // The legacy table only has the low 16 bits of the PID.
    ULONG_PTR want = legacy ? (ULONG_PTR)(USHORT)pid : (ULONG_PTR)pid;

    if (mode == OUT_TEXT) {
        printf("process  pid %lu%s\n\n", pid,
               htgt ? "" : "  (no DUP_HANDLE access: type/name unavailable, showing index)");
        printf("  %-8s  %-16s  %-28s  %s\n", "handle", "type", "granted access", "name");
    } else if (mode == OUT_CSV) {
        puts("handle,type,access,name,target_pid,injectable,access_names");
    } else {
        putchar('[');
    }

    unsigned count = 0;
    for (size_t i = 0; i < n; i++) {
        const hentry *e = &h[i];
        if (e->pid != want) {
            continue;
        }

        char type[64];
        char name[1024];
        snprintf(type, sizeof type, "#%u", e->type_index);   // fallback
        name[0] = '\0';

        // Cross-process reach: a handle to ANOTHER process/thread that carries
        // write/execute-control access is the capability behind code injection
        // (CreateRemoteThread, WriteProcessMemory, SetThreadContext). We resolve
        // the target id and flag it; a handle to the process's own self is normal
        // and left unflagged.
        int injectable = 0;
        DWORD target_pid = 0;

        if (htgt != NULL) {
            HANDLE dup = NULL;
            if (DuplicateHandle(htgt, (HANDLE)e->value, GetCurrentProcess(), &dup, 0, FALSE,
                                DUPLICATE_SAME_ACCESS)) {
                int abandoned = describe_dup(&r, dup, type, sizeof type, name, sizeof name);
                if (strcmp(type, "Process") == 0) {
                    const ULONG inj = PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                      PROCESS_CREATE_THREAD;
                    target_pid = GetProcessId(dup);     // 0 if not queryable
                    if ((e->access & inj) && target_pid != (DWORD)pid) {
                        injectable = 1;
                    }
                } else if (strcmp(type, "Thread") == 0) {
                    const ULONG inj = THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME;
                    target_pid = GetProcessIdOfThread(dup);
                    if ((e->access & inj) && target_pid != (DWORD)pid) {
                        injectable = 1;
                    }
                }
                if (!abandoned) CloseHandle(dup);
            }
        }

        if (mode == OUT_TEXT) {
            printf("  0x%04lX    %-16s  ", (unsigned long)e->value, type);
            print_access(type, e->access);
            printf("  %s", name);
            if (injectable) {
                printf("  [INJECTABLE -> pid %lu]", (unsigned long)target_pid);
            }
            putchar('\n');
        } else if (mode == OUT_CSV) {
            printf("0x%04lX,", (unsigned long)e->value);
            csv_str(type);
            printf(",0x%08lX,", (unsigned long)e->access);
            csv_str(name);
            char names[512];
            rights_decode(type, (uint32_t)e->access, names, sizeof names);
            printf(",%lu,%d,", (unsigned long)target_pid, injectable ? 1 : 0);
            csv_str(names);
            putchar('\n');
        } else {
            printf("%s{\"handle\":\"0x%04lX\",\"type\":", count ? "," : "", (unsigned long)e->value);
            json_str(type);
            char names[512];
            rights_decode(type, (uint32_t)e->access, names, sizeof names);
            printf(",\"access\":\"0x%08lX\",\"access_names\":", (unsigned long)e->access);
            json_str(names);
            fputs(",\"name\":", stdout);
            json_str(name);
            if (target_pid != 0) {
                printf(",\"target_pid\":%lu", (unsigned long)target_pid);
            } else {
                fputs(",\"target_pid\":null", stdout);
            }
            printf(",\"injectable\":%s}", injectable ? "true" : "false");
        }
        count++;
    }

    if (htgt != NULL) {
        CloseHandle(htgt);
    }
    free(h);

    if (mode == OUT_TEXT) {
        printf("\n%u handles%s\n", count, r.stuck ? " (some file names timed out)" : "");
    } else if (mode == OUT_JSON) {
        puts("]");
    }
    return 0;
}
