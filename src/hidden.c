// winspect hidden - cross-view detection ("the same truth from two sources")
//
// Rootkit-style hiding usually works by lying in ONE place: a hooked
// enumeration API, a service whose security descriptor makes the SCM skip it.
// Reading the same facts through an independent path exposes the lie - the
// idea behind GMER, Unhide and Sysinternals RootkitRevealer. Two views here:
//
// 1) Processes. Three independent lists:
//      A  Toolhelp snapshot (what Task Manager-style tools use)
//      B  NtQuerySystemInformation(SystemProcessInformation) (the native list)
//      C  brute force: OpenProcess on every multiple of 4 up to 65536 and keep
//         the ones that open AND are still running
//    A PID in C (or B) but missing from A is reported. Because processes
//    start and stop all the time, every candidate is re-checked against a
//    fresh snapshot before it is printed (a brand-new process is not hidden).
//
// 2) Services. Every Win32 service / driver key under
//      HKLM\SYSTEM\CurrentControlSet\Services
//    is compared with what EnumServicesStatusEx returns. A key that the SCM
//    does not list while OpenService on it fails with access denied is the
//    signature of a service hidden with a restrictive SDDL (public research,
//    MITRE T1564). A key the SCM does not know at all was written straight
//    into the registry (it activates at the next boot) - also reported.
//    Keys without a Type/ImagePath are skipped (not real services).
//
// Read-only: snapshots, PROCESS_QUERY_LIMITED_INFORMATION opens, registry
// reads and SCM enumeration only.

#include "hidden.h"
#include "jsonutil.h"

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXPID 65536

typedef LONG (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

// Bitmaps of PIDs seen by each view (PIDs are multiples of 4).
static unsigned char seen_th[MAXPID / 32], seen_nt[MAXPID / 32];

static void setbit(unsigned char *b, DWORD pid) { if (pid < MAXPID) b[pid / 32] |= (unsigned char)(1u << ((pid / 4) % 8)); }
static int  getbit(const unsigned char *b, DWORD pid) { return pid < MAXPID && (b[pid / 32] >> ((pid / 4) % 8)) & 1; }

static void view_toolhelp(void)
{
    memset(seen_th, 0, sizeof seen_th);
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof pe;
    if (Process32FirstW(s, &pe)) {
        do { setbit(seen_th, pe.th32ProcessID); } while (Process32NextW(s, &pe));
    }
    CloseHandle(s);
}

static int view_native(void)
{
    memset(seen_nt, 0, sizeof seen_nt);
    NtQSI_t q = (NtQSI_t)(void (*)(void))GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                        "NtQuerySystemInformation");
    if (q == NULL) return 0;
    ULONG size = 1 << 20;
    BYTE *buf = NULL;
    LONG st;
    for (int tries = 0; tries < 6; tries++) {
        free(buf);
        buf = (BYTE *)malloc(size);
        if (buf == NULL) return 0;
        ULONG need = 0;
        st = q(5 /* SystemProcessInformation */, buf, size, &need);
        if (st >= 0) break;
        size = (need > size ? need : size) * 2;
    }
    if (st < 0) { free(buf); return 0; }
    // Walk the variable-length records; NextEntryOffset is at offset 0 and
    // UniqueProcessId sits after the fixed header (winternl's layout).
    SYSTEM_PROCESS_INFORMATION *p = (SYSTEM_PROCESS_INFORMATION *)buf;
    for (;;) {
        setbit(seen_nt, (DWORD)(ULONG_PTR)p->UniqueProcessId);
        if (p->NextEntryOffset == 0) break;
        p = (SYSTEM_PROCESS_INFORMATION *)((BYTE *)p + p->NextEntryOffset);
    }
    free(buf);
    return 1;
}

// Is this PID a live process we can open (exit code still STILL_ACTIVE)?
static int alive(DWORD pid, char *path, size_t n)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == NULL) return 0;
    DWORD code = 0;
    int ok = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    if (ok && path != NULL) {
        WCHAR w[1024];
        DWORD wl = 1024;
        path[0] = '\0';
        if (QueryFullProcessImageNameW(h, 0, w, &wl)) {
            WideCharToMultiByte(CP_UTF8, 0, w, -1, path, (int)n, NULL, NULL);
        }
    }
    CloseHandle(h);
    return ok;
}

typedef struct { int mode, first; unsigned findings; } hctx;

static void row(hctx *c, const char *kind, const char *id, const char *detail, const char *why)
{
    c->findings++;
    if (c->mode == 0) {
        printf("  [!] %-8s %-28s %s\n        <- %s\n", kind, id, detail, why);
    } else if (c->mode == 2) {
        csv_str(kind); putchar(','); csv_str(id); putchar(',');
        csv_str(detail); putchar(','); csv_str(why); putchar('\n');
    } else {
        printf("%s{\"kind\":", c->first ? "" : ",");
        json_str(kind);
        fputs(",\"id\":", stdout);     json_str(id);
        fputs(",\"detail\":", stdout); json_str(detail);
        fputs(",\"reason\":", stdout); json_str(why);
        putchar('}');
        c->first = 0;
    }
}

static void check_processes(hctx *c)
{
    view_toolhelp();
    int have_nt = view_native();
    for (DWORD pid = 8; pid < MAXPID; pid += 4) {
        int in_th = getbit(seen_th, pid), in_nt = have_nt && getbit(seen_nt, pid);
        if (in_th) continue;
        char path[1024] = "";
        int open_ok = alive(pid, path, sizeof path);
        if (!open_ok && !in_nt) continue;
        // Re-check with fresh views: a process that just started is not hidden.
        view_toolhelp();
        if (getbit(seen_th, pid)) continue;
        if (!alive(pid, NULL, 0) && !(view_native() && getbit(seen_nt, pid))) continue;
        char id[32];
        snprintf(id, sizeof id, "pid %lu", (unsigned long)pid);
        row(c, "process", id, path[0] ? path : "(image path unavailable)",
            in_nt ? "in the native process list but missing from the Toolhelp snapshot"
                  : "opens directly but is missing from the Toolhelp snapshot");
    }
}

// Is service `name` in the SCM's list? (linear search: a few hundred names)
static int scm_has(const ENUM_SERVICE_STATUS_PROCESSW *v, DWORD n, const WCHAR *name)
{
    for (DWORD i = 0; i < n; i++) {
        if (_wcsicmp(v[i].lpServiceName, name) == 0) return 1;
    }
    return 0;
}

static void check_services(hctx *c)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == NULL) {
        fputs("hidden: cannot open the Service Control Manager\n", stderr);
        return;
    }
    DWORD bytes = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
                          SERVICE_STATE_ALL, NULL, 0, &bytes, &count, &resume, NULL);
    BYTE *buf = bytes ? (BYTE *)malloc(bytes + 4096) : NULL;
    resume = 0;
    if (buf == NULL || !EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO,
                                              SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                                              buf, bytes + 4096, &bytes, &count, &resume, NULL)) {
        free(buf);
        CloseServiceHandle(scm);
        fputs("hidden: cannot enumerate services\n", stderr);
        return;
    }
    const ENUM_SERVICE_STATUS_PROCESSW *list = (const ENUM_SERVICE_STATUS_PROCESSW *)buf;

    HKEY root;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ, &root) == ERROR_SUCCESS) {
        for (DWORD i = 0;; i++) {
            WCHAR name[256];
            DWORD nl = 256;
            if (RegEnumKeyExW(root, i, name, &nl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            // Only real services: a Type DWORD for a Win32 service/driver and an ImagePath.
            DWORD type = 0, tl = sizeof type;
            WCHAR img[1024];
            DWORD il = sizeof img;
            if (RegGetValueW(root, name, L"Type", RRF_RT_REG_DWORD, NULL, &type, &tl) != ERROR_SUCCESS) continue;
            if (!(type & (SERVICE_WIN32 | SERVICE_DRIVER))) continue;
            if (RegGetValueW(root, name, L"ImagePath", RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                             NULL, img, &il) != ERROR_SUCCESS) continue;
            if (scm_has(list, count, name)) continue;
            // Not listed. Distinguish "hidden by its SD" from "just registered".
            SC_HANDLE s = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
            DWORD err = s ? 0 : GetLastError();
            if (s) CloseServiceHandle(s);
            char u8n[512], u8i[2048];
            WideCharToMultiByte(CP_UTF8, 0, name, -1, u8n, sizeof u8n, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, img, -1, u8i, sizeof u8i, NULL, NULL);
            row(c, "service", u8n, u8i,
                err == ERROR_ACCESS_DENIED
                    ? "registered service the SCM does not list and refuses to open (restrictive SDDL?)"
                : err == ERROR_SERVICE_DOES_NOT_EXIST
                    ? "service key written straight into the registry - SCM does not know it yet (activates at next boot)"
                    : "registered service missing from the SCM enumeration");
        }
        RegCloseKey(root);
    }
    free(buf);
    CloseServiceHandle(scm);
}

int cmd_hidden(int argc, char **argv)
{
    hctx c = { 0, 1, 0 };
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else {
            fprintf(stderr, "hidden: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (c.mode == 0) {
        puts("hidden  (cross-view: processes and services)\n");
    } else if (c.mode == 2) {
        puts("kind,id,detail,reason");
    } else {
        putchar('[');
    }
    check_processes(&c);
    check_services(&c);
    if (c.mode == 0) {
        printf("%s%u finding(s)%s\n", c.findings ? "\n" : "", c.findings,
               c.findings ? "" : " - the views agree");
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
