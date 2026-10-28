// winspect hunt - process lineage and masquerade checks ("Hunt Evil")
//
// A healthy Windows box has a very regular process family tree:
//   System -> smss.exe -> (csrss.exe, wininit.exe, winlogon.exe)
//   wininit.exe -> services.exe, lsass.exe (, lsaiso.exe)
//   services.exe -> svchost.exe (always with "-k <group>"), spoolsv.exe, ...
// Malware that names itself "svchost.exe" or "lsass.exe" to blend in usually
// breaks one of these facts: wrong parent, wrong folder, a second copy of a
// process that must be unique, a svchost without its "-k" group, a core
// process not running as SYSTEM, or a boot-time process (lsass, services,
// wininit) that started long after boot - i.e. not the original. The SANS
// "Hunt Evil" poster teaches exactly these checks; the rule table lives in the
// portable artparse.c (unit-tested), this file gathers the live facts.
//
// Parent resolution is careful about PID reuse: a "parent" only counts if it
// was created BEFORE the child (otherwise the real parent exited and its PID
// was recycled). Unknown/exited parents are never reported as wrong.
//
// Read-only: Toolhelp snapshot, PROCESS_QUERY_LIMITED_INFORMATION opens.

#include "hunt.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HUNT_MAX 8192

typedef struct {
    DWORD pid, ppid;
    char name[260];
    char path[1024];
    char cmdline[1024];
    char sid[96];           // token user SID ("S-1-5-18"), "" if unreadable
    ULONGLONG created;      // FILETIME as integer, 0 if unknown
    int parent;             // index of the real parent, -1 if exited/unknown
} hproc;

static hproc g[HUNT_MAX];

// ProcessCommandLineInformation (60), Windows 8.1+: the command line without
// reading the target's memory.
typedef LONG (NTAPI *NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static void query(hproc *p, NtQIP_t ntqip)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p->pid);
    if (h == NULL) {
        return;
    }
    FILETIME c, e, k, u;
    if (GetProcessTimes(h, &c, &e, &k, &u)) {
        p->created = ((ULONGLONG)c.dwHighDateTime << 32) | c.dwLowDateTime;
    }
    WCHAR wpath[1024];
    DWORD n = 1024;
    if (QueryFullProcessImageNameW(h, 0, wpath, &n)) {
        WideCharToMultiByte(CP_UTF8, 0, wpath, -1, p->path, sizeof p->path, NULL, NULL);
    }
    // Token user: who the process runs as. Protected processes (lsass as PPL)
    // may refuse TOKEN_QUERY; then the SID stays empty and is never judged.
    HANDLE tok = NULL;
    if (OpenProcessToken(h, TOKEN_QUERY, &tok)) {
        BYTE tu[256];
        DWORD tl = 0;
        char *ss = NULL;
        if (GetTokenInformation(tok, TokenUser, tu, sizeof tu, &tl) &&
                ConvertSidToStringSidA(((TOKEN_USER *)tu)->User.Sid, &ss)) {
            snprintf(p->sid, sizeof p->sid, "%s", ss);
            LocalFree(ss);
        }
        CloseHandle(tok);
    }
    if (ntqip != NULL) {
        BYTE buf[4096];
        ULONG ret = 0;
        if (ntqip(h, 60, buf, sizeof buf, &ret) >= 0) {
            // Result is a UNICODE_STRING followed by its buffer. Copy the
            // fields out with memcpy: buf has no alignment guarantee.
            USHORT len;
            WCHAR *s;
            memcpy(&len, buf, sizeof len);
            memcpy(&s, buf + sizeof(void *), sizeof s);
            if (s != NULL && len > 0 && len < sizeof buf) {
                int got = WideCharToMultiByte(CP_UTF8, 0, s, len / 2, p->cmdline,
                                              sizeof p->cmdline - 1, NULL, NULL);
                p->cmdline[got > 0 ? got : 0] = '\0';
            }
        }
    }
    CloseHandle(h);
}

// Case-insensitive "path starts with dir\".
static int under_dir(const char *path, const char *dir)
{
    size_t n = strlen(dir);
    return _strnicmp(path, dir, n) == 0 && (path[n] == '\\' || path[n] == '/');
}

typedef struct {
    int mode, all, first;
    unsigned findings;
} hctx;

static void out_row(hctx *c, const hproc *p, const char *parent, const char *finding)
{
    if (c->mode == 0) {
        printf("  %s%-22s pid %-6lu parent %-22s %s\n", finding ? "[!] " : "    ", p->name,
               (unsigned long)p->pid, parent, p->path[0] ? p->path : "(path unavailable)");
        if (finding) {
            printf("        <- %s\n", finding);
        }
    } else if (c->mode == 2) {
        printf("%lu,%lu,", (unsigned long)p->pid, (unsigned long)p->ppid);
        csv_str(p->name);  putchar(',');
        csv_str(parent);   putchar(',');
        csv_str(p->path);  putchar(',');
        csv_str(finding ? finding : ""); putchar('\n');
    } else {
        printf("%s{\"pid\":%lu,\"ppid\":%lu,\"name\":", c->first ? "" : ",",
               (unsigned long)p->pid, (unsigned long)p->ppid);
        json_str(p->name);
        fputs(",\"parent\":", stdout);  json_str(parent);
        fputs(",\"path\":", stdout);    json_str(p->path);
        fputs(",\"command_line\":", stdout); json_str(p->cmdline);
        fputs(",\"user_sid\":", stdout); json_str(p->sid);
        printf(",\"suspicious\":%s,\"finding\":", finding ? "true" : "false");
        json_str(finding ? finding : "");
        putchar('}');
        c->first = 0;
    }
}

static void report(hctx *c, const hproc *p, const char *parent, const char *finding)
{
    if (finding) c->findings++;
    if (finding || c->all) out_row(c, p, parent, finding);
}

int cmd_hunt(int argc, char **argv)
{
    hctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "--all") == 0)  c.all = 1;
        else {
            fprintf(stderr, "hunt: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "hunt: CreateToolhelp32Snapshot failed (error %lu)\n",
                (unsigned long)GetLastError());
        return 1;
    }
    NtQIP_t ntqip = (NtQIP_t)(void (*)(void))GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                            "NtQueryInformationProcess");
    int n = 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (n >= HUNT_MAX) break;
            hproc *p = &g[n++];
            memset(p, 0, sizeof *p);
            p->pid = pe.th32ProcessID;
            p->ppid = pe.th32ParentProcessID;
            p->parent = -1;
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, p->name, sizeof p->name, NULL, NULL);
            if (p->pid != 0 && p->pid != 4) {
                query(p, ntqip);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    // Resolve real parents (guarding against PID reuse via creation time).
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if (j == i || g[j].pid != g[i].ppid) continue;
            if (g[i].created && g[j].created && g[j].created > g[i].created) break;   // reused PID
            g[i].parent = j;
            break;
        }
    }

    // Boot time as a FILETIME: now minus the uptime.
    FILETIME nowft;
    GetSystemTimeAsFileTime(&nowft);
    ULONGLONG now = ((ULONGLONG)nowft.dwHighDateTime << 32) | nowft.dwLowDateTime;
    ULONGLONG boot = now - GetTickCount64() * 10000ULL;

    char sys32[MAX_PATH] = "", syswow[MAX_PATH] = "";
    GetSystemDirectoryA(sys32, MAX_PATH);
    GetSystemWow64DirectoryA(syswow, MAX_PATH);     // empty on 32-bit Windows

    if (c.mode == 0) {
        puts("hunt  (process lineage + masquerade checks)\n");
    } else if (c.mode == 2) {
        puts("pid,ppid,name,parent,path,finding");
    } else {
        putchar('[');
    }

    for (int i = 0; i < n; i++) {
        hproc *p = &g[i];
        const char *parent = p->parent >= 0 ? g[p->parent].name : "(exited)";
        if (p->pid == 4 || p->pid == 0) {
            if (c.all) report(&c, p, "-", NULL);
            continue;
        }
        char finding[512];
        finding[0] = '\0';

        int ok = lineage_parent_ok(p->name, p->parent >= 0 ? g[p->parent].name : NULL);
        if (ok == 0) {
            snprintf(finding, sizeof finding, "unexpected parent %s for %s", parent, p->name);
        }
        if (finding[0] == '\0' && lineage_singleton(p->name)) {
            int copies = 0;
            for (int j = 0; j < n; j++) {
                if (_stricmp(g[j].name, p->name) == 0) copies++;
            }
            if (copies > 1) {
                snprintf(finding, sizeof finding, "%d instances of %s (must be unique)", copies, p->name);
            }
        }
        if (finding[0] == '\0' && lineage_system32_only(p->name) && p->path[0] &&
                !under_dir(p->path, sys32) && !(syswow[0] && under_dir(p->path, syswow))) {
            snprintf(finding, sizeof finding, "core Windows name running outside System32");
        }
        if (finding[0] == '\0' && _stricmp(p->name, "svchost.exe") == 0 && p->cmdline[0] &&
                strstr(p->cmdline, "-k") == NULL) {
            snprintf(finding, sizeof finding, "svchost.exe without a -k service group");
        }
        if (finding[0] == '\0' && p->sid[0] && lineage_system_account(p->name) &&
                strcmp(p->sid, "S-1-5-18") != 0) {
            snprintf(finding, sizeof finding, "%s runs as %s, expected SYSTEM (S-1-5-18)",
                     p->name, p->sid);
        }
        if (finding[0] == '\0' && p->created > boot &&
                lineage_started_late(p->name, (p->created - boot) / 10000000ULL)) {
            snprintf(finding, sizeof finding, "%s started %llu min after boot (boot-time process)",
                     p->name, (unsigned long long)((p->created - boot) / 10000000ULL / 60));
        }
        report(&c, p, parent, finding[0] ? finding : NULL);
    }

    if (c.mode == 0) {
        printf("\n%d process(es) checked, %u finding(s)%s\n", n, c.findings,
               c.all ? "" : "  (use --all to list every process)");
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
