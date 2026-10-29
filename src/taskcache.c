// winspect taskcache - hidden scheduled task detection via TaskCache\Tree
//
// The Task Scheduler keeps a registry cache of every task:
//   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<folder...>\<task>
// Each task key holds Id (the task's GUID), Index and SD (the task's security
// descriptor). The task definition itself is an XML file under
// %SystemRoot%\System32\Tasks\<folder...>\<task>.
//
// Ways a task can exist yet stay invisible to schtasks / the Task Scheduler UI
// (public research: Microsoft's "Tarrask" write-up, Binary Defense ARC Labs):
//   1. SD value deleted   - the tools cannot read the task, so they skip it.
//                           Microsoft's hunt: "Tree tasks without an SD value".
//   2. SD with deny ACEs  - a valid SD that denies read access hides the task
//                           just as well while passing check 1.
//   3. no XML file        - a task written straight into the registry (not via
//                           the Task Scheduler API) leaves no file and no
//                           creation event.
// We walk the Tree, check all three and say which one fired. Real admin
// tooling rarely produces any of them, so a hit is worth a close look - still
// a hint, not a verdict.
//
// Read-only: KEY_READ on the cache, GetFileAttributes on the XML path. The
// cache is normally readable only by administrators; we say so if denied.

#include "taskcache.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TREE_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"

typedef struct {
    int mode;
    int only_flagged;
    int first;
    unsigned tasks, flagged;
    WCHAR tasks_dir[MAX_PATH];
} tc_ctx;

static void w2u(const WCHAR *w, char *out, size_t n)
{
    if (WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)n, NULL, NULL) <= 0) {
        out[0] = '\0';
    }
}

// 1 if the self-relative SD's DACL contains any ACCESS_DENIED ACE.
static int sd_has_deny(const BYTE *sd, DWORD len)
{
    if (len < sizeof(SECURITY_DESCRIPTOR_RELATIVE) ||
            !IsValidSecurityDescriptor((PSECURITY_DESCRIPTOR)sd)) {
        return 0;
    }
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = NULL;
    if (!GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)sd, &present, &dacl, &defaulted) ||
            !present || dacl == NULL) {
        return 0;
    }
    for (DWORD i = 0; i < dacl->AceCount; i++) {
        ACE_HEADER *ace = NULL;
        if (GetAce(dacl, i, (LPVOID *)&ace) && ace->AceType == ACCESS_DENIED_ACE_TYPE) {
            return 1;
        }
    }
    return 0;
}

static void report(tc_ctx *c, const char *path, const char *id, int has_sd, int deny,
                   int has_xml)
{
    const char *reason = NULL;
    if (!has_sd)        reason = "no SD value - hidden from schtasks (Tarrask technique)";
    else if (deny)      reason = "SD contains deny ACEs - may hide the task from tools";
    else if (!has_xml)  reason = "no XML file in System32\\Tasks - registry-only task";
    c->tasks++;
    if (reason) { c->flagged++; }
    if (c->only_flagged && reason == NULL) {
        return;
    }
    if (c->mode == 0) {
        printf("  %s%-60s %s\n", reason ? "[!] " : "    ", path, id);
        if (reason) {
            printf("        <- %s\n", reason);
        }
    } else if (c->mode == 2) {
        csv_str(path); putchar(',');
        csv_str(id);
        printf(",%s,%s,%s,", has_sd ? "true" : "false", deny ? "true" : "false",
               has_xml ? "true" : "false");
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"task\":", c->first ? "" : ",");
        json_str(path);
        fputs(",\"id\":", stdout); json_str(id);
        printf(",\"has_sd\":%s,\"sd_deny_ace\":%s,\"has_xml\":%s,\"suspicious\":%s,\"reason\":",
               has_sd ? "true" : "false", deny ? "true" : "false", has_xml ? "true" : "false",
               reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

// Recursively walk one Tree key. rel is the task path relative to the Tree
// root ("" at the top, "\Microsoft\Windows\..." below).
static void walk(tc_ctx *c, HKEY key, const WCHAR *rel, int depth)
{
    if (depth > 32) {
        return;     // defensive bound: real trees are a few levels deep
    }
    // A key with an Id value is a task; folders have no Id.
    WCHAR id[64];
    DWORD idlen = sizeof id;
    if (RegGetValueW(key, NULL, L"Id", RRF_RT_REG_SZ, NULL, id, &idlen) == ERROR_SUCCESS) {
        BYTE sd[8192];
        DWORD sdlen = sizeof sd;
        LONG r = RegQueryValueExW(key, L"SD", NULL, NULL, sd, &sdlen);
        int has_sd = (r == ERROR_SUCCESS || r == ERROR_MORE_DATA);
        int deny = (r == ERROR_SUCCESS) && sd_has_deny(sd, sdlen);

        WCHAR xml[MAX_PATH * 2];
        _snwprintf(xml, MAX_PATH * 2, L"%ls%ls", c->tasks_dir, rel);
        xml[MAX_PATH * 2 - 1] = 0;
        int has_xml = GetFileAttributesW(xml) != INVALID_FILE_ATTRIBUTES;

        char path[1024], ids[128];
        w2u(rel, path, sizeof path);
        w2u(id, ids, sizeof ids);
        report(c, path, ids, has_sd, deny, has_xml);
    }

    for (DWORD i = 0;; i++) {
        WCHAR sub[256];
        DWORD sl = 256;
        if (RegEnumKeyExW(key, i, sub, &sl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        HKEY sk;
        if (RegOpenKeyExW(key, sub, 0, KEY_READ, &sk) != ERROR_SUCCESS) {
            continue;
        }
        WCHAR childrel[1024];
        _snwprintf(childrel, 1024, L"%ls\\%ls", rel, sub);
        childrel[1023] = 0;
        walk(c, sk, childrel, depth + 1);
        RegCloseKey(sk);
    }
}

int cmd_taskcache(int argc, char **argv)
{
    tc_ctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)         c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)     c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0) c.only_flagged = 1;
        else {
            fprintf(stderr, "taskcache: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    UINT wl = GetSystemDirectoryW(c.tasks_dir, MAX_PATH);
    if (wl == 0 || wl >= MAX_PATH - 8) {
        fputs("taskcache: cannot resolve the system directory\n", stderr);
        return 1;
    }
    wcscat(c.tasks_dir, L"\\Tasks");

    HKEY root;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TREE_KEY, 0, KEY_READ | KEY_WOW64_64KEY, &root);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "taskcache: cannot open TaskCache\\Tree%s\n",
                rc == ERROR_ACCESS_DENIED ? " (access denied - run elevated)" : "");
        return 1;
    }

    if (c.mode == 0) {
        puts("taskcache (TaskCache\\Tree, checked for hidden tasks)\n");
    } else if (c.mode == 2) {
        puts("task,id,has_sd,sd_deny_ace,has_xml,reason");
    } else {
        putchar('[');
    }
    walk(&c, root, L"", 0);
    RegCloseKey(root);

    if (c.mode == 0) {
        printf("\n%u task(s), %u flagged as possibly hidden\n", c.tasks, c.flagged);
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
