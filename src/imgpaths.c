// Locating the evidence of an offline Windows installation (see imgpaths.h).

#include "imgpaths.h"

#include <stdio.h>
#include <string.h>

static int is_file(const char *p)
{
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static int is_dir(const char *p)
{
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

// out = root + rel when it exists (as a file or a folder), else "".
static void at(const img_paths *p, char *out, size_t n, const char *rel, int dir)
{
    snprintf(out, n, "%s\\%s", p->root, rel);
    if (!(dir ? is_dir(out) : is_file(out))) out[0] = 0;
}

int img_find(const char *root, img_paths *p)
{
    memset(p, 0, sizeof *p);
    snprintf(p->root, sizeof p->root, "%s", root);
    size_t rl = strlen(p->root);
    while (rl > 0 && (p->root[rl - 1] == '\\' || p->root[rl - 1] == '/')) p->root[--rl] = 0;
    at(p, p->system, sizeof p->system, "Windows\\System32\\config\\SYSTEM", 0);
    at(p, p->software, sizeof p->software, "Windows\\System32\\config\\SOFTWARE", 0);
    at(p, p->sam, sizeof p->sam, "Windows\\System32\\config\\SAM", 0);
    at(p, p->amcache, sizeof p->amcache, "Windows\\AppCompat\\Programs\\Amcache.hve", 0);
    at(p, p->prefetch, sizeof p->prefetch, "Windows\\Prefetch", 1);
    at(p, p->tasks, sizeof p->tasks, "Windows\\System32\\Tasks", 1);
    at(p, p->recycle, sizeof p->recycle, "$Recycle.Bin", 1);
    at(p, p->pca, sizeof p->pca, "Windows\\appcompat\\pca", 1);
    at(p, p->srum, sizeof p->srum, "Windows\\System32\\sru\\SRUDB.dat", 0);
    static const char *const logs[IMG_MAX_LOGS] = {
        "System.evtx", "Security.evtx", "Microsoft-Windows-Windows Defender%4Operational.evtx",
        "Microsoft-Windows-TaskScheduler%4Operational.evtx",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
        "Microsoft-Windows-PowerShell%4Operational.evtx",
    };
    for (int i = 0; i < IMG_MAX_LOGS; i++) {
        char rel[200];
        snprintf(rel, sizeof rel, "Windows\\System32\\winevt\\Logs\\%s", logs[i]);
        at(p, p->evtx[p->nevtx], sizeof p->evtx[0], rel, 0);
        if (p->evtx[p->nevtx][0]) p->nevtx++;
    }
    // Profiles: every Users\<name> that has an NTUSER.DAT.
    char pat[MAX_PATH + 16];
    snprintf(pat, sizeof pat, "%s\\Users\\*", p->root);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.' || p->nusers >= IMG_MAX_USERS)
                continue;
            img_user *u = &p->users[p->nusers];
            char rel[MAX_PATH + 120];
            snprintf(rel, sizeof rel, "Users\\%s\\NTUSER.DAT", fd.cFileName);
            at(p, u->ntuser, sizeof u->ntuser, rel, 0);
            if (u->ntuser[0] == 0) continue;
            snprintf(u->name, sizeof u->name, "%s", fd.cFileName);
            snprintf(rel, sizeof rel, "Users\\%s\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", fd.cFileName);
            at(p, u->usrclass, sizeof u->usrclass, rel, 0);
            snprintf(rel, sizeof rel, "Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", fd.cFileName);
            at(p, u->pshist, sizeof u->pshist, rel, 0);
            snprintf(rel, sizeof rel, "Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent", fd.cFileName);
            at(p, u->recent, sizeof u->recent, rel, 1);
            snprintf(rel, sizeof rel, "Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations", fd.cFileName);
            at(p, u->autodest, sizeof u->autodest, rel, 1);
            p->nusers++;
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    return p->system[0] || p->software[0] ? 0 : -1;
}
