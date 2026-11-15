// winspect triage - a single verdict from several independent signals
//
// The individual commands each answer one narrow question. An analyst looking at
// an unknown process wants the questions asked together and the answers weighed:
// "should I care about this one?" triage does exactly that. It gathers the cheap,
// high-signal, user-mode checks winspect already knows how to do and turns them
// into a score plus the concrete reasons behind it:
//
//   signature trust   - is the image Authenticode-trusted (embedded or catalog)?
//   path masquerade    - does the PEB image path match the kernel's real path?
//   ntdll inline hooks  - are the hot native stubs patched in this process?
//   private executable - is there committed +X memory with no backing module?
//   token integrity    - is it elevated, and does that line up with trust?
//
// None of these alone is proof of anything (EDRs hook ntdll; installers run from
// %TEMP%). Weighed together they separate "ordinary" from "look closer", which is
// what triage reports. Every reason is spelled out so the score is never a black
// box. Read-only, user-mode, no driver.

// Win10 API surface for QueryFullProcessImageName etc.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "pidarg.h"
#include "triage.h"
#include "jsonutil.h"
#include "artparse.h"
#include "detect.h"     // shared image-tamper / IAT-hook detection

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>   // PEB, PROCESS_BASIC_INFORMATION
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// A single scored observation. weight is added to the total only when hit.
struct reason {
    const char *text;
    int         weight;
};

#define MAX_REASONS 16

// --- building blocks (compact versions of the dedicated commands) -------------

// Bounded, all-or-nothing ReadProcessMemory.
static int rpm(HANDLE h, const void *remote, void *local, SIZE_T n)
{
    SIZE_T got = 0;
    return (ReadProcessMemory(h, remote, local, n, &got) && got == n) ? 1 : 0;
}

// Reads a UNICODE_STRING's text from the target into a UTF-8 buffer.
static void read_ustr(HANDLE h, const UNICODE_STRING *us, char *out, size_t outsz)
{
    out[0] = '\0';
    if (us->Length == 0 || us->Buffer == NULL) {
        return;
    }
    WCHAR wbuf[1024];
    USHORT bytes = us->Length;
    USHORT cap = (USHORT)(sizeof wbuf - sizeof(WCHAR));
    if (bytes > cap) {
        bytes = cap;
    }
    if (!rpm(h, us->Buffer, wbuf, bytes)) {
        return;
    }
    wbuf[bytes / sizeof(WCHAR)] = L'\0';
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, (int)outsz, NULL, NULL);
}

// Returns the target's PEB ImagePathName in UTF-8 (empty on failure).
static void peb_image_path(HANDLE h, char *out, size_t outsz)
{
    out[0] = '\0';
    PROCESS_BASIC_INFORMATION pbi;
    if (NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof pbi, NULL) < 0 ||
        pbi.PebBaseAddress == NULL) {
        return;
    }
    PEB peb;
    if (!rpm(h, pbi.PebBaseAddress, &peb, sizeof peb) || peb.ProcessParameters == NULL) {
        return;
    }
    RTL_USER_PROCESS_PARAMETERS params;
    if (rpm(h, peb.ProcessParameters, &params, sizeof params)) {
        read_ustr(h, &params.ImagePathName, out, outsz);
    }
}

// Counts how many of the frequently-hooked ntdll stubs differ between this
// process and the target (an inline hook leaves the target's bytes changed).
static int count_hooked_stubs(HANDLE h)
{
    static const char *names[] = {
        "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
        "NtCreateThreadEx", "NtMapViewOfSection",
    };
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        return 0;
    }
    int hooked = 0;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        FARPROC fn = GetProcAddress(ntdll, names[i]);
        if (fn == NULL) {
            continue;
        }
        uintptr_t a;
        memcpy(&a, &fn, sizeof a);
        const void *p = (const void *)a;
        unsigned char local[8], remote[8];
        memcpy(local, p, sizeof local);
        if (rpm(h, p, remote, sizeof remote) && memcmp(local, remote, sizeof local) != 0) {
            hooked++;
        }
    }
    return hooked;
}

// Counts committed, private, executable regions (code with no backing module).
static int count_private_exec(HANDLE h)
{
    uintptr_t addr = 0;
    int flagged = 0;
    for (unsigned guard = 0; guard < 1000000; guard++) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof mbi) != sizeof mbi) {
            break;
        }
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) {
            break;
        }
        addr = next;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            DWORD base = mbi.Protect & 0xFF;
            if (base & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                flagged++;
            }
        }
    }
    return flagged;
}

// Is the file at wpath Authenticode-trusted, via an embedded signature or a
// system catalog? Sets *source to "embedded", "catalog", or "none".
static int image_trusted(const WCHAR *wpath, const char **source)
{
    *source = "none";

    WINTRUST_FILE_INFO fi;
    ZeroMemory(&fi, sizeof fi);
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = wpath;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd;
    ZeroMemory(&wd, sizeof wd);
    wd.cbStruct            = sizeof wd;
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fi;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;

    LONG st = WinVerifyTrust(NULL, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wd);

    if (st == ERROR_SUCCESS) {
        *source = "embedded";
        return 1;
    }
    if (st != (LONG)TRUST_E_NOSIGNATURE) {
        return 0;   // signed but not trusted, tampered, expired, ...
    }

    // No embedded signature: try the catalog path (common for OS binaries).
    HANDLE hFile = CreateFileW(wpath, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }
    HCATADMIN hAdmin = NULL;
    int trusted = 0;
    if (CryptCATAdminAcquireContext(&hAdmin, NULL, 0)) {
        DWORD hashLen = 0;
        CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, NULL, 0);
        BYTE *hash = (hashLen > 0) ? (BYTE *)malloc(hashLen) : NULL;
        if (hash != NULL && CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash, 0)) {
            HCATINFO hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash, hashLen, 0, NULL);
            if (hCat != NULL) {
                CATALOG_INFO ci;
                ZeroMemory(&ci, sizeof ci);
                ci.cbStruct = sizeof ci;
                WCHAR tag[2 * 64 + 1];
                DWORD tagn = (hashLen > 64) ? 64 : hashLen;
                for (DWORD i = 0; i < tagn; i++) {
                    static const WCHAR hexd[] = L"0123456789ABCDEF";
                    tag[i * 2]     = hexd[(hash[i] >> 4) & 0xF];
                    tag[i * 2 + 1] = hexd[hash[i] & 0xF];
                }
                tag[tagn * 2] = L'\0';
                if (CryptCATCatalogInfoFromContext(hCat, &ci, 0)) {
                    WINTRUST_CATALOG_INFO wci;
                    ZeroMemory(&wci, sizeof wci);
                    wci.cbStruct             = sizeof wci;
                    wci.pcwszCatalogFilePath = ci.wszCatalogFile;
                    wci.pcwszMemberFilePath  = wpath;
                    wci.pcwszMemberTag       = tag;
                    wci.hMemberFile          = hFile;
                    wci.pbCalculatedFileHash = hash;
                    wci.cbCalculatedFileHash = hashLen;

                    WINTRUST_DATA cwd;
                    ZeroMemory(&cwd, sizeof cwd);
                    cwd.cbStruct            = sizeof cwd;
                    cwd.dwUIChoice          = WTD_UI_NONE;
                    cwd.fdwRevocationChecks = WTD_REVOKE_NONE;
                    cwd.dwUnionChoice       = WTD_CHOICE_CATALOG;
                    cwd.pCatalog            = &wci;
                    cwd.dwStateAction       = WTD_STATEACTION_VERIFY;

                    LONG cst = WinVerifyTrust(NULL, &action, &cwd);
                    cwd.dwStateAction = WTD_STATEACTION_CLOSE;
                    WinVerifyTrust(NULL, &action, &cwd);
                    if (cst == ERROR_SUCCESS) {
                        trusted = 1;
                        *source = "catalog";
                    }
                }
                CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
            }
        }
        free(hash);
        CryptCATAdminReleaseContext(hAdmin, 0);
    }
    CloseHandle(hFile);
    return trusted;
}

// Case-insensitive "does haystack contain needle?" for path heuristics.
static int path_contains(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        if (_strnicmp(p, needle, nl) == 0) {
            return 1;
        }
    }
    return 0;
}

// Token integrity level name + whether elevated.
static const char *token_integrity_and_elev(HANDLE proc, int *elevated)
{
    *elevated = 0;
    const char *level = "unknown";
    HANDLE tok = NULL;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
        return level;
    }
    DWORD len = 0;
    TOKEN_ELEVATION el;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &len)) {
        *elevated = el.TokenIsElevated ? 1 : 0;
    }
    // Integrity level from the token's mandatory label SID RID.
    DWORD need = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &need);
    if (need > 0) {
        TOKEN_MANDATORY_LABEL *lbl = (TOKEN_MANDATORY_LABEL *)malloc(need);
        if (lbl != NULL && GetTokenInformation(tok, TokenIntegrityLevel, lbl, need, &need)) {
            UCHAR *cnt = GetSidSubAuthorityCount(lbl->Label.Sid);
            DWORD rid = (cnt != NULL && *cnt > 0)
                        ? *GetSidSubAuthority(lbl->Label.Sid, (DWORD)(*cnt - 1)) : 0;
            if (rid >= SECURITY_MANDATORY_SYSTEM_RID)      level = "System";
            else if (rid >= SECURITY_MANDATORY_HIGH_RID)   level = "High";
            else if (rid >= SECURITY_MANDATORY_MEDIUM_RID) level = "Medium";
            else if (rid >= SECURITY_MANDATORY_LOW_RID)    level = "Low";
            else                                           level = "Untrusted";
        }
        free(lbl);
    }
    CloseHandle(tok);
    return level;
}

// Does the process hold a powerful privilege in the ENABLED state? SeDebug and
// friends are the token-level capability behind tampering with other processes;
// enabled (not merely present) is the interesting state.
// Name of the real parent of `pid` (Toolhelp ppid, accepted only if that
// process was created before the child - otherwise the PID was recycled).
// Returns 1 and fills `out` when the parent is alive and genuine.
static int real_parent_name(DWORD pid, char *out, size_t n)
{
    out[0] = '\0';
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof pe;
    DWORD ppid = 0;
    int found = 0;
    if (Process32FirstW(s, &pe)) {
        do { if (pe.th32ProcessID == pid) { ppid = pe.th32ParentProcessID; found = 1; break; } }
        while (Process32NextW(s, &pe));
    }
    int ok = 0;
    if (found && ppid != 0 && Process32FirstW(s, &pe)) {
        do {
            if (pe.th32ProcessID != ppid) continue;
            FILETIME c1, c2, x1, x2, k1, k2, u1, u2;
            HANDLE hc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
            int older = 1;      // cannot tell -> trust the snapshot
            if (hc && hp && GetProcessTimes(hc, &c1, &x1, &k1, &u1) &&
                    GetProcessTimes(hp, &c2, &x2, &k2, &u2)) {
                older = CompareFileTime(&c2, &c1) <= 0;
            }
            if (hc) CloseHandle(hc);
            if (hp) CloseHandle(hp);
            if (older) {
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, out, (int)n, NULL, NULL);
                ok = 1;
            }
            break;
        } while (Process32NextW(s, &pe));
    }
    CloseHandle(s);
    return ok;
}

// Returns 1 if any powerful privilege is ENABLED; their names are written to
// `which` (comma-separated) so the report can say exactly which ones.
static int has_dangerous_enabled_priv(HANDLE proc, char *which, size_t whichn)
{
    which[0] = '\0';
    static const char *danger[] = {
        "SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege", "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege", "SeCreateTokenPrivilege",
    };
    HANDLE tok = NULL;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
        return 0;
    }
    int found = 0;
    DWORD need = 0;
    GetTokenInformation(tok, TokenPrivileges, NULL, 0, &need);
    if (need > 0) {
        TOKEN_PRIVILEGES *p = (TOKEN_PRIVILEGES *)malloc(need);
        if (p != NULL && GetTokenInformation(tok, TokenPrivileges, p, need, &need)) {
            for (DWORD i = 0; i < p->PrivilegeCount; i++) {
                if (!(p->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) {
                    continue;
                }
                char name[64];
                DWORD nl = sizeof name;
                if (LookupPrivilegeNameA(NULL, &p->Privileges[i].Luid, name, &nl)) {
                    for (size_t d = 0; d < sizeof danger / sizeof danger[0]; d++) {
                        if (strcmp(name, danger[d]) == 0) {
                            size_t L = strlen(which);
                            snprintf(which + L, whichn - L, "%s%s", found ? ", " : "", name);
                            found = 1;
                            break;
                        }
                    }
                }
            }
        }
        free(p);
    }
    CloseHandle(tok);
    return found;
}

int cmd_triage(int argc, char **argv)
{
    const char *pid_arg = NULL;
    int json = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) json = 1;
        else if (pid_arg == NULL)           pid_arg = argv[a];
        else {
            fprintf(stderr, "triage: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (pid_arg == NULL) {
        fputs("usage: winspect triage <pid> [--json]\n", stderr);
        return 1;
    }
    unsigned long pid = 0;
    if (!pid_from_arg("triage", pid_arg, &pid)) {
        return 1;
    }

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h == NULL) {
        DWORD err = GetLastError();
        fprintf(stderr, "triage: cannot open pid %lu (error %lu)\n", pid, (unsigned long)err);
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "        (try an elevated console; a Medium process can't read a High one)\n");
        }
        return 1;
    }

    struct reason reasons[MAX_REASONS];
    int nreasons = 0;
    int score = 0;

    // --- gather the facts -----------------------------------------------------
    char realpath[MAX_PATH] = "";
    DWORD rlen = sizeof realpath;
    int have_real = QueryFullProcessImageNameA(h, 0, realpath, &rlen) ? 1 : 0;

    const char *sig_source = "none";
    int trusted = 0;
    if (have_real) {
        WCHAR wpath[MAX_PATH * 2];
        if (MultiByteToWideChar(CP_ACP, 0, realpath, -1, wpath,
                                (int)(sizeof wpath / sizeof wpath[0])) != 0) {
            trusted = image_trusted(wpath, &sig_source);
        }
    }

    char pebpath[MAX_PATH * 2] = "";
    peb_image_path(h, pebpath, sizeof pebpath);
    int masquerade = (have_real && pebpath[0] && _stricmp(realpath, pebpath) != 0);

    int hooks = count_hooked_stubs(h);
    int privx = count_private_exec(h);

    // Deep checks shared with `verify`: does the main image in memory still match
    // its file on disk (hollowing / patch), and do its imports resolve into real
    // modules (IAT hook)?
    struct tamper_result tamper;
    detect_image_tamper(h, &tamper);
    struct iathook_result iat;
    detect_iat_hooks(h, &iat);
    struct thread_result thr;
    detect_unbacked_threads(h, (DWORD)pid, &thr);
    struct secperm_result sperm;
    detect_section_perms(h, &sperm);

    int elevated = 0;
    const char *integrity = token_integrity_and_elev(h, &elevated);
    char danger_names[256];
    int danger_priv = has_dangerous_enabled_priv(h, danger_names, sizeof danger_names);
    char danger_msg[320];
    snprintf(danger_msg, sizeof danger_msg, "token has powerful privilege(s) ENABLED: %s",
             danger_names);

    // Lineage ("Hunt Evil" rules, shared with `hunt`): a core Windows process
    // started by the wrong parent, or a core name running outside System32.
    const char *base = have_real ? strrchr(realpath, '\\') : NULL;
    base = base ? base + 1 : (have_real ? realpath : "");
    char parent[260] = "";
    int have_parent = real_parent_name((DWORD)pid, parent, sizeof parent);
    int bad_parent = have_parent && base[0] && lineage_parent_ok(base, parent) == 0;
    int outside_sys32 = 0;
    if (have_real && base[0] && lineage_system32_only(base)) {
        char sys32[MAX_PATH] = "", wow[MAX_PATH] = "";
        GetSystemDirectoryA(sys32, MAX_PATH);
        GetSystemWow64DirectoryA(wow, MAX_PATH);
        size_t l1 = strlen(sys32), l2 = strlen(wow);
        int in1 = l1 && _strnicmp(realpath, sys32, l1) == 0 && realpath[l1] == '\\';
        int in2 = l2 && _strnicmp(realpath, wow, l2) == 0 && realpath[l2] == '\\';
        outside_sys32 = !in1 && !in2;
    }
    char parent_msg[400];
    snprintf(parent_msg, sizeof parent_msg, "%s started by unexpected parent %s", base, parent);

    int from_temp = have_real && (path_contains(realpath, "\\Temp\\") ||
                                  path_contains(realpath, "\\AppData\\") ||
                                  path_contains(realpath, "\\Downloads\\") ||
                                  path_contains(realpath, "\\Users\\Public\\"));

    CloseHandle(h);

    // --- weigh them -----------------------------------------------------------
    // Each reason both bumps the score and records a human explanation. The
    // weights are deliberately blunt; triage points you at a process, it does
    // not convict it.
    #define ADD(cond, w, msg) do { \
        if ((cond) && nreasons < MAX_REASONS) { \
            reasons[nreasons].text = (msg); reasons[nreasons].weight = (w); \
            score += (w); nreasons++; \
        } } while (0)

    ADD(tamper.modified_sections > 0, 45, "main image code in memory differs from the file on disk (hollowing / patch?)");
    ADD(privx > 0, 40, "private executable memory present (no backing module - injected code?)");
    // Softer weight than the disk/memory signals: JIT and some managed runtimes
    // legitimately start threads in unbacked memory, so this alone shouldn't
    // convict - it should contribute, not dominate.
    ADD(thr.unbacked > 0, 25, "thread(s) start outside any module (injected / hijacked thread?)");
    ADD(sperm.mismatches > 0, 35, "section(s) more permissive in memory than on disk (patched/staged code?)");
    ADD(iat.hooked_entries > 0, 35, "IAT entries point into unbacked memory (import hook / trampoline?)");
    ADD(masquerade, 30, "PEB image path does not match the kernel image path (masquerade?)");
    ADD(outside_sys32, 40, "core Windows process name running outside System32 (masquerading)");
    ADD(bad_parent, 30, parent_msg);
    ADD(!trusted, 25, "image is not Authenticode-trusted (no valid signature or catalog)");
    ADD(hooks > 0, 15, "ntdll stubs are inline-hooked in this process (EDR, or injected hooks)");
    ADD(from_temp, 15, "image runs from a user-writable / temporary location");
    ADD(danger_priv, 15, danger_msg);
    ADD(elevated && !trusted, 10, "process is elevated but its image is not trusted");

    #undef ADD

    const char *verdict = (score >= 60) ? "HIGH" : (score >= 30) ? "MEDIUM" : "LOW";

    // --- report ---------------------------------------------------------------
    if (json) {
        printf("{\"pid\":%lu,\"image\":", pid);
        json_str(have_real ? realpath : "");
        printf(",\"score\":%d,\"verdict\":", score);
        json_str(verdict);
        fputs(",\"signals\":{", stdout);
        printf("\"trusted\":%s,\"signature_source\":", trusted ? "true" : "false");
        json_str(sig_source);
        printf(",\"masquerade\":%s", masquerade ? "true" : "false");
        fputs(",\"peb_path\":", stdout); json_str(pebpath);
        printf(",\"hooked_stubs\":%d,\"private_exec_regions\":%d", hooks, privx);
        printf(",\"image_modified_sections\":%d,\"iat_hooked_entries\":%d",
               tamper.modified_sections, iat.hooked_entries);
        printf(",\"image_diff_bytes\":%u,\"image_patch_count\":%u,\"image_patches\":",
               tamper.total_diff_bytes, tamper.patch_count);
        detect_json_patches(&tamper);
        printf(",\"unbacked_threads\":%d,\"section_perm_mismatches\":%d",
               thr.unbacked, sperm.mismatches);
        fputs(",\"integrity\":", stdout); json_str(integrity);
        printf(",\"elevated\":%s,\"from_temp\":%s,\"dangerous_privilege\":%s",
               elevated ? "true" : "false", from_temp ? "true" : "false",
               danger_priv ? "true" : "false");
        fputs(",\"parent\":", stdout); json_str(parent);
        printf(",\"unexpected_parent\":%s,\"outside_system32\":%s}",
               bad_parent ? "true" : "false", outside_sys32 ? "true" : "false");
        fputs(",\"reasons\":[", stdout);
        for (int i = 0; i < nreasons; i++) {
            printf("%s{\"weight\":%d,\"text\":", i ? "," : "", reasons[i].weight);
            json_str(reasons[i].text);
            putchar('}');
        }
        puts("]}");
    } else {
        printf("triage  pid %lu\n", pid);
        printf("  image        %s\n", have_real ? realpath : "(unknown)");
        printf("  signature    %s (%s)\n", trusted ? "trusted" : "NOT trusted", sig_source);
        printf("  integrity    %s%s\n", integrity, elevated ? " (elevated)" : "");
        printf("  parent       %s\n", have_parent ? parent : "(exited or unknown)");
        printf("  ntdll hooks  %d\n", hooks);
        printf("  private +x   %d region(s)\n", privx);
        printf("  image tamper %d section(s) differ from disk\n", tamper.modified_sections);
        if (tamper.modified_sections == 0 && tamper.skipped_sections) {
            printf("               not compared: %s (written by the Windows loader in every process)\n", tamper.skipped_section);
        }
        if (tamper.modified_sections > 0) {
            // The evidence behind the signal, so it can be judged rather than
            // trusted: a few short jumps into a named DLL is a hooking product,
            // a section that differs wholesale is a replaced image.
            char sum[256];
            detect_tamper_summary(&tamper, sum, sizeof sum);
            printf("               %s\n", sum);
            detect_print_patches(&tamper, "               ");
        }
        printf("  IAT hooks    %d entry(ies) into unbacked memory\n", iat.hooked_entries);
        printf("  bad threads  %d thread(s) start outside any module\n", thr.unbacked);
        printf("  section perm %d section(s) more permissive in memory\n", sperm.mismatches);
        putchar('\n');
        printf("  SCORE %d  ->  %s\n", score, verdict);
        if (nreasons == 0) {
            puts("  (no suspicious signals)");
        } else {
            puts("  reasons:");
            for (int i = 0; i < nreasons; i++) {
                printf("    [+%2d] %s\n", reasons[i].weight, reasons[i].text);
            }
        }
    }
    return 0;
}
