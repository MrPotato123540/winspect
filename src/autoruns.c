// winspect autoruns - what runs automatically (registry + Startup ASEPs)
//
// Persistence most often lives in well-known places: Run / RunOnce (machine,
// user, Wow6432Node, Policies), Winlogon Userinit/Shell, IFEO Debugger,
// SilentProcessExit, AppInit_DLLs, BootExecute, the LSA package lists, print
// monitors, NetSh helpers and the Startup folders. This command reads them -
// read-only - and lists every entry, flagging it WITH A REASON:
//   * "user-writable path"  - the command lives in Temp/AppData/Downloads/...
//   * "non-default value"   - for locations that always exist (Shell, Userinit,
//                             BootExecute, LSA, monitors) the question is
//                             whether the stock Windows value was changed
//   * "rarely legitimate location" - IFEO Debugger, SilentProcessExit,
//                             AppInit_DLLs, per-user Shell: any entry is odd
//   * Startup folders are judged by file type (a raw .exe/.bat/.vbs dropped
//     there, not a shortcut), because the folder itself is under AppData.
//   * Newer locations (Autoruns' other tabs, by concept): AppCertDlls, cmd.exe
//     AutoRun, logon scripts, Active Setup, time providers, screensaver,
//     exefile / ms-settings handler hijacks and the "Office test" key.
//   * With --sig, an entry whose image path does not exist is reported as
//     "image file not found" (Autoruns' yellow "File not found" rows): a
//     leftover - or a dropper that already deleted its payload.
// It is a deliberately small, transparent subset of Sysinternals Autoruns;
// every location is named in the output. We never add, change or remove values.

#include "autoruns.h"
#include "jsonutil.h"
#include "ioc.h"
#include "lnk.h"
#include "sign.h"
#include "artparse.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void w2u(const WCHAR *w, char *out, size_t n)
{
    out[0] = '\0';
    if (w != NULL) {
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)n, NULL, NULL);
    }
}

#define AR_SEEN_MAX 2048
struct arctx {
    int mode; int first; unsigned count; unsigned flagged;
    int only_flagged;       // --flagged: print only entries with a reason
    int sig;                // --sig: verify each entry's image signature
    // Fingerprints of reported (name, command) pairs. Some keys are SHARED
    // between the 64-bit view and Wow6432Node, so reading both would print the
    // same entry twice; a WOW64 entry identical to one already shown is skipped.
    unsigned long long seen[AR_SEEN_MAX];
    unsigned nseen;
};

// FNV-1a over name + '\x01' + command.
static unsigned long long ar_fp(const char *name, const char *cmd)
{
    unsigned long long h = 1469598103934665603ULL;
    for (const char *p = name; *p; p++) { h ^= (unsigned char)*p; h *= 1099511628211ULL; }
    h ^= 1; h *= 1099511628211ULL;
    for (const char *p = cmd; *p; p++) { h ^= (unsigned char)*p; h *= 1099511628211ULL; }
    return h;
}

// Returns 1 if this entry is a WOW64 duplicate that should be skipped;
// otherwise records it and returns 0.
static int ar_duplicate(struct arctx *c, const char *loc, const char *name, const char *cmd)
{
    unsigned long long fp = ar_fp(name, cmd);
    int is_wow = strstr(loc, "WOW64") != NULL || strstr(loc, "Wow6432Node") != NULL;
    if (is_wow) {
        for (unsigned i = 0; i < c->nseen; i++) {
            if (c->seen[i] == fp) {
                return 1;
            }
        }
    }
    if (c->nseen < AR_SEEN_MAX) {
        c->seen[c->nseen++] = fp;
    }
    return 0;
}
#define AR_TEXT 0
#define AR_JSON 1
#define AR_CSV  2

// A "default check": returns 1 when a value is the stock Windows value. Used
// for locations that always exist (Winlogon Shell, BootExecute, LSA packages):
// there the interesting question is "was the default changed?", not "is there
// an entry?". NULL means "no default to compare against".
typedef int (*default_fn)(const char *item);

// Prints one entry; reason == NULL means "not flagged".
static void emit_reason(struct arctx *c, const char *loc, const char *name, const char *cmd,
                        const char *reason)
{
    if (ar_duplicate(c, loc, name, cmd)) {
        return;
    }
    // --sig (Autoruns' "Verify code signatures"): resolve what the entry runs
    // and check its signature; an untrusted image becomes a reason of its own.
    char sigtxt[32] = "";
    if (c->sig) {
        char image[1024];
        const char *src = "none";
        int t = sign_command_trust(cmd, image, sizeof image, &src);
        // -1 with a full path resolved means the file itself is gone; -1 with
        // nothing resolved means we could not tell what the command runs.
        int missing = (t == -1 && strchr(image, '\\') != NULL);
        snprintf(sigtxt, sizeof sigtxt, "%s", t == 1 ? src : t == 0 ? "untrusted"
                                              : missing ? "missing" : "unresolved");
        if (t == 0 && reason == NULL) {
            reason = "image not signed / not trusted";
        } else if (missing && reason == NULL) {
            reason = "image file not found";
        }
    }
    c->count++;
    if (reason) { c->flagged++; }
    if (c->only_flagged && reason == NULL) {
        return;
    }
    if (c->mode == AR_TEXT) {
        printf("  %s%-22s %s\n", reason ? "[!] " : "    ", name, cmd);
        printf("        (%s)%s%s%s%s\n", loc, sigtxt[0] ? "  sig: " : "", sigtxt,
               reason ? "  <- " : "", reason ? reason : "");
    } else if (c->mode == AR_CSV) {
        csv_str(loc);  putchar(',');
        csv_str(name); putchar(',');
        csv_str(cmd);  printf(",%d,", reason ? 1 : 0);
        csv_str(reason ? reason : ""); putchar(',');
        csv_str(sigtxt); putchar('\n');
    } else {
        printf("%s{\"location\":", c->first ? "" : ",");
        json_str(loc);
        fputs(",\"name\":", stdout); json_str(name);
        fputs(",\"command\":", stdout); json_str(cmd);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        fputs(",\"signature\":", stdout);
        json_str(sigtxt);
        putchar('}');
        c->first = 0;
    }
}

// Flags an entry - with the reason - when the command points into a
// user-writable directory, when a default check says the value is not the
// stock one, or when `always` is set (locations where any entry is unusual).
static void emit_ex(struct arctx *c, const char *loc, const char *name, const char *cmd,
                    int always, default_fn is_default)
{
    const char *reason = NULL;
    if (ioc_user_writable(cmd))                        reason = "user-writable path";
    else if (is_default != NULL && !is_default(cmd))   reason = "non-default value";
    else if (always)                                   reason = "rarely legitimate location";
    emit_reason(c, loc, name, cmd, reason);
}

static void emit(struct arctx *c, const char *loc, const char *name, const char *cmd)
{
    emit_ex(c, loc, name, cmd, 0, NULL);
}

static int in_list_ci(const char *s, const char *const *list)
{
    for (; *list != NULL; list++) {
        if (_stricmp(s, *list) == 0) {
            return 1;
        }
    }
    return 0;
}

// --- stock values (Windows 10/11) ------------------------------------------
static int def_shell(const char *s) { return _stricmp(s, "explorer.exe") == 0; }

static int def_userinit(const char *s)
{
    // Stock: "<SystemDirectory>\userinit.exe," - trailing comma(s) optional.
    char want[MAX_PATH], got[MAX_PATH];
    UINT n = GetSystemDirectoryA(want, MAX_PATH);
    if (n == 0 || n >= MAX_PATH - 16) {
        return 1;   // cannot tell - do not raise a false alarm
    }
    snprintf(want + n, sizeof want - n, "\\userinit.exe");
    snprintf(got, sizeof got, "%s", s);
    size_t L = strlen(got);
    while (L > 0 && (got[L - 1] == ',' || got[L - 1] == ' ')) { got[--L] = '\0'; }
    return _stricmp(got, want) == 0 || _stricmp(got, "userinit.exe") == 0;
}

static int def_bootexecute(const char *s)
{
    // Stock: "autocheck autochk *" (chkdsk at boot); options may vary.
    return _strnicmp(s, "autocheck autochk ", 18) == 0;
}

static int def_lsa_auth(const char *s)
{
    static const char *const d[] = { "msv1_0", NULL };
    return in_list_ci(s, d);
}

static int def_lsa_notify(const char *s)
{
    static const char *const d[] = { "scecli", "rassfm", NULL };
    return in_list_ci(s, d);
}

static int def_lsa_security(const char *s)
{
    static const char *const d[] = { "kerberos", "msv1_0", "schannel", "wdigest", "tspkg",
                                     "pku2u", "cloudAP", "negoexts", "livessp", NULL };
    return in_list_ci(s, d);
}

static int def_print_monitor(const char *s)
{
    static const char *const d[] = { "localspl.dll", "tcpmon.dll", "usbmon.dll", "WSDMon.dll",
                                     "APMon.dll", "AppMon.dll", "FXSMON.DLL", NULL };
    return in_list_ci(s, d);
}

static int def_netsh_helper(const char *s)
{
    // Stock helpers are bare DLL names resolved from System32. A full path
    // elsewhere is what stands out.
    return strchr(s, '\\') == NULL || ioc_contains_ci(s, "\\System32\\");
}

// Enumerates all values of one Run-style key (name -> command).
static void enum_run_key(HKEY root, const WCHAR *subkey, const char *label, struct arctx *c)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) {
        return;
    }
    for (DWORD i = 0; ; i++) {
        WCHAR wname[512];
        DWORD namelen = 512;
        BYTE data[4096];
        DWORD datalen = sizeof data - sizeof(WCHAR);   // room for our terminator
        DWORD type = 0;
        LONG r = RegEnumValueW(k, i, wname, &namelen, NULL, &type, data, &datalen);
        if (r == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (r != ERROR_SUCCESS) {
            continue;
        }
        if (type != REG_SZ && type != REG_EXPAND_SZ) {
            continue;
        }
        data[datalen] = 0;          // registry strings may lack a NUL
        data[datalen + 1] = 0;
        char name[512], cmd[2048];
        w2u(wname, name, sizeof name);
        w2u((const WCHAR *)data, cmd, sizeof cmd);
        emit(c, label, name[0] ? name : "(default)", cmd);
    }
    RegCloseKey(k);
}

// Reads one named value (Winlogon Userinit / Shell) and reports it as an entry.
static void read_value(HKEY root, const WCHAR *subkey, const WCHAR *value,
                       const char *label, int always, default_fn is_default,
                       struct arctx *c)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) {
        return;
    }
    BYTE data[4096];
    // Leave room for a terminator: registry strings are not guaranteed to be
    // NUL-terminated, so we add one ourselves before converting.
    DWORD datalen = sizeof data - sizeof(WCHAR), type = 0;
    if (RegQueryValueExW(k, value, NULL, &type, data, &datalen) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        data[datalen] = 0;
        data[datalen + 1] = 0;
        char name[256], cmd[2048];
        w2u(value[0] ? value : L"(default)", name, sizeof name);
        w2u((const WCHAR *)data, cmd, sizeof cmd);
        if (cmd[0] != '\0') {          // an empty value persists nothing
            emit_ex(c, label, name, cmd, always, is_default);
        }
    }
    RegCloseKey(k);
}

// For each subkey of `parent`, reads the string value `value` and reports it
// with the subkey name as the entry name. This is the shape of the per-image
// hijack points: IFEO\<image.exe>\Debugger and
// SilentProcessExit\<image.exe>\MonitorProcess - "when X starts/exits, run Y".
static void enum_subkey_value(HKEY root, const WCHAR *parent, const WCHAR *value,
                              const char *label, int always, default_fn is_default,
                              struct arctx *c)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(root, parent, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) {
        return;
    }
    for (DWORD i = 0; ; i++) {
        WCHAR sub[256];
        DWORD sublen = 256;
        LONG r = RegEnumKeyExW(k, i, sub, &sublen, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (r != ERROR_SUCCESS) {
            continue;
        }
        HKEY sk = NULL;
        if (RegOpenKeyExW(k, sub, 0, KEY_READ, &sk) != ERROR_SUCCESS) {
            continue;
        }
        BYTE data[4096];
        DWORD datalen = sizeof data - sizeof(WCHAR), type = 0;
        if (RegQueryValueExW(sk, value, NULL, &type, data, &datalen) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            data[datalen] = 0;
            data[datalen + 1] = 0;
            char name[256], cmd[2048];
            w2u(sub, name, sizeof name);
            w2u((const WCHAR *)data, cmd, sizeof cmd);
            if (cmd[0] != '\0') {
                emit_ex(c, label, name, cmd, always, is_default);
            }
        }
        RegCloseKey(sk);
    }
    RegCloseKey(k);
}

// Reads a REG_MULTI_SZ value and reports each string as its own entry
// (BootExecute, LSA package lists). A literal "" item - how Windows writes an
// empty Security Packages list - is skipped.
static void read_multi_sz(HKEY root, const WCHAR *subkey, const WCHAR *value,
                          const char *label, default_fn is_default, struct arctx *c)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) {
        return;
    }
    WCHAR data[4096];
    // Reserve two WCHARs so the list is always double-NUL terminated.
    DWORD datalen = sizeof data - 2 * sizeof(WCHAR), type = 0;
    if (RegQueryValueExW(k, value, NULL, &type, (BYTE *)data, &datalen) == ERROR_SUCCESS &&
        (type == REG_MULTI_SZ || type == REG_SZ)) {
        size_t nw = datalen / sizeof(WCHAR);
        data[nw] = 0;
        data[nw + 1] = 0;
        char name[256];
        w2u(value, name, sizeof name);
        for (const WCHAR *p = data; *p != 0; p += wcslen(p) + 1) {
            char item[1024];
            w2u(p, item, sizeof item);
            if (item[0] == '\0' || strcmp(item, "\"\"") == 0) {
                continue;
            }
            emit_ex(c, label, name, item, 0, is_default);
        }
    }
    RegCloseKey(k);
}

// Reports every value of a key whose value DATA is a DLL (NetSh helpers).
static void enum_value_dlls(HKEY root, const WCHAR *subkey, const char *label,
                            int always, default_fn is_default, struct arctx *c)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) {
        return;
    }
    for (DWORD i = 0; ; i++) {
        WCHAR wname[256];
        DWORD namelen = 256;
        BYTE data[2048];
        DWORD datalen = sizeof data - sizeof(WCHAR), type = 0;
        LONG r = RegEnumValueW(k, i, wname, &namelen, NULL, &type, data, &datalen);
        if (r == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
            continue;
        }
        data[datalen] = 0;
        data[datalen + 1] = 0;
        char name[256], dll[1024];
        w2u(wname, name, sizeof name);
        w2u((const WCHAR *)data, dll, sizeof dll);
        if (dll[0] != '\0') {
            emit_ex(c, label, name, dll, always, is_default);
        }
    }
    RegCloseKey(k);
}

// Lists the files in a Startup folder: anything dropped here runs at logon.
static void enum_startup_dir(const char *dir, const char *label, struct arctx *c)
{
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof pattern, "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        if (_stricmp(fd.cFileName, "desktop.ini") == 0) {
            continue;   // folder metadata, not an auto-start entry
        }
        char full[MAX_PATH];
        snprintf(full, sizeof full, "%s\\%s", dir, fd.cFileName);
        // The per-user Startup folder itself lives under AppData, so judging by
        // path would flag every entry. Judge by what was dropped instead:
        // shortcuts (.lnk/.url) are the normal case; a raw executable or script
        // placed directly in Startup is not.
        const char *ext = strrchr(fd.cFileName, '.');
        if (ext != NULL && _stricmp(ext, ".lnk") == 0) {
            // Resolve the shortcut: what it RUNS matters, not that it is a .lnk.
            WCHAR wfull[MAX_PATH];
            lnk_info li;
            if (MultiByteToWideChar(CP_ACP, 0, full, -1, wfull, MAX_PATH) > 0 &&
                    lnk_load(wfull, &li) == 0 && (li.target[0] != '\0' || li.anomalies)) {
                char cmd[3200];
                snprintf(cmd, sizeof cmd, "%s%s%s", li.target, li.arguments[0] ? " " : "",
                         li.arguments);
                const char *reason = lnk_anomaly_reason(li.anomalies);
                if (reason != NULL)                     ;   // crafted link: says enough
                else if (ioc_script_host(li.target))    reason = "shortcut launches a script host / LOLBin";
                else if (ioc_user_writable(li.target))  reason = "user-writable path";
                emit_reason(c, label, fd.cFileName, cmd, reason);
                continue;
            }
        }
        int normal = ext != NULL && (_stricmp(ext, ".lnk") == 0 || _stricmp(ext, ".url") == 0);
        emit_reason(c, label, fd.cFileName, full,
                    normal ? NULL : "executable/script dropped directly in Startup");
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int cmd_autoruns(int argc, char **argv)
{
    int mode = AR_TEXT, only_flagged = 0, sig = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = AR_JSON;
        else if (strcmp(argv[a], "--flagged") == 0) only_flagged = 1;
        else if (strcmp(argv[a], "--sig") == 0) sig = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = AR_CSV;
        else {
            fprintf(stderr, "autoruns: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    static struct arctx c;     // static: the fingerprint table is 16 KB
    memset(&c, 0, sizeof c);
    c.mode = mode; c.first = 1; c.only_flagged = only_flagged; c.sig = sig;

    if (mode == AR_TEXT) {
        puts("autoruns  (registry + Startup auto-start locations)\n");
    } else if (mode == AR_CSV) {
        puts("location,name,command,suspicious,reason,signature");
    } else if (mode == AR_JSON) {
        putchar('[');
    }

    static const WCHAR RUN[]       = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    static const WCHAR RUNONCE[]   = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    static const WCHAR RUN_WOW[]   = L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
    static const WCHAR WINLOGON[]  = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

    enum_run_key(HKEY_LOCAL_MACHINE, RUN,     "HKLM\\...\\Run",         &c);
    enum_run_key(HKEY_LOCAL_MACHINE, RUNONCE, "HKLM\\...\\RunOnce",     &c);
    enum_run_key(HKEY_LOCAL_MACHINE, RUN_WOW, "HKLM\\Wow6432Node\\Run", &c);
    enum_run_key(HKEY_CURRENT_USER,  RUN,     "HKCU\\...\\Run",         &c);
    enum_run_key(HKEY_CURRENT_USER,  RUNONCE, "HKCU\\...\\RunOnce",     &c);

    // Winlogon Userinit / Shell: tampering here is a classic logon-persistence
    // technique, so we surface them even when they hold the default value.
    read_value(HKEY_LOCAL_MACHINE, WINLOGON, L"Userinit", "HKLM\\...\\Winlogon", 0, def_userinit, &c);
    read_value(HKEY_LOCAL_MACHINE, WINLOGON, L"Shell",    "HKLM\\...\\Winlogon", 0, def_shell, &c);
    // A per-user Shell override replaces Explorer for that user only.
    read_value(HKEY_CURRENT_USER,  WINLOGON, L"Shell",    "HKCU\\...\\Winlogon", 1, NULL, &c);

    // Policy-driven Run keys: same effect as Run, but set via (Group) Policy and
    // easy to overlook.
    static const WCHAR POL_RUN[] =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run";
    enum_run_key(HKEY_LOCAL_MACHINE, POL_RUN, "HKLM\\...\\Policies\\Explorer\\Run", &c);
    enum_run_key(HKEY_CURRENT_USER,  POL_RUN, "HKCU\\...\\Policies\\Explorer\\Run", &c);

    // Image File Execution Options "Debugger": when the named image starts, the
    // debugger command runs INSTEAD (MITRE T1546.012). Legitimate uses are rare
    // outside developer machines, so any entry here deserves a look.
    static const WCHAR IFEO[] =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    static const WCHAR IFEO_WOW[] =
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    enum_subkey_value(HKEY_LOCAL_MACHINE, IFEO,     L"Debugger", "IFEO Debugger",        1, NULL, &c);
    enum_subkey_value(HKEY_LOCAL_MACHINE, IFEO_WOW, L"Debugger", "IFEO Debugger (WOW64)", 1, NULL, &c);

    // SilentProcessExit "MonitorProcess": runs a program when the named image
    // exits - the quieter sibling of the IFEO Debugger trick.
    static const WCHAR SPE[] =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";
    static const WCHAR SPE_WOW[] =
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";
    enum_subkey_value(HKEY_LOCAL_MACHINE, SPE,     L"MonitorProcess", "SilentProcessExit",         1, NULL, &c);
    enum_subkey_value(HKEY_LOCAL_MACHINE, SPE_WOW, L"MonitorProcess", "SilentProcessExit (WOW64)", 1, NULL, &c);

    // AppInit_DLLs: DLLs loaded into every process that loads user32 (only
    // honoured when LoadAppInit_DLLs = 1, and blocked under Secure Boot on
    // modern Windows - but any value here is still a red flag).
    static const WCHAR WINDOWS_NT[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    static const WCHAR WINDOWS_NT_WOW[] =
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    read_value(HKEY_LOCAL_MACHINE, WINDOWS_NT,     L"AppInit_DLLs", "AppInit_DLLs",         1, NULL, &c);
    read_value(HKEY_LOCAL_MACHINE, WINDOWS_NT_WOW, L"AppInit_DLLs", "AppInit_DLLs (WOW64)", 1, NULL, &c);

    // BootExecute: native programs smss.exe runs before Windows is up (stock:
    // "autocheck autochk *"). Anything else runs extremely early and privileged.
    static const WCHAR SESSMGR[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    read_multi_sz(HKEY_LOCAL_MACHINE, SESSMGR, L"BootExecute", "BootExecute", def_bootexecute, &c);

    // LSA packages: DLLs lsass.exe loads - authentication, password-change
    // notification and security support providers. An extra entry here can see
    // credentials (MITRE T1547.002/.005), so we compare against the stock lists.
    static const WCHAR LSA[]     = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
    static const WCHAR LSA_OSC[] = L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig";
    read_multi_sz(HKEY_LOCAL_MACHINE, LSA,     L"Authentication Packages", "LSA", def_lsa_auth, &c);
    read_multi_sz(HKEY_LOCAL_MACHINE, LSA,     L"Notification Packages",   "LSA", def_lsa_notify, &c);
    read_multi_sz(HKEY_LOCAL_MACHINE, LSA,     L"Security Packages",       "LSA", def_lsa_security, &c);
    read_multi_sz(HKEY_LOCAL_MACHINE, LSA_OSC, L"Security Packages",       "LSA\\OSConfig", def_lsa_security, &c);

    // Print monitors: DLLs the spooler (SYSTEM) loads at start (T1547.010).
    static const WCHAR MONITORS[] = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors";
    enum_subkey_value(HKEY_LOCAL_MACHINE, MONITORS, L"Driver", "Print Monitors", 0,
                      def_print_monitor, &c);

    // NetSh helper DLLs: loaded whenever netsh.exe runs (T1546.007).
    enum_value_dlls(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\NetSh", "NetSh helpers",
                    0, def_netsh_helper, &c);

    // AppCertDlls: loaded into every process that calls CreateProcess*
    // (T1546.009). Windows ships none, so any value is unusual.
    enum_value_dlls(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
                    "AppCertDlls", 1, NULL, &c);

    // cmd.exe AutoRun: a command run every time cmd.exe starts (unless /D).
    // Not set by Windows; any value deserves a look.
    static const WCHAR CMDPROC[] = L"SOFTWARE\\Microsoft\\Command Processor";
    read_value(HKEY_LOCAL_MACHINE, CMDPROC, L"AutoRun", "HKLM\\...\\Command Processor", 1, NULL, &c);
    read_value(HKEY_CURRENT_USER,  CMDPROC, L"AutoRun", "HKCU\\...\\Command Processor", 1, NULL, &c);

    // Logon script set per user in HKCU\Environment (T1037.001): runs at
    // logon without touching any Run key.
    read_value(HKEY_CURRENT_USER, L"Environment", L"UserInitMprLogonScript",
               "HKCU\\Environment", 1, NULL, &c);

    // Active Setup: StubPath commands run once per user at logon (T1547.014).
    // Windows and many installers use it, so only user-writable paths stand out.
    enum_subkey_value(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
                      L"StubPath", "Active Setup", 0, NULL, &c);
    enum_subkey_value(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components",
                      L"StubPath", "Active Setup (WOW64)", 0, NULL, &c);

    // Time providers: DLLs the W32Time service (svchost, LOCAL SERVICE) loads
    // (T1547.003). Stock: NtpClient/NtpServer -> System32\w32time.dll and the
    // Hyper-V provider vmictimeprovider.dll.
    enum_subkey_value(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders",
                      L"DllName", "Time Providers", 0, asep_time_provider_default, &c);

    // Screensaver: Windows runs SCRNSAVE.EXE after idle time (T1546.002); a
    // .scr is just a PE file. Flagged when it lives in a user-writable dir.
    read_value(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"SCRNSAVE.EXE",
               "HKCU\\Control Panel\\Desktop", 0, NULL, &c);

    // Executable file association: how Explorer opens an .exe. Stock value is
    // "%1" %*; anything else wraps every program start (Autoruns' "Hijacks").
    read_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\exefile\\shell\\open\\command", L"",
               "HKLM\\Classes\\exefile", 0, asep_exefile_default, &c);
    // Per-user overrides of protocol / file handlers that elevated Windows
    // programs consult (ms-settings is read by fodhelper/computerdefaults,
    // exefile by many). Windows creates none of these under HKCU, so any
    // value is a documented UAC-bypass / hijack pattern (T1548.002, T1546.001).
    read_value(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell\\Open\\command", L"",
               "HKCU\\Classes\\ms-settings", 1, NULL, &c);
    read_value(HKEY_CURRENT_USER, L"Software\\Classes\\exefile\\shell\\open\\command", L"",
               "HKCU\\Classes\\exefile", 1, NULL, &c);

    // "Office test" key: a DLL every Office application loads at start
    // (T1137.002). Not created by Office itself.
    read_value(HKEY_CURRENT_USER,  L"Software\\Microsoft\\Office test\\Special\\Perf", L"",
               "HKCU\\Office test", 1, NULL, &c);
    read_value(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office test\\Special\\Perf", L"",
               "HKLM\\Office test", 1, NULL, &c);

    // Startup folders: per-user and all-users. Files here run at logon.
    {
        char base[MAX_PATH], dir[MAX_PATH];
        if (GetEnvironmentVariableA("APPDATA", base, sizeof base) > 0) {
            snprintf(dir, sizeof dir, "%s\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", base);
            enum_startup_dir(dir, "Startup (user)", &c);
        }
        if (GetEnvironmentVariableA("ProgramData", base, sizeof base) > 0) {
            snprintf(dir, sizeof dir, "%s\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp", base);
            enum_startup_dir(dir, "Startup (all users)", &c);
        }
    }

    if (mode == AR_TEXT) {
        printf("\n%u auto-start entr%s, %u flagged\n",
               c.count, c.count == 1 ? "y" : "ies", c.flagged);
    } else if (mode == AR_JSON) {
        puts("]");
    }
    return 0;
}
