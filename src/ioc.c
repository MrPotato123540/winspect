// Indicator (IOC) shape detection - pure, OS-independent, unit-tested.
// Extracted from the strings command so the same classification can be reused
// and verified on any platform (see tests/test_util.c).

#include "ioc.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

int ioc_is_ipv4(const char *s)
{
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) {
            continue;
        }
        // p is at the start of a digit run; try to read a.b.c.d from here.
        const char *q = p;
        int groups = 0, ok = 1;
        for (int g = 0; g < 4; g++) {
            int val = 0, digits = 0;
            while (isdigit((unsigned char)*q) && digits < 3) {
                val = val * 10 + (*q - '0'); q++; digits++;
            }
            if (digits == 0 || val > 255) { ok = 0; break; }
            groups++;
            if (g < 3) {
                if (*q != '.') { ok = 0; break; }
                q++;
            }
        }
        // A match must be a clean quad not immediately followed by another digit
        // (so "1.2.3.4" matches but "1.2.3.45" is still fine, "1.2.3.4.5" is not a
        // /32 and the trailing ".5" means the run continues - rejected).
        if (ok && groups == 4 && *q != '.' && !isdigit((unsigned char)*q)) {
            return 1;
        }
        // Skip past this digit/dot run before trying again.
        while (*p && (isdigit((unsigned char)*p) || *p == '.')) {
            p++;
        }
        if (!*p) { break; }
    }
    return 0;
}

static int starts_with_ci(const char *s, const char *pfx)
{
    for (; *pfx; s++, pfx++) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*pfx)) {
            return 0;
        }
    }
    return 1;
}

static int contains_ci(const char *s, const char *needle)
{
    for (const char *p = s; *p; p++) {
        if (starts_with_ci(p, needle)) {
            return 1;
        }
    }
    return 0;
}

// A long run of the base64 alphabet with valid padding: at least 40 chars,
// length a multiple of 4, '=' only at the very end (max two), and a mix of
// character kinds (at least one digit or '+' or '/', and both letter cases)
// so ordinary long words or hex dumps do not qualify.
static int looks_base64(const char *s)
{
    size_t n = strlen(s), pad = 0;
    if (n < 40 || n % 4 != 0) return 0;
    int lower = 0, upper = 0, other = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '=') {
            pad++;
            if (i < n - 2) return 0;
            continue;
        }
        if (pad) return 0;                  // data after padding
        if (c >= 'a' && c <= 'z')      lower = 1;
        else if (c >= 'A' && c <= 'Z') upper = 1;
        else if ((c >= '0' && c <= '9') || c == '+' || c == '/') other = 1;
        else return 0;
    }
    return pad <= 2 && lower && upper && other;
}

const char *ioc_classify(const char *s)
{
    // PowerShell with an encoded command: the payload is hidden in base64.
    if (contains_ci(s, "powershell") || contains_ci(s, "pwsh")) {
        if (contains_ci(s, " -enc") || contains_ci(s, " -e ") || contains_ci(s, " -ec ") ||
            contains_ci(s, "-encodedcommand")) {
            return "encoded-cmd";
        }
    }
    if (contains_ci(s, "http://") || contains_ci(s, "https://") || contains_ci(s, "ftp://")) {
        return "url";
    }
    if (starts_with_ci(s, "HKEY_") || contains_ci(s, "\\CurrentVersion\\") ||
        contains_ci(s, "SYSTEM\\CurrentControlSet") || contains_ci(s, "\\SOFTWARE\\")) {
        return "registry";
    }
    if (ioc_is_ipv4(s)) {
        return "ip";
    }
    // A drive-letter path (X:\) or a UNC path (\\server\share).
    if ((isalpha((unsigned char)s[0]) && s[1] == ':' && s[2] == '\\') ||
        (s[0] == '\\' && s[1] == '\\')) {
        return "path";
    }
    if (looks_base64(s)) {
        return "base64";
    }
    return "";
}

int ioc_user_writable(const char *p)
{
    static const char *const dirs[] = {
        "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Users\\Public\\",
        "\\ProgramData\\", "%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%",
        "%PUBLIC%", "%PROGRAMDATA%",
    };
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        if (contains_ci(p, dirs[i])) {
            return 1;
        }
    }
    return 0;
}

int ioc_contains_ci(const char *s, const char *needle)
{
    return contains_ci(s, needle);
}

int ioc_script_host(const char *cmd)
{
    // 1) Isolate the executable part of the command line.
    char exe[512];
    const char *p = cmd;
    while (*p == ' ' || *p == '\t') p++;
    size_t len;
    if (*p == '"') {                              // "C:\x\y.exe" args
        p++;
        const char *q = strchr(p, '"');
        len = q ? (size_t)(q - p) : strlen(p);
    } else {                                      // C:\x y\z.exe args  |  name args
        len = strlen(p);
        for (size_t i = 0; p[i]; i++) {
            if (starts_with_ci(p + i, ".exe") && (p[i + 4] == '\0' || p[i + 4] == ' ')) {
                len = i + 4;
                break;
            }
        }
        if (len == strlen(p)) {                   // no ".exe": stop at first space
            const char *sp = strchr(p, ' ');
            if (sp) len = (size_t)(sp - p);
        }
    }
    if (len >= sizeof exe) len = sizeof exe - 1;
    memcpy(exe, p, len);
    exe[len] = '\0';

    // 2) Basename without ".exe".
    char *base = exe;
    for (char *q = exe; *q; q++) {
        if (*q == '\\' || *q == '/') base = q + 1;
    }
    size_t bl = strlen(base);
    if (bl > 4 && starts_with_ci(base + bl - 4, ".exe")) base[bl - 4] = '\0';

    // 3) Whole-name comparison against the launcher list.
    static const char *const hosts[] = {
        "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
        "cmd", "certutil", "bitsadmin", "msiexec", "installutil", "regasm", "regsvcs",
        "msbuild", "forfiles", NULL
    };
    for (int i = 0; hosts[i] != NULL; i++) {
        if (strlen(base) == strlen(hosts[i]) && starts_with_ci(base, hosts[i])) {
            return 1;
        }
    }
    return 0;
}

// Tiny pattern matcher for pipe names: literal characters compare ignoring
// case, '#' matches one decimal digit, '%' matches one hex digit, and a final
// '*' matches any remainder. The whole name must be consumed.
static int pipe_match(const char *name, const char *pat)
{
    for (; *pat; pat++, name++) {
        if (*pat == '*') return 1;
        char c = *name;
        if (c == '\0') return 0;
        if (*pat == '#') {
            if (c < '0' || c > '9') return 0;
        } else if (*pat == '%') {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
        } else {
            char a = c, b = *pat;
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) return 0;
        }
    }
    return *name == '\0';
}

const char *ioc_pipe_known(const char *pipe)
{
    static const struct { const char *pat, *label; } known[] = {
        { "MSSE-####-server",  "Cobalt Strike default pipe" },
        { "msagent_%%",        "Cobalt Strike default pipe" },
        { "postex_%%%%",       "Cobalt Strike default pipe" },
        { "postex_ssh_%%%%",   "Cobalt Strike default pipe" },
        { "status_%%",         "Cobalt Strike default pipe" },
        { "PSEXESVC*",         "PsExec service pipe (remote execution)" },
        { "RemCom_communicaton*", "RemCom service pipe (remote execution)" },
        { "PAExec*",           "PAExec service pipe (remote execution)" },
    };
    for (size_t i = 0; i < sizeof known / sizeof known[0]; i++) {
        if (pipe_match(pipe, known[i].pat)) {
            return known[i].label;
        }
    }
    return NULL;
}

const char *ioc_ip_scope(const char *s)
{
    unsigned o[4];
    int n = 0;
    const char *p = s;
    for (int i = 0; i < 4; i++) {
        if (*p < '0' || *p > '9') return "";
        unsigned v = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (unsigned)(*p - '0');
            if (++digits > 3 || v > 255) return "";
            p++;
        }
        o[n++] = v;
        if (i < 3) {
            if (*p != '.') return "";
            p++;
        }
    }
    if (*p != '\0') return "";
    if (o[0] == 127)                                  return "loopback";
    if (o[0] == 0)                                    return "unspecified";
    if (o[0] == 10)                                   return "private";
    if (o[0] == 172 && o[1] >= 16 && o[1] <= 31)      return "private";
    if (o[0] == 192 && o[1] == 168)                   return "private";
    if (o[0] == 169 && o[1] == 254)                   return "link-local";
    if (o[0] == 100 && o[1] >= 64 && o[1] <= 127)     return "cgnat";
    if (o[0] >= 224 && o[0] <= 239)                   return "multicast";
    if (o[0] == 255 && o[1] == 255 && o[2] == 255 && o[3] == 255) return "broadcast";
    return "public";
}

unsigned ioc_port_from_net(unsigned long field)
{
    // Keep only the low 16 bits, swap the two bytes, and mask again: the
    // shift happens in int, so without the final mask the old high byte would
    // survive above bit 15 (0x1234 would become 0x123412).
    unsigned n = (unsigned)(field & 0xFFFFu);
    return ((n >> 8) | (n << 8)) & 0xFFFFu;
}

// Copy the first token of p: quoted string, or up to ".exe"/".dll" + space/end,
// or up to the first space. Returns a pointer just past the token.
static const char *first_token(const char *p, char *out, size_t n)
{
    while (*p == ' ' || *p == '\t') p++;
    size_t len;
    const char *next;
    if (*p == '"') {
        p++;
        const char *q = strchr(p, '"');
        len = q ? (size_t)(q - p) : strlen(p);
        next = q ? q + 1 : p + len;
    } else {
        len = strlen(p);
        const char *sp = strchr(p, ' ');
        for (size_t i = 0; p[i]; i++) {
            if ((starts_with_ci(p + i, ".exe") || starts_with_ci(p + i, ".dll") ||
                 starts_with_ci(p + i, ".com") || starts_with_ci(p + i, ".scr")) &&
                    (p[i + 4] == '\0' || p[i + 4] == ' ' || p[i + 4] == ',')) {
                len = i + 4;
                break;
            }
            if (sp && p + i == sp && !contains_ci(p, ".exe") && !contains_ci(p, ".dll")) {
                len = i;
                break;
            }
        }
        next = p + len;
    }
    if (len >= n) len = n - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return next;
}

int ioc_command_image(const char *cmd, char *out, size_t n)
{
    out[0] = '\0';
    if (cmd == NULL || *cmd == '\0' || n == 0) return 0;
    // BootExecute lines start with the keyword "autocheck" ("autocheck autochk
    // *"); the program is the word after it.
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    if (starts_with_ci(cmd, "autocheck ")) cmd += 10;
    const char *rest = first_token(cmd, out, n);
    // For DLL launchers the interesting file is the DLL argument.
    char exe[512];
    snprintf(exe, sizeof exe, "%s", out);
    const char *base = exe;
    for (const char *q = exe; *q; q++) if (*q == '\\' || *q == '/') base = q + 1;
    int is_rundll = starts_with_ci(base, "rundll32");
    int is_regsvr = starts_with_ci(base, "regsvr32");
    if (is_rundll || is_regsvr) {
        // Skip switches (/s, /i:..., -x) and take the next token.
        const char *p = rest;
        for (;;) {
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '/' || *p == '-') {
                while (*p && *p != ' ') p++;
                continue;
            }
            break;
        }
        if (*p) {
            char dll[1024];
            first_token(p, dll, sizeof dll);
            char *comma = strchr(dll, ',');      // rundll32 a.dll,Entry
            if (comma) *comma = '\0';
            if (dll[0]) snprintf(out, n, "%s", dll);
        }
    }
    return out[0] != '\0';
}

const char *ioc_ps_reason(const char *l)
{
    if (contains_ci(l, "-encodedcommand") || contains_ci(l, " -enc ") || contains_ci(l, " -ec ") ||
        ((contains_ci(l, "powershell") || contains_ci(l, "pwsh")) && contains_ci(l, " -e ")))
        return "encoded PowerShell command";
    if (contains_ci(l, "DownloadString") || contains_ci(l, "DownloadFile") || contains_ci(l, "DownloadData") ||
        contains_ci(l, "Net.WebClient") || contains_ci(l, "Start-BitsTransfer") ||
        ((contains_ci(l, "Invoke-WebRequest") || contains_ci(l, "iwr ") || contains_ci(l, "curl ") ||
          contains_ci(l, "wget ") || contains_ci(l, "Invoke-RestMethod") || contains_ci(l, "irm ")) &&
         (contains_ci(l, "iex") || contains_ci(l, "Invoke-Expression"))))
        return "download cradle (fetches code from the network)";
    if (contains_ci(l, "AmsiUtils") || contains_ci(l, "amsiInitFailed") || contains_ci(l, "AmsiScanBuffer"))
        return "AMSI tampering";
    if ((contains_ci(l, "Set-MpPreference") && contains_ci(l, "-Disable")) ||
        (contains_ci(l, "Add-MpPreference") && contains_ci(l, "-Exclusion")))
        return "Microsoft Defender settings weakened";
    if (contains_ci(l, "mimikatz") || contains_ci(l, "sekurlsa") || contains_ci(l, "Invoke-Mimikatz") ||
        (contains_ci(l, "comsvcs") && contains_ci(l, "MiniDump")) || contains_ci(l, "lsass.dmp"))
        return "credential dumping";
    if (contains_ci(l, "Clear-EventLog") || contains_ci(l, "wevtutil cl") || contains_ci(l, "wevtutil.exe cl") ||
        contains_ci(l, "Remove-EventLog") || contains_ci(l, "ConsoleHost_history"))
        return "log / history clearing";
    if (contains_ci(l, "-ExecutionPolicy Bypass") || contains_ci(l, "-ep bypass") || contains_ci(l, "-exec bypass") ||
        contains_ci(l, "Set-ExecutionPolicy Unrestricted") || contains_ci(l, "Set-ExecutionPolicy Bypass"))
        return "execution policy bypass";
    if (contains_ci(l, "Invoke-Expression") || contains_ci(l, "iex(") || contains_ci(l, "iex (") || contains_ci(l, "| iex"))
        return "runs a string as code (Invoke-Expression)";
    if (contains_ci(l, "Register-ScheduledTask") || contains_ci(l, "New-ScheduledTask") || contains_ci(l, "schtasks /create") ||
        contains_ci(l, "New-Service") || contains_ci(l, "sc.exe create") || contains_ci(l, "sc create") ||
        (contains_ci(l, "CurrentVersion\\Run") && (contains_ci(l, "Set-ItemProperty") || contains_ci(l, "New-ItemProperty") ||
                                                    contains_ci(l, "reg add"))))
        return "persistence (task / service / Run key)";
    return NULL;
}
