// artparse - portable parsers for ShimCache blobs and firewall rule strings
//
// ShimCache (AppCompatCache), Windows 10/11 layout:
//   header: u32 offset of the first entry - 0x30 before the Creators Update,
//           0x34 from it on (the header grew by one field).
//   entry:  "10ts" signature (4) | unknown (4) | u32 entry size = bytes that
//           follow these first 12 | u16 path size in bytes | UTF-16 path |
//           u64 last-modified FILETIME | u32 data size | data
//   The next entry starts at entry + 12 + entry size.
// We validate that path + time + data fit inside the declared entry size and
// stop at the first entry that does not: the size field is the only link to
// the next entry, so continuing past a bad one would mean guessing.
//
// Firewall rules are plain strings of '|'-separated Key=Value fields with a
// leading version ("v2.30"); fw_field pulls one field out by exact key.

#include "artparse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const unsigned char *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

// Minimal UTF-16LE -> UTF-8 (BMP + surrogate pairs, '?' for broken ones).
static void u16_to_u8(const unsigned char *s, size_t nchars, char *out, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < nchars; i++) {
        uint32_t c = (uint32_t)s[2 * i] | ((uint32_t)s[2 * i + 1] << 8);
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < nchars) {
            uint32_t lo = (uint32_t)s[2 * i + 2] | ((uint32_t)s[2 * i + 3] << 8);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                i++;
            } else {
                c = '?';
            }
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            c = '?';
        }
        unsigned char b[4] = { 0, 0, 0, 0 };
        size_t len;
        if (c < 0x80)         { b[0] = (unsigned char)c; len = 1; }
        else if (c < 0x800)   { b[0] = (unsigned char)(0xC0 | (c >> 6));
                                b[1] = (unsigned char)(0x80 | (c & 0x3F)); len = 2; }
        else if (c < 0x10000) { b[0] = (unsigned char)(0xE0 | (c >> 12));
                                b[1] = (unsigned char)(0x80 | ((c >> 6) & 0x3F));
                                b[2] = (unsigned char)(0x80 | (c & 0x3F)); len = 3; }
        else                  { b[0] = (unsigned char)(0xF0 | (c >> 18));
                                b[1] = (unsigned char)(0x80 | ((c >> 12) & 0x3F));
                                b[2] = (unsigned char)(0x80 | ((c >> 6) & 0x3F));
                                b[3] = (unsigned char)(0x80 | (c & 0x3F)); len = 4; }
        if (o + len + 1 > n) {
            break;
        }
        memcpy(out + o, b, len);
        o += len;
    }
    out[o] = '\0';
}

// Windows 7: header 128 bytes (magic @0, entry count @4); entries describe
// UTF-16 paths stored elsewhere in the blob (offset from the blob start).
static int shim_parse_win7(const unsigned char *d, size_t n, shim_cb cb, void *ctx, const char **format)
{
    size_t count = rd32(d + 4);
    if (count > (n - 128) / 32) return -2;
    // x64 entries are 48 bytes with a 64-bit path offset @8; x86 entries are
    // 32 bytes with a 32-bit path offset @4. Pick x64 when its first entry
    // makes sense (path stored after the entry table, inside the blob).
    int x64 = 0;
    if (count == 0) {
        x64 = 1;
    } else if (128 + count * 48 <= n) {
        uint64_t off = rd64(d + 128 + 8);
        size_t len = (size_t)d[128] | ((size_t)d[129] << 8);
        x64 = off >= 128 + count * 48 && off <= n && len <= n - off;
    }
    size_t esz = x64 ? 48 : 32;
    if (128 + count * esz > n) return -2;
    if (format) *format = x64 ? "win7-x64" : "win7-x86";
    int reported = 0;
    for (size_t i = 0; i < count; i++) {
        const unsigned char *e = d + 128 + i * esz;
        size_t len = (size_t)e[0] | ((size_t)e[1] << 8);
        uint64_t off = x64 ? rd64(e + 8) : rd32(e + 4);
        uint64_t mtime = rd64(e + (x64 ? 16 : 8));
        uint32_t insert = rd32(e + (x64 ? 24 : 16));
        if (off > n || len > n - off) return -2;
        char path[1024];
        u16_to_u8(d + off, len / 2, path, sizeof path);
        cb(path, mtime, (insert & 0x2) ? 1 : 0, ctx);
        reported++;
    }
    return reported;
}

int shim_parse_ex(const unsigned char *d, size_t n, shim_cb cb, void *ctx, const char **format)
{
    if (format) *format = "";
    if (n < 0x34) {
        return -1;
    }
    if (rd32(d) == 0xBADC0FEEu) {
        return n >= 128 ? shim_parse_win7(d, n, cb, ctx, format) : -1;
    }
    size_t pos = rd32(d);
    if (pos != 0x30 && pos != 0x34) {
        return -1;      // Windows 8.x / XP layouts are different - not handled
    }
    if (format) *format = "win10";
    int count = 0;
    while (pos + 12 <= n && memcmp(d + pos, "10ts", 4) == 0) {
        size_t esize = rd32(d + pos + 8);
        const unsigned char *e = d + pos + 12;
        if (esize > n - pos - 12 || esize < 2) {
            return -2;
        }
        size_t psize = (size_t)e[0] | ((size_t)e[1] << 8);
        if (2 + psize + 8 + 4 > esize) {
            return -2;
        }
        uint64_t mtime = rd64(e + 2 + psize);
        size_t dsize = rd32(e + 2 + psize + 8);
        if (dsize > esize - (2 + psize + 8 + 4)) {
            return -2;
        }
        char path[1024];
        u16_to_u8(e + 2, psize / 2, path, sizeof path);
        cb(path, mtime, -1, ctx);
        count++;
        pos += 12 + esize;
    }
    return count;
}

int shim_parse(const unsigned char *d, size_t n, shim_cb cb, void *ctx)
{
    return shim_parse_ex(d, n, cb, ctx, NULL);
}

int fw_field(const char *rule, const char *key, char *out, size_t n)
{
    size_t kl = strlen(key);
    out[0] = '\0';
    // Fields start at the beginning of the string or right after a '|'.
    for (const char *p = rule; p != NULL && *p; ) {
        if (strncmp(p, key, kl) == 0 && p[kl] == '=') {
            const char *v = p + kl + 1;
            size_t i = 0;
            while (v[i] != '\0' && v[i] != '|' && i + 1 < n) {
                out[i] = v[i];
                i++;
            }
            out[i] = '\0';
            return 1;
        }
        p = strchr(p, '|');
        if (p != NULL) {
            p++;
        }
    }
    return 0;
}

// ---- service / driver paths -------------------------------------------------

static int ieq_prefix(const char *s, const char *pfx)
{
    for (; *pfx; s++, pfx++) {
        char a = *s, b = *pfx;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

int svc_unquoted_path(const char *p)
{
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p == '"' || *p == '\0') {
        return 0;
    }
    // Locate the end of the executable: the first ".exe" (case-insensitive)
    // that is followed by end-of-string or a space.
    for (const char *q = p; *q; q++) {
        if (ieq_prefix(q, ".exe") && (q[4] == '\0' || q[4] == ' ')) {
            for (const char *r = p; r < q; r++) {
                if (*r == ' ') {
                    return 1;
                }
            }
            return 0;
        }
    }
    return 0;
}

void drv_path_normalize(const char *raw, const char *windir, char *out, size_t n)
{
    if (n == 0) {
        return;
    }
    if (ieq_prefix(raw, "\\SystemRoot\\")) {
        snprintf(out, n, "%s\\%s", windir, raw + 12);
    } else if (ieq_prefix(raw, "\\??\\")) {
        snprintf(out, n, "%s", raw + 4);
    } else if (ieq_prefix(raw, "system32\\")) {
        snprintf(out, n, "%s\\%s", windir, raw);
    } else if (ieq_prefix(raw, "\\Windows\\") && windir[0] != '\0' && windir[1] == ':') {
        snprintf(out, n, "%c:%s", windir[0], raw);
    } else {
        snprintf(out, n, "%s", raw);
    }
}

// ---- process lineage rules ----------------------------------------------------

static int ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y) return 0;
    }
    return *a == *b;
}

// ---- Auto-start default values ------------------------------------------------

int asep_exefile_default(const char *cmd)
{
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    size_t n = strlen(cmd);
    while (n > 0 && (cmd[n - 1] == ' ' || cmd[n - 1] == '\t')) n--;
    return n == 7 && memcmp(cmd, "\"%1\" %*", 7) == 0;
}

int asep_time_provider_default(const char *dll)
{
    const char *base = strrchr(dll, '\\');
    if (base == NULL) {
        base = dll;                                    // bare name: System32 search
    } else {
        // Directory part must end in "\system32" (any drive / %systemroot%).
        size_t dl = (size_t)(base - dll);
        if (dl < 9 || !ieq_prefix(base - 9, "\\system32")) return 0;
        base++;
    }
    return ieq(base, "w32time.dll") || ieq(base, "vmictimeprovider.dll");
}

struct lineage_rule {
    const char *child;
    const char *parents[3];     // expected parent names (NULL-terminated)
    int parent_may_exit;        // started by a short-lived parent (smss / userinit)
};

static const struct lineage_rule lineage_rules[] = {
    { "smss.exe",        { "System", "smss.exe", NULL },   0 },
    { "csrss.exe",       { "smss.exe", NULL, NULL },       1 },
    { "wininit.exe",     { "smss.exe", NULL, NULL },       1 },
    { "winlogon.exe",    { "smss.exe", NULL, NULL },       1 },
    { "services.exe",    { "wininit.exe", NULL, NULL },    0 },
    { "lsass.exe",       { "wininit.exe", NULL, NULL },    0 },
    { "lsaiso.exe",      { "wininit.exe", NULL, NULL },    0 },
    { "svchost.exe",     { "services.exe", NULL, NULL },   0 },
    { "spoolsv.exe",     { "services.exe", NULL, NULL },   0 },
    { "taskhostw.exe",   { "svchost.exe", NULL, NULL },    0 },
    { "RuntimeBroker.exe", { "svchost.exe", NULL, NULL },  0 },
    // explorer.exe is deliberately absent: users legitimately restart it from
    // Task Manager or a shell, so a parent rule would mostly raise false alarms.
};

int lineage_parent_ok(const char *child, const char *parent)
{
    for (size_t i = 0; i < sizeof lineage_rules / sizeof lineage_rules[0]; i++) {
        const struct lineage_rule *r = &lineage_rules[i];
        if (!ieq(child, r->child)) continue;
        if (parent == NULL) {
            return r->parent_may_exit ? 1 : -1;
        }
        for (int k = 0; k < 3 && r->parents[k] != NULL; k++) {
            if (ieq(parent, r->parents[k])) return 1;
        }
        return 0;
    }
    return -1;
}

int lineage_singleton(const char *name)
{
    static const char *const one[] = { "lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe", NULL };
    for (int i = 0; one[i] != NULL; i++) {
        if (ieq(name, one[i])) return 1;
    }
    return 0;
}

int lineage_system32_only(const char *name)
{
    static const char *const core[] = {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "wininit.exe",
        "winlogon.exe", "lsaiso.exe", "spoolsv.exe", "taskhostw.exe", "RuntimeBroker.exe",
        "conhost.exe", "dllhost.exe", "rundll32.exe", "taskmgr.exe", NULL
    };
    for (int i = 0; core[i] != NULL; i++) {
        if (ieq(name, core[i])) return 1;
    }
    return 0;
}

int lineage_system_account(const char *name)
{
    // Session-0 core processes: the SANS poster lists "Local System" as their
    // only account. (csrss/winlogon also run as SYSTEM in every session.)
    static const char *const sys[] = {
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "lsaiso.exe", NULL
    };
    for (int i = 0; sys[i] != NULL; i++) {
        if (ieq(name, sys[i])) return 1;
    }
    return 0;
}

int lineage_started_late(const char *name, uint64_t seconds_after_boot)
{
    // Started once, during boot, and never restarted (if one of these dies,
    // Windows bug-checks or reboots). csrss/winlogon are excluded: a new
    // pair starts for every interactive / RDP session.
    static const char *const boot[] = { "wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe", NULL };
    for (int i = 0; boot[i] != NULL; i++) {
        if (ieq(name, boot[i])) return seconds_after_boot > LINEAGE_BOOT_WINDOW_S;
    }
    return 0;
}

int asep_masquerade(const char *image)
{
    const char *base = strrchr(image, '\\');
    if (base == NULL) return 0;                        // bare name: search path
    if (!lineage_system32_only(base + 1)) return 0;
    // Directory part must END in \System32 or \SysWOW64.
    size_t dl = (size_t)(base - image);
    if (dl >= 9 && ieq_prefix(base - 9, "\\System32")) return 0;
    if (dl >= 9 && ieq_prefix(base - 9, "\\SysWOW64")) return 0;
    return 1;
}

// ---- posture rules ----------------------------------------------------------

posture_status posture_judge(posture_op op, uint32_t arg, int present, uint32_t value,
                             posture_status missing)
{
    if (!present) {
        return missing;
    }
    switch (op) {
    case PR_GOOD_IF_EQ:      return value == arg ? POSTURE_OK : POSTURE_WARN;
    case PR_BAD_IF_EQ:       return value == arg ? POSTURE_WARN : POSTURE_OK;
    case PR_GOOD_IF_GE:      return value >= arg ? POSTURE_OK : POSTURE_WARN;
    case PR_GOOD_IF_NONZERO: return value != 0 ? POSTURE_OK : POSTURE_WARN;
    }
    return POSTURE_INFO;
}

// ---- event log XML ----------------------------------------------------------

// Copy [a, b) to out, decoding the five predefined XML entities.
static void xml_copy(const char *a, const char *b, char *out, size_t n)
{
    size_t o = 0;
    while (a < b && o + 1 < n) {
        if (*a == '&') {
            static const struct { const char *ent; char ch; } ents[] = {
                { "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' },
                { "&quot;", '"' }, { "&apos;", '\'' },
            };
            int done = 0;
            for (size_t i = 0; i < sizeof ents / sizeof ents[0]; i++) {
                size_t L = strlen(ents[i].ent);
                if ((size_t)(b - a) >= L && strncmp(a, ents[i].ent, L) == 0) {
                    out[o++] = ents[i].ch;
                    a += L;
                    done = 1;
                    break;
                }
            }
            if (done) continue;
        }
        out[o++] = *a++;
    }
    out[o] = '\0';
}

int evt_data(const char *xml, const char *name, char *out, size_t n)
{
    out[0] = '\0';
    char pat1[160], pat2[160];
    snprintf(pat1, sizeof pat1, "<Data Name='%s'>", name);
    snprintf(pat2, sizeof pat2, "<Data Name=\"%s\">", name);
    const char *p = strstr(xml, pat1);
    size_t plen = strlen(pat1);
    if (p == NULL) {
        p = strstr(xml, pat2);
        plen = strlen(pat2);
    }
    if (p == NULL) return 0;
    p += plen;
    const char *e = strstr(p, "</Data>");
    if (e == NULL) return 0;
    xml_copy(p, e, out, n);
    return 1;
}

int evt_system(const char *xml, const char *element, char *out, size_t n)
{
    out[0] = '\0';
    char open[96], close[96];
    snprintf(open, sizeof open, "<%s", element);
    snprintf(close, sizeof close, "</%s>", element);
    const char *p = xml;
    // Find "<Element" followed by '>' or ' ' (not a longer element name).
    while ((p = strstr(p, open)) != NULL) {
        char c = p[strlen(open)];
        if (c == '>' || c == ' ') break;
        p++;
    }
    if (p == NULL) return 0;
    p = strchr(p, '>');
    if (p == NULL) return 0;
    if (p[-1] == '/') return 0;     // self-closing: no text
    p++;
    const char *e = strstr(p, close);
    if (e == NULL) return 0;
    xml_copy(p, e, out, n);
    return 1;
}

int evt_time(const char *xml, char *out, size_t n)
{
    out[0] = '\0';
    const char *p = strstr(xml, "<TimeCreated");
    if (p == NULL) return 0;
    const char *a = strstr(p, "SystemTime=");
    const char *gt = strchr(p, '>');
    if (a == NULL || (gt != NULL && a > gt)) return 0;
    a += 11;
    char q = *a;
    if (q != '\'' && q != '"') return 0;
    a++;
    const char *e = strchr(a, q);
    if (e == NULL) return 0;
    // "YYYY-MM-DDTHH:MM:SS..." -> "YYYY-MM-DD HH:MM:SS"
    char tmp[64];
    xml_copy(a, e, tmp, sizeof tmp);
    if (strlen(tmp) >= 19 && tmp[10] == 'T') {
        tmp[10] = ' ';
        tmp[19] = '\0';
    }
    snprintf(out, n, "%s", tmp);
    return 1;
}

// ---- system information values ------------------------------------------------------

int systemtime_str(const unsigned char *d, size_t n, char *out, size_t outn)
{
    if (outn) out[0] = '\0';
    if (n < 16) return 0;
    unsigned v[8];
    for (int i = 0; i < 8; i++) v[i] = (unsigned)d[2 * i] | ((unsigned)d[2 * i + 1] << 8);
    // year, month, dow, day, hour, minute, second, ms
    if (v[0] < 1601 || v[0] > 30827 || v[1] < 1 || v[1] > 12 || v[2] > 6 || v[3] < 1 || v[3] > 31 ||
        v[4] > 23 || v[5] > 59 || v[6] > 59 || v[7] > 999) return 0;
    snprintf(out, outn, "%04u-%02u-%02u %02u:%02u:%02u", v[0], v[1], v[3], v[4], v[5], v[6]);
    return 1;
}

void unix_time_str(uint32_t t, char *out, size_t n)
{
    if (n) out[0] = '\0';
    if (t == 0) return;
    // Civil date from days since 1970-01-01 (H. Hinnant's public algorithm).
    long long days = t / 86400, rem = t % 86400;
    days += 719468;
    long long era = days / 146097;
    unsigned doe = (unsigned)(days - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    long long y = (long long)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    unsigned d = doy - (153 * mp + 2) / 5 + 1;
    unsigned m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y++;
    snprintf(out, n, "%04lld-%02u-%02u %02lld:%02lld:%02lld", y, m, d, rem / 3600, (rem / 60) % 60, rem % 60);
}

const char *netlist_name_type(uint32_t t)
{
    switch (t) {
    case 6:   return "wired";
    case 23:  return "vpn";
    case 71:  return "wireless";
    case 243: return "mobile broadband";
    default:  return "other";
    }
}

const char *netlist_category(uint32_t c)
{
    return c == 0 ? "public" : c == 1 ? "private" : c == 2 ? "domain" : "?";
}

// ---- remote-access (RMM) tools ---------------------------------------------------------

static int has_ci(const char *s, const char *needle)
{
    size_t n = strlen(needle);
    for (; *s; s++) {
        size_t i = 0;
        while (i < n) {
            char a = s[i], b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a == '\0' || a != b) break;
            i++;
        }
        if (i == n) return 1;
    }
    return 0;
}

const char *rmm_tool_name(const char *program)
{
    // needle -> product name. Specific names only, so ordinary software does
    // not match (no bare "remote" or "vnc" substrings of unrelated words).
    static const char *const t[][2] = {
        { "anydesk", "AnyDesk" }, { "teamviewer", "TeamViewer" },
        { "screenconnect", "ConnectWise ScreenConnect" }, { "connectwise control", "ConnectWise ScreenConnect" },
        { "splashtop", "Splashtop" }, { "logmein", "LogMeIn" }, { "rustdesk", "RustDesk" },
        { "atera", "Atera" }, { "ninjarmm", "NinjaOne" }, { "ninjaone", "NinjaOne" },
        { "kaseya", "Kaseya" }, { "take control agent", "N-able Take Control" },
        { "remote utilities", "Remote Utilities" }, { "ammyy", "Ammyy Admin" },
        { "supremo", "Supremo" }, { "remotepc", "RemotePC" }, { "zoho assist", "Zoho Assist" },
        { "gotoassist", "GoTo Assist" }, { "goto resolve", "GoTo Resolve" }, { "dwservice", "DWService" },
        { "dwagent", "DWService" }, { "meshagent", "MeshCentral" }, { "meshcentral", "MeshCentral" },
        { "tightvnc", "TightVNC" }, { "ultravnc", "UltraVNC" }, { "realvnc", "RealVNC" },
        { "vnc server", "VNC" }, { "tigervnc", "TigerVNC" }, { "chrome remote desktop", "Chrome Remote Desktop" },
        { "radmin", "Radmin" }, { "netsupport", "NetSupport Manager" }, { "simplehelp", "SimpleHelp" },
        { "action1", "Action1" }, { "pulseway", "Pulseway" }, { "bomgar", "BeyondTrust Remote Support" },
        { "beyondtrust remote", "BeyondTrust Remote Support" }, { "parsec", "Parsec" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        if (has_ci(program, t[i][0])) return t[i][1];
    }
    return NULL;
}

// ---- Amcache -------------------------------------------------------------------------

int amcache_sha1(const char *id, char out[41])
{
    out[0] = '\0';
    size_t n = strlen(id);
    if (n == 44 && strncmp(id, "0000", 4) == 0) id += 4;
    else if (n != 40) return 0;
    for (int i = 0; i < 40; i++) {
        char c = id[i];
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { out[0] = '\0'; return 0; }
        out[i] = c;
    }
    out[40] = '\0';
    return 1;
}

// ---- event filters / failed-logon summary ---------------------------------------

int evt_xpath_since(const char *base, unsigned hours, char *out, size_t n)
{
    size_t bl = strlen(base);
    if (hours == 0) {
        if (bl + 1 > n) return -1;
        memcpy(out, base, bl + 1);
        return 0;
    }
    if (bl < 4 || strncmp(base, "*[System[", 9) != 0 || strcmp(base + bl - 2, "]]") != 0) return -1;
    unsigned long long ms = (unsigned long long)hours * 3600000ULL;
    int w = snprintf(out, n, "%.*s and TimeCreated[timediff(@SystemTime) <= %llu]]]",
                     (int)(bl - 2), base, ms);
    return (w < 0 || (size_t)w >= n) ? -1 : 0;
}

static void copy_str(char *dst, size_t n, const char *src)
{
    size_t L = strlen(src);
    if (L >= n) L = n - 1;
    memcpy(dst, src, L);
    dst[L] = '\0';
}

int evt_fail_add(evt_fail_table *t, const char *ip, const char *user, const char *time)
{
    if (ip == NULL || ip[0] == '\0') ip = "-";
    evt_fail_src *s = NULL;
    for (unsigned i = 0; i < t->n; i++) {
        if (strcmp(t->src[i].ip, ip) == 0) { s = &t->src[i]; break; }
    }
    if (s == NULL) {
        if (t->n >= EVT_FAIL_MAX_SRC) return -1;
        s = &t->src[t->n++];
        memset(s, 0, sizeof *s);
        copy_str(s->ip, sizeof s->ip, ip);
    }
    s->count++;
    // first/last by string order ("YYYY-MM-DD hh:mm:ss" sorts as time).
    if (time != NULL && time[0] != '\0') {
        if (s->first[0] == '\0' || strcmp(time, s->first) < 0) copy_str(s->first, sizeof s->first, time);
        if (strcmp(time, s->last) > 0)                         copy_str(s->last, sizeof s->last, time);
    }
    if (user != NULL && user[0] != '\0') {
        for (unsigned u = 0; u < s->nusers; u++) {
            if (ieq(s->users[u], user)) return 0;
        }
        if (s->nusers < EVT_FAIL_MAX_USERS) copy_str(s->users[s->nusers++], sizeof s->users[0], user);
    }
    return 0;
}

const char *evt_fail_verdict(const evt_fail_src *s)
{
    if (s->nusers >= 5)  return "many accounts from one source (password spraying?)";
    if (s->count >= 10)  return "many failures from one source (password guessing?)";
    return NULL;
}

// ---- Mark-of-the-Web ----------------------------------------------------------

// Copy the value of "key=" from the line starting at p (up to CR/LF).
static int ini_value(const char *p, const char *key, char *out, size_t n)
{
    size_t kl = strlen(key);
    if (strncmp(p, key, kl) != 0 || p[kl] != '=') return 0;
    p += kl + 1;
    size_t o = 0;
    while (*p && *p != '\r' && *p != '\n' && o + 1 < n) out[o++] = *p++;
    out[o] = '\0';
    return 1;
}

void motw_parse(const char *text, motw_info *out)
{
    out->zone = -1;
    out->referrer[0] = out->host[0] = '\0';
    for (const char *line = text; line && *line; ) {
        while (*line == ' ' || *line == '\t') line++;
        char zone[16];
        if (ini_value(line, "ZoneId", zone, sizeof zone)) {
            char *end = NULL;
            long z = strtol(zone, &end, 10);
            if (end != zone) out->zone = (int)z;
        }
        ini_value(line, "ReferrerUrl", out->referrer, sizeof out->referrer);
        ini_value(line, "HostUrl", out->host, sizeof out->host);
        line = strchr(line, '\n');
        if (line) line++;
    }
}

const char *zone_name(int zone)
{
    static const char *const names[] = { "local machine", "intranet", "trusted", "internet", "restricted" };
    return (zone >= 0 && zone <= 4) ? names[zone] : "?";
}

// ---- UserAssist ---------------------------------------------------------------

void rot13_inplace(char *s)
{
    for (; *s; s++) {
        char c = *s;
        if (c >= 'a' && c <= 'z')      *s = (char)('a' + (c - 'a' + 13) % 26);
        else if (c >= 'A' && c <= 'Z') *s = (char)('A' + (c - 'A' + 13) % 26);
    }
}

int userassist_record(const unsigned char *d, size_t n, uint32_t *runs, uint64_t *last)
{
    if (n >= 68) {                      // Windows 7 and later (72 bytes)
        *runs = rd32(d + 4);
        *last = rd64(d + 60);
        return 1;
    }
    if (n == 16) {                      // Windows XP / 2003
        uint32_t c = rd32(d + 4);
        *runs = c >= 5 ? c - 5 : 0;
        *last = rd64(d + 8);
        return 1;
    }
    return 0;
}

// ---- MRU lists ------------------------------------------------------------------

size_t mrulistex_order(const unsigned char *d, size_t n, uint32_t *out, size_t max)
{
    size_t k = 0;
    for (size_t i = 0; i + 4 <= n && k < max; i += 4) {
        uint32_t v = rd32(d + i);
        if (v == 0xFFFFFFFFu) break;
        out[k++] = v;
    }
    return k;
}

void runmru_clean(char *s)
{
    size_t L = strlen(s);
    if (L >= 2 && s[L - 2] == '\\' && s[L - 1] == '1') {
        s[L - 2] = '\0';
    }
}

int recentdocs_name(const unsigned char *d, size_t n, char *out, size_t outn)
{
    out[0] = '\0';
    for (size_t i = 0; i + 1 < n; i += 2) {
        if (d[i] == 0 && d[i + 1] == 0) {
            u16_to_u8(d, i / 2, out, outn);
            return 1;
        }
    }
    return 0;
}
