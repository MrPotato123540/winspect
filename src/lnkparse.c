// lnkparse - Shell Link (.lnk) parser per [MS-SHLLINK], portable C
//
// Layout, in order (each part optional except the header, per LinkFlags):
//   ShellLinkHeader (0x4C bytes)
//     0x00 HeaderSize = 0x4C   0x04 LinkCLSID {00021401-0000-0000-C000-000000000046}
//     0x14 LinkFlags           0x18 FileAttributes
//     0x1C CreationTime  0x24 AccessTime  0x2C WriteTime   0x34 FileSize
//   LinkTargetIDList  if HasLinkTargetIDList (0x01): u16 size + shell item IDs
//   LinkInfo          if HasLinkInfo (0x02): u32 size, u32 header size, u32 flags,
//                     VolumeID / LocalBasePath / network / CommonPathSuffix
//                     offsets (relative to LinkInfo); Unicode variants when the
//                     header size is >= 0x24
//   StringData        each present string is u16 character count + chars,
//                     UTF-16 if IsUnicode (0x80) else ANSI, in this order:
//                     NAME (0x04), RELATIVE_PATH (0x08), WORKING_DIR (0x10),
//                     COMMAND_LINE_ARGUMENTS (0x20), ICON_LOCATION (0x40)
//   ExtraData         blocks of u32 size + u32 signature, ended by size < 4:
//                     0xA0000001 EnvironmentVariableDataBlock (ANSI 260 + UTF-16 520)
//                     0xA0000003 TrackerDataBlock: MachineID (16 ANSI) @+16,
//                       Droid = volume GUID @+32, file GUID @+48. The file GUID
//                       is a version-1 UUID, whose last 6 bytes are the MAC
//                       address of the creating machine (RFC 4122 "node").
// Every offset and count is bounds-checked: .lnk files arrive from untrusted
// places (USB sticks, mail), so a crafted one must never read out of bounds.

#include "lnkparse.h"

#include <stdio.h>
#include <string.h>

#define LF_HAS_IDLIST   0x00000001u
#define LF_HAS_LINKINFO 0x00000002u
#define LF_HAS_NAME     0x00000004u
#define LF_HAS_RELPATH  0x00000008u
#define LF_HAS_WORKDIR  0x00000010u
#define LF_HAS_ARGS     0x00000020u
#define LF_HAS_ICON     0x00000040u
#define LF_UNICODE      0x00000080u

static const unsigned char LNK_CLSID[16] = {
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

static uint32_t rd16(const unsigned char *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const unsigned char *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

// UTF-16LE (nchars units, stops at NUL) -> UTF-8.
static void u16_to_u8(const unsigned char *s, size_t nchars, char *out, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < nchars; i++) {
        uint32_t c = rd16(s + 2 * i);
        if (c == 0) break;
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < nchars) {
            uint32_t lo = rd16(s + 2 * i + 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) { c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); i++; }
            else c = '?';
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            c = '?';
        }
        unsigned char b[4] = { 0, 0, 0, 0 }; size_t len;
        if (c < 0x80)         { b[0] = (unsigned char)c; len = 1; }
        else if (c < 0x800)   { b[0] = (unsigned char)(0xC0 | (c >> 6)); b[1] = (unsigned char)(0x80 | (c & 0x3F)); len = 2; }
        else if (c < 0x10000) { b[0] = (unsigned char)(0xE0 | (c >> 12)); b[1] = (unsigned char)(0x80 | ((c >> 6) & 0x3F));
                                b[2] = (unsigned char)(0x80 | (c & 0x3F)); len = 3; }
        else                  { b[0] = (unsigned char)(0xF0 | (c >> 18)); b[1] = (unsigned char)(0x80 | ((c >> 12) & 0x3F));
                                b[2] = (unsigned char)(0x80 | ((c >> 6) & 0x3F)); b[3] = (unsigned char)(0x80 | (c & 0x3F)); len = 4; }
        if (o + len + 1 > n) break;
        memcpy(out + o, b, len);
        o += len;
    }
    out[o] = '\0';
}

// ANSI (code-page) bytes are copied as-is up to NUL / limit; non-ASCII bytes
// become '?' so the output is always valid UTF-8.
static void ansi_copy(const unsigned char *s, size_t max, char *out, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < max && s[i] != 0 && o + 1 < n; i++) {
        out[o++] = (s[i] < 0x80) ? (char)s[i] : '?';
    }
    out[o] = '\0';
}

// NUL-terminated ANSI string inside [base, end).
static void ansi_at(const unsigned char *d, size_t start, size_t end, char *out, size_t n)
{
    out[0] = '\0';
    if (start >= end) return;
    ansi_copy(d + start, end - start, out, n);
}

// NUL-terminated UTF-16 string inside [start, end).
static void u16_at(const unsigned char *d, size_t start, size_t end, char *out, size_t n)
{
    out[0] = '\0';
    if (start >= end) return;
    u16_to_u8(d + start, (end - start) / 2, out, n);
}

const char *lnk_anomaly_reason(uint32_t a)
{
    if (a & LNK_ANOM_OVERSIZED_STRING) return "string count > 260 hides the next field (crafted link)";
    if (a & LNK_ANOM_PADDING)          return "command line padded with blanks to hide it";
    return NULL;
}

const char *lnk_drive_type_name(uint32_t t)
{
    static const char *const names[] = { "unknown", "no root dir", "removable", "fixed",
                                         "network", "cdrom", "ramdisk" };
    return t < sizeof names / sizeof names[0] ? names[t] : "?";
}

// VolumeID at [v, li_end): size, drive type, serial, label (ANSI, or UTF-16
// when the label offset is 0x14 and a Unicode offset follows).
static void parse_volume(const unsigned char *d, size_t v, size_t li_end, lnk_info *out)
{
    if (v + 16 > li_end) return;
    size_t vsize = rd32(d + v);
    if (vsize < 16 || vsize > li_end - v) return;
    size_t vend = v + vsize;
    out->has_volume = 1;
    out->drive_type = rd32(d + v + 4);
    out->drive_serial = rd32(d + v + 8);
    size_t loff = rd32(d + v + 12);
    if (loff == 0x14) {
        if (vsize >= 0x14) {
            size_t uoff = rd32(d + v + 16);
            if (uoff >= 0x14 && uoff < vsize) u16_at(d, v + uoff, vend, out->volume_label, sizeof out->volume_label);
        }
    } else if (loff >= 16 && loff < vsize) {
        ansi_at(d, v + loff, vend, out->volume_label, sizeof out->volume_label);
    }
}

// CommonNetworkRelativeLink at [c, li_end): the share name (NetName).
static void parse_network(const unsigned char *d, size_t c, size_t li_end, lnk_info *out)
{
    if (c + 20 > li_end) return;
    size_t csize = rd32(d + c);
    if (csize < 20 || csize > li_end - c) return;
    size_t cend = c + csize;
    size_t noff = rd32(d + c + 8);
    if (noff > 0x14 && csize >= 0x1C) {
        size_t uoff = rd32(d + c + 20);
        if (uoff >= 0x1C && uoff < csize) u16_at(d, c + uoff, cend, out->net_share, sizeof out->net_share);
    }
    if (out->net_share[0] == '\0' && noff >= 20 && noff < csize) {
        ansi_at(d, c + noff, cend, out->net_share, sizeof out->net_share);
    }
}

static void parse_linkinfo(const unsigned char *d, size_t li, size_t li_end, lnk_info *out)
{
    size_t span = li_end - li;
    size_t hsize = rd32(d + li + 4);
    uint32_t liflags = rd32(d + li + 8);
    if (hsize < 0x1C || hsize > span) {
        return;
    }
    size_t vol_off = rd32(d + li + 12), net_off = rd32(d + li + 20);
    if ((liflags & 1) && vol_off >= hsize && vol_off < span) parse_volume(d, li + vol_off, li_end, out);
    if ((liflags & 2) && net_off >= hsize && net_off < span) parse_network(d, li + net_off, li_end, out);
    // Offsets are relative to LinkInfo; anything outside it is ignored (checked
    // against the span first, so li + off can never wrap around).
    size_t base_off = rd32(d + li + 16), suffix_off = rd32(d + li + 24);
    if (base_off >= span)   base_off = 0;
    if (suffix_off >= span) suffix_off = 0;
    char base[1024] = "", suffix[512] = "";
    // Prefer the Unicode fields when the header carries them (size >= 0x24).
    if (hsize >= 0x24) {
        size_t ubase = rd32(d + li + 0x1C), usuffix = rd32(d + li + 0x20);
        if ((liflags & 1) && ubase && ubase < span) u16_at(d, li + ubase, li_end, base, sizeof base);
        if (usuffix && usuffix < span)              u16_at(d, li + usuffix, li_end, suffix, sizeof suffix);
    }
    if (base[0] == '\0' && (liflags & 1) && base_off) {
        ansi_at(d, li + base_off, li_end, base, sizeof base);
    }
    if (suffix[0] == '\0' && suffix_off) {
        ansi_at(d, li + suffix_off, li_end, suffix, sizeof suffix);
    }
    // Full path = LocalBasePath + CommonPathSuffix (the suffix is usually empty).
    // A target on a network share has no local base path: NetName + "\" + suffix.
    if (base[0] == '\0' && out->net_share[0] != '\0') {
        size_t nl = strlen(out->net_share);
        if (nl + 2 <= sizeof base) {
            memcpy(base, out->net_share, nl + 1);
            if (suffix[0] != '\0' && base[nl - 1] != '\\') { base[nl] = '\\'; base[nl + 1] = '\0'; }
        }
    }
    size_t bl = strlen(base), sl = strlen(suffix);
    if (bl + sl + 1 <= sizeof out->target) {
        memcpy(out->target, base, bl);
        memcpy(out->target + bl, suffix, sl + 1);
    }
}

// Reads one StringData entry at *pos; advances *pos. Returns 0 or -2.
// limit260: NAME, RELATIVE_PATH and WORKING_DIR are read as at most 260
// characters whatever their count says, and the next string starts right
// after those 260 - the shell behaves this way, and crafted links abuse it:
// an inflated WORKING_DIR count hides the real COMMAND_LINE_ARGUMENTS from
// parsers that trust the count (seen in the wild; the LnkParse3 project's
// test corpus has such a sample). A count above 260 is reported as an anomaly.
static int string_data(const unsigned char *d, size_t n, size_t *pos, int unicode,
                       int limit260, char *out, size_t outn, lnk_info *li)
{
    if (*pos + 2 > n) return -2;
    size_t count = rd16(d + *pos);
    if (limit260 && count > 260) {
        count = 260;
        li->anomalies |= LNK_ANOM_OVERSIZED_STRING;
    }
    size_t bytes = unicode ? count * 2 : count;
    *pos += 2;
    if (bytes > n - *pos) return -2;
    if (unicode) u16_to_u8(d + *pos, count, out, outn);
    else         ansi_copy(d + *pos, count, out, outn);
    *pos += bytes;
    return 0;
}

// 1 if s contains a run of at least 32 blanks/control characters: padding
// that pushes the real command out of the Properties dialog's view.
static int padded(const char *s)
{
    int run = 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        run = (c == ' ' || c == '\t' || c == '\r' || c == '\n') ? run + 1 : 0;
        if (run >= 32) return 1;
    }
    return 0;
}

// ExtraData: walk the blocks; unknown ones are skipped by size. A malformed
// chain just ends the walk (everything before it is kept).
static void extra_data(const unsigned char *d, size_t n, size_t pos, lnk_info *out)
{
    static const char hex[] = "0123456789abcdef";
    while (pos + 8 <= n) {
        size_t bsize = rd32(d + pos);
        if (bsize < 8 || bsize > n - pos) break;
        uint32_t sig = rd32(d + pos + 4);
        if (sig == 0xA0000001u && bsize >= 0x314) {
            u16_at(d, pos + 268, pos + 268 + 520, out->env_target, sizeof out->env_target);
            if (out->env_target[0] == '\0') ansi_at(d, pos + 8, pos + 268, out->env_target, sizeof out->env_target);
        } else if (sig == 0xA0000003u && bsize >= 0x60) {
            ansi_at(d, pos + 16, pos + 32, out->machine_id, sizeof out->machine_id);
            const unsigned char *g = d + pos + 48;           // file droid GUID
            if ((rd16(g + 6) >> 12) == 1) {                  // version-1 (time + node) UUID
                for (int i = 0; i < 6; i++) {
                    out->mac[i * 3]     = hex[g[10 + i] >> 4];
                    out->mac[i * 3 + 1] = hex[g[10 + i] & 15];
                    out->mac[i * 3 + 2] = i < 5 ? ':' : '\0';
                }
            }
        }
        pos += bsize;
    }
}

int lnk_idlist_items(const unsigned char *d, size_t n, lnk_item_cb cb, void *ctx)
{
    size_t pos = 0;
    int count = 0;
    while (pos + 2 <= n) {
        shellitem it;
        int sz = shellitem_parse(d + pos, n - pos, &it);
        if (sz == 0) break;                 // terminating empty item
        if (sz < 0) return count ? count : -1;
        if (cb) cb(&it, ctx);
        count++;
        pos += (size_t)sz;
        if (count > 64) break;
    }
    return count;
}

// Path from the IDList: names joined with "\"; a root folder directly followed
// by a volume ("My Computer" then "C:\") is dropped so the result reads
// "C:\dir\file". Long names are used where the item carries one.
struct idpath { char *out; size_t n; int pending_root; char root[512]; int items; };
static void idpath_cb(const shellitem *it, void *vctx)
{
    struct idpath *p = (struct idpath *)vctx;
    p->items++;
    if (p->items == 1 && it->type == 0x1F) {
        p->pending_root = 1;
        snprintf(p->root, sizeof p->root, "%s", it->name);
        return;
    }
    if (p->pending_root) {
        p->pending_root = 0;
        if (strcmp(it->kind ? it->kind : "", "Volume") != 0) {
            size_t L = strlen(p->out);
            snprintf(p->out + L, p->n - L, "%s", p->root);
        }
    }
    size_t L = strlen(p->out);
    int sep = L > 0 && p->out[L - 1] != '\\';
    snprintf(p->out + L, p->n - L, "%s%s", sep ? "\\" : "", it->name);
}

int lnk_parse(const unsigned char *d, size_t n, lnk_info *out)
{
    memset(out, 0, sizeof *out);
    if (n < 0x4C || rd32(d) != 0x4C || memcmp(d + 4, LNK_CLSID, 16) != 0) {
        return -1;
    }
    out->flags = rd32(d + 0x14);
    out->attributes = rd32(d + 0x18);
    out->created = rd64(d + 0x1C);
    out->accessed = rd64(d + 0x24);
    out->written = rd64(d + 0x2C);
    out->file_size = rd32(d + 0x34);

    size_t pos = 0x4C;
    if (out->flags & LF_HAS_IDLIST) {
        if (pos + 2 > n) return -2;
        size_t idsize = rd16(d + pos);
        pos += 2;
        if (idsize > n - pos) return -2;
        struct idpath ip = { out->idlist_path, sizeof out->idlist_path, 0, "", 0 };
        out->idlist_items = lnk_idlist_items(d + pos, idsize, idpath_cb, &ip);
        if (ip.pending_root) snprintf(out->idlist_path, sizeof out->idlist_path, "%s", ip.root);
        pos += idsize;
    }
    if (out->flags & LF_HAS_LINKINFO) {
        if (pos + 4 > n) return -2;
        size_t lisize = rd32(d + pos);
        if (lisize < 0x1C || lisize > n - pos) return -2;
        parse_linkinfo(d, pos, pos + lisize, out);
        pos += lisize;
    }
    int uni = (out->flags & LF_UNICODE) != 0;
    if ((out->flags & LF_HAS_NAME)    && string_data(d, n, &pos, uni, 1, out->name, sizeof out->name, out)) return -2;
    if ((out->flags & LF_HAS_RELPATH) && string_data(d, n, &pos, uni, 1, out->relative, sizeof out->relative, out)) return -2;
    if ((out->flags & LF_HAS_WORKDIR) && string_data(d, n, &pos, uni, 1, out->workdir, sizeof out->workdir, out)) return -2;
    if ((out->flags & LF_HAS_ARGS)    && string_data(d, n, &pos, uni, 0, out->arguments, sizeof out->arguments, out)) return -2;
    if ((out->flags & LF_HAS_ICON)    && string_data(d, n, &pos, uni, 0, out->icon, sizeof out->icon, out)) return -2;
    if (padded(out->arguments) || padded(out->workdir)) out->anomalies |= LNK_ANOM_PADDING;

    extra_data(d, n, pos, out);

    // No LinkInfo path (e.g. links to shell namespaces or relative-only links):
    // fall back to the environment-variable target, then the relative path,
    // so callers still have something to show.
    const char *fb = out->env_target[0] ? out->env_target
                   : out->idlist_path[0] ? out->idlist_path : out->relative;
    if (out->target[0] == '\0' && fb[0] != '\0') {
        size_t L = strlen(fb);
        if (L < sizeof out->target) memcpy(out->target, fb, L + 1);
    }
    return 0;
}
