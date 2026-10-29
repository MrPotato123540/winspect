// shellitem - Windows shell item parser, portable C (see shellitem.h)

#include "shellitem.h"

#include <stdio.h>
#include <string.h>

static uint32_t rd16(const unsigned char *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int dos_datetime_str(const unsigned char *p, char *out, size_t n)
{
    if (n) out[0] = '\0';
    uint32_t date = rd16(p), time = rd16(p + 2);
    if (date == 0 && time == 0) return 0;
    unsigned day = date & 31, mon = (date >> 5) & 15, year = 1980 + (date >> 9);
    unsigned sec = (time & 31) * 2, min = (time >> 5) & 63, hour = time >> 11;
    if (day < 1 || mon < 1 || mon > 12 || hour > 23 || min > 59 || sec > 59) return 0;
    snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", year, mon, day, hour, min, sec);
    return 1;
}

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

// Printable ASCII up to NUL inside [p, end).
static void ascii_at(const unsigned char *p, const unsigned char *end, char *out, size_t n)
{
    size_t o = 0;
    for (; p < end && *p && o + 1 < n; p++) out[o++] = (*p >= 0x20 && *p < 0x7F) ? (char)*p : '?';
    out[o] = '\0';
}

static void guid_str(const unsigned char *g, char *out, size_t n)
{
    snprintf(out, n, "{%08lX-%04lX-%04lX-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             (unsigned long)rd32(g), (unsigned long)rd16(g + 4), (unsigned long)rd16(g + 6),
             g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
}

// Shell folder CLSIDs that show up as root items (Microsoft's documented
// namespace CLSIDs, plus Dropbox seen in real ShellBags).
static const char *known_folder(const char *guid)
{
    static const char *const t[][2] = {
        { "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", "My Computer" },
        { "{208D2C60-3AEA-1069-A2D7-08002B30309D}", "My Network Places" },
        { "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}", "Network" },
        { "{645FF040-5081-101B-9F08-00AA002F954E}", "Recycle Bin" },
        { "{21EC2020-3AEA-1069-A2DD-08002B30309D}", "Control Panel" },
        { "{26EE0668-A00A-44D7-9371-BEB064C98683}", "Control Panel" },
        { "{59031A47-3F72-44A7-89C5-5595FE6B30EE}", "User Files" },
        { "{031E4825-7B94-4DC3-B131-E946B44C8DD5}", "Libraries" },
        { "{679F85CB-0220-4080-B29B-5540CC05AAB6}", "Quick access" },
        { "{018D5C66-4533-4307-9B53-224DE2ED1FE6}", "OneDrive" },
        { "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Desktop" },
        { "{D3162B92-9365-467A-956B-92703ACA08AF}", "Documents" },
        { "{088E3905-0323-4B02-9826-5D99428E115F}", "Downloads" },
        { "{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}", "Music" },
        { "{24AD3AD4-A569-4530-98E1-AB02F9417AA8}", "Pictures" },
        { "{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}", "Videos" },
        { "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}", "3D Objects" },
        { "{E31EA727-12ED-4702-820C-4B6445F28E1A}", "Dropbox" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        if (strcmp(t[i][0], guid) == 0) return t[i][1];
    }
    return NULL;
}

// Serialized property storage ([MS-PROPSTORE]): u32 size, "1SPS", format id,
// then values (u32 size - 0 ends -, u32 id, u8 reserved, u16 type, u16 pad,
// value). In the {B725F130-47EF-101A-A5F1-02608C9EEBAC} storage, id 10 is
// System.ItemNameDisplay - the name Explorer shows. A VT_LPWSTR (0x1F) value
// is u32 character count + UTF-16. Returns 1 when a name was found.
static int propstore_name(const unsigned char *d, size_t size, char *out, size_t n)
{
    static const unsigned char fmt[16] = { 0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10,
                                           0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC };
    for (size_t p = 4; p + 24 <= size; p++) {
        if (memcmp(d + p, "1SPS", 4) != 0 || memcmp(d + p + 4, fmt, 16) != 0) continue;
        size_t storage = rd32(d + p - 4);
        size_t end = (storage >= 24 && storage <= size - (p - 4)) ? p - 4 + storage : size;
        size_t q = p + 20;
        for (int guard = 0; guard < 64 && q + 9 <= end; guard++) {
            size_t vs = rd32(d + q);
            if (vs == 0 || vs > end - q) break;
            if (vs >= 17 && rd32(d + q + 4) == 10 && rd16(d + q + 9) == 0x1F) {
                size_t chars = rd32(d + q + 13);
                if (chars > 0 && 17 + chars * 2 <= vs) {
                    u16_to_u8(d + q + 17, chars, out, n);
                    if (out[0]) return 1;
                }
            }
            q += vs;
        }
    }
    return 0;
}

// Find a 0xBEEF0004 extension block inside [d+from, d+size) and read it.
static int beef0004(const unsigned char *d, size_t size, size_t from, shellitem *out)
{
    for (size_t p = from; p + 8 <= size; p++) {
        if (rd32(d + p + 4) != 0xBEEF0004u) continue;
        size_t bsize = rd16(d + p), ver = rd16(d + p + 2);
        if (bsize < 0x14 || bsize > size - p) continue;
        const unsigned char *b = d + p;
        dos_datetime_str(b + 8, out->created, sizeof out->created);
        dos_datetime_str(b + 12, out->accessed, sizeof out->accessed);
        size_t off = ver >= 9 ? 0x2E : ver == 8 ? 0x2A : ver == 7 ? 0x26 : 0x14;
        if (ver >= 7 && bsize >= 0x1C) {
            uint64_t ref = (uint64_t)rd32(b + 0x14) | ((uint64_t)rd16(b + 0x18) << 32);
            out->mft_entry = ref;
        }
        if (off + 2 <= bsize) {
            char longname[512];
            u16_to_u8(b + off, (bsize - off) / 2, longname, sizeof longname);
            if (longname[0]) snprintf(out->name, sizeof out->name, "%s", longname);
        }
        return 1;
    }
    return 0;
}

int shellitem_parse(const unsigned char *d, size_t n, shellitem *out)
{
    memset(out, 0, sizeof *out);
    if (n < 2) return -1;
    size_t size = rd16(d);
    if (size == 0) return 0;
    if (size < 3 || size > n) return -1;
    unsigned t = d[2];
    out->type = t;
    const unsigned char *end = d + size;
    char g[40];
    if (t == 0x1F) {
        out->kind = "Root Folder";
        if (size >= 10 && d[3] == 0x00 && rd32(d + 6) == 0x23A3DFD5u) {
            // Root item wrapping a property-store "delegate" view: the form
            // Explorer uses for search-results folders.
            snprintf(out->name, sizeof out->name, "Search Folder");
        } else if (size >= 20) {
            guid_str(d + 4, g, sizeof g);
            snprintf(out->guid, sizeof out->guid, "%s", g);
            const char *k = known_folder(g);
            snprintf(out->name, sizeof out->name, "%s", k ? k : g);
            if (k == NULL && d[3] == 0x00) {
                // Extended root item that carries a drive ("D:\") instead of a GUID.
                for (size_t p = 4; p + 3 <= size; p++) {
                    if (d[p] >= 'A' && d[p] <= 'Z' && d[p + 1] == ':' && d[p + 2] == '\\') {
                        snprintf(out->name, sizeof out->name, "%c:\\", d[p]);
                        out->kind = "Volume";
                        break;
                    }
                }
            }
        }
    } else if (t == 0x2E) {
        // Shell folder item with a GUID (This PC\Documents, Downloads, ...).
        out->kind = "Shell Folder";
        if (size >= 20) {
            guid_str(d + 4, g, sizeof g);
            snprintf(out->guid, sizeof out->guid, "%s", g);
            const char *k = known_folder(g);
            snprintf(out->name, sizeof out->name, "%s", k ? k : g);
        }
    } else if ((t & 0x70) == 0x20) {
        out->kind = "Volume";
        if (size > 3) ascii_at(d + 3, end, out->name, sizeof out->name);
    } else if ((t & 0x70) == 0x30) {
        out->kind = (t & 0x01) ? "Directory" : (t & 0x02) ? "File" : "File Entry";
        if (size >= 14) dos_datetime_str(d + 8, out->modified, sizeof out->modified);
        size_t p = 14;
        if (size > 14) {
            if (t & 0x04) {                                  // Unicode short name
                u16_to_u8(d + 14, (size - 14) / 2, out->name, sizeof out->name);
                p = 14 + 2 * (strlen(out->name) + 1);
            } else {
                ascii_at(d + 14, end, out->name, sizeof out->name);
                p = 14 + strlen(out->name) + 1;
                if (p & 1) p++;                              // padded to 16 bits
            }
        }
        snprintf(out->short_name, sizeof out->short_name, "%.259s", out->name);
        if (p < size) beef0004(d, size, p, out);
    } else if ((t & 0x70) == 0x40) {
        out->kind = "Network Location";
        if (size > 5) ascii_at(d + 5, end, out->name, sizeof out->name);
    } else if (t == 0x71) {
        out->kind = "Control Panel Item";
        if (size >= 30) {
            guid_str(d + 14, g, sizeof g);
            snprintf(out->name, sizeof out->name, "%s", g);
        }
    } else if (t == 0x74 && size > 12 && memcmp(d + 6, "CFSF", 4) == 0) {
        // "Delegate" item: CFSF, then an embedded file-entry item (its own u16
        // size first), then the delegate CLSIDs and the usual 0xBEEF0004 block
        // holding the long name and times.
        shellitem inner;
        int isz = shellitem_parse(d + 10, size - 10, &inner);
        if (isz > 0) {
            *out = inner;
            beef0004(d, size, 10 + (size_t)isz, out);
        } else {
            out->kind = "Delegate";
            beef0004(d, size, 3, out);
        }
        out->type = t;
        if (!out->name[0]) snprintf(out->name, sizeof out->name, "[type 0x74]");
    } else {
        out->kind = t == 0x61 ? "URI" : t == 0x00 ? "Property View" : "Other";
        if (!beef0004(d, size, 3, out) && !propstore_name(d, size, out->name, sizeof out->name))
            snprintf(out->name, sizeof out->name, "[type 0x%02X]", t);
    }
    return (int)size;
}
