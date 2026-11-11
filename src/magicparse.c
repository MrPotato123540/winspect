// File type by content + name / content mismatch checks (see magicparse.h).
//
// The signature list is deliberately short: formats an investigator meets on
// a Windows machine and whose magic numbers are published in their own
// specifications. Anything else is "data" - saying "unknown" is better than
// guessing. The mismatch checks only ever fire on a positive identification.

#include "magicparse.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static uint16_t u16(const unsigned char *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t u32(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static int has(const unsigned char *d, size_t n, size_t off, const char *sig, size_t len)
{
    return off + len <= n && memcmp(d + off, sig, len) == 0;
}

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

// Case-insensitive search of an ASCII needle in the first `n` bytes.
static int text_has(const unsigned char *d, size_t n, const char *needle)
{
    size_t L = strlen(needle);
    for (size_t i = 0; i + L <= n; i++) {
        size_t k = 0;
        while (k < L && lower((char)d[i + k]) == needle[k]) k++;
        if (k == L) return 1;
    }
    return 0;
}

static const char *pe_kind(const unsigned char *d, size_t n)
{
    uint32_t lfa = u32(d + 0x3C);
    if (lfa > n || n - lfa < 24 + 70 || memcmp(d + lfa, "PE\0\0", 4) != 0) return "DOS executable (MZ)";
    uint16_t machine = u16(d + lfa + 4), chars = u16(d + lfa + 22);
    uint16_t subsystem = u16(d + lfa + 24 + 68);
    int x64 = machine == 0x8664, arm64 = machine == 0xAA64, x86 = machine == 0x014C;
    if (subsystem == 1) return x64 ? "PE driver (x64)" : arm64 ? "PE driver (ARM64)" : x86 ? "PE driver (x86)" : "PE driver";
    if (chars & 0x2000) return x64 ? "PE DLL (x64)" : arm64 ? "PE DLL (ARM64)" : x86 ? "PE DLL (x86)" : "PE DLL";
    return x64 ? "PE executable (x64)" : arm64 ? "PE executable (ARM64)" : x86 ? "PE executable (x86)" : "PE executable";
}

// A zip's first entry name tells the common containers apart.
static const char *zip_kind(const unsigned char *d, size_t n, const char **group)
{
    *group = "archive";
    if (n < 30) return "ZIP archive";
    size_t nl = u16(d + 26);
    const unsigned char *nm = d + 30;
    if (30 + nl > n) nl = n - 30;
#define FIRST(s) (nl >= sizeof(s) - 1 && memcmp(nm, s, sizeof(s) - 1) == 0)
    if (FIRST("[Content_Types].xml") || FIRST("_rels/") || FIRST("docProps/") || FIRST("word/") || FIRST("xl/") || FIRST("ppt/")) {
        *group = "document";
        return "Office Open XML document (docx / xlsx / pptx)";
    }
    if (FIRST("mimetype") && text_has(d, n < 200 ? n : 200, "opendocument")) { *group = "document"; return "OpenDocument file"; }
    if (FIRST("META-INF/")) return "Java archive (JAR)";
    if (FIRST("AndroidManifest.xml")) return "Android package (APK)";
#undef FIRST
    return "ZIP archive";
}

static const char *text_kind(const unsigned char *d, size_t n, const char **group)
{
    size_t look = n < 4096 ? n : 4096;
    if (look == 0) { *group = "data"; return "empty"; }
    if (look >= 2 && ((d[0] == 0xFF && d[1] == 0xFE) || (d[0] == 0xFE && d[1] == 0xFF))) { *group = "text"; return "text (UTF-16)"; }
    size_t odd = 0;
    for (size_t i = 0; i < look; i++) {
        unsigned char c = d[i];
        if (c == 0) { *group = "data"; return "data"; }
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != 0x0C && c != 0x1B) odd++;
    }
    if (odd * 50 > look) { *group = "data"; return "data"; }
    const unsigned char *s = d;
    size_t sl = look;
    if (sl >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF) { s += 3; sl -= 3; }
    while (sl && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) { s++; sl--; }
    *group = "script";
    if (text_has(d, look, "<hta:application")) return "HTML application (HTA)";
    if (sl >= 2 && s[0] == '#' && s[1] == '!') return "script (shebang)";
    if (sl >= 9 && text_has(s, 9, "@echo off")) return "batch script";
    *group = "text";
    if (sl >= 5 && memcmp(s, "<?xml", 5) == 0) return "XML text";
    if (sl >= 5 && (text_has(s, 14, "<!doctype html") || text_has(s, 5, "<html"))) return "HTML text";
    return "text";
}

const char *magic_sniff(const unsigned char *d, size_t n, const char **group)
{
    static const char *dummy;
    if (group == NULL) group = &dummy;
    *group = "data";
#define SIG(off, s) has(d, n, off, s, sizeof(s) - 1)
    if (n >= 0x40 && d[0] == 'M' && d[1] == 'Z') { *group = "program"; return pe_kind(d, n); }
    if (SIG(0, "\x7F" "ELF")) { *group = "program"; return "ELF executable"; }
    if (n >= 4 && (u32(d) == 0xFEEDFACEu || u32(d) == 0xFEEDFACFu)) { *group = "program"; return "Mach-O executable"; }
    if (SIG(0, "PK\x03\x04")) return zip_kind(d, n, group);
    if (SIG(0, "PK\x05\x06")) { *group = "archive"; return "ZIP archive (empty)"; }
    if (SIG(0, "Rar!\x1A\x07")) { *group = "archive"; return "RAR archive"; }
    if (SIG(0, "7z\xBC\xAF\x27\x1C")) { *group = "archive"; return "7-Zip archive"; }
    if (SIG(0, "MSCF")) { *group = "archive"; return "Microsoft Cabinet (CAB)"; }
    if (SIG(0, "\x1F\x8B\x08")) { *group = "archive"; return "gzip data"; }
    if (SIG(0, "BZh")) { *group = "archive"; return "bzip2 data"; }
    if (SIG(0, "\xFD" "7zXZ\x00")) { *group = "archive"; return "xz data"; }
    if (SIG(0, "MSWIM\0\0\0")) { *group = "archive"; return "Windows Imaging file (WIM)"; }
    if (SIG(0, "vhdxfile")) { *group = "archive"; return "virtual disk (VHDX)"; }
    if (SIG(0, "conectix")) { *group = "archive"; return "virtual disk (VHD)"; }
    if (SIG(0x8001, "CD001")) { *group = "archive"; return "ISO 9660 disc image"; }
    if (SIG(0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) { *group = "document"; return "OLE2 compound file (legacy Office document / MSI)"; }
    if (SIG(0, "%PDF-")) { *group = "document"; return "PDF document"; }
    if (SIG(0, "{\\rtf")) { *group = "document"; return "Rich Text Format document"; }
    if (SIG(0, "\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3")) { *group = "document"; return "OneNote section"; }
    if (SIG(0, "ITSF")) { *group = "document"; return "compiled HTML help (CHM)"; }
    if (SIG(0, "\x4C\x00\x00\x00\x01\x14\x02\x00")) { *group = "shortcut"; return "Windows shortcut (LNK)"; }
    if (SIG(0, "\x89PNG\r\n\x1A\n")) { *group = "image"; return "PNG image"; }
    if (SIG(0, "\xFF\xD8\xFF")) { *group = "image"; return "JPEG image"; }
    if (SIG(0, "GIF87a") || SIG(0, "GIF89a")) { *group = "image"; return "GIF image"; }
    if (n >= 14 && d[0] == 'B' && d[1] == 'M' && u32(d + 6) == 0 && u32(d + 10) >= 14 && u32(d + 10) < 2048) { *group = "image"; return "BMP image"; }
    if (SIG(0, "II*\x00") || SIG(0, "MM\x00*")) { *group = "image"; return "TIFF image"; }
    if (SIG(0, "RIFF") && n >= 12) {
        if (memcmp(d + 8, "WEBP", 4) == 0) { *group = "image"; return "WebP image"; }
        *group = "media";
        return memcmp(d + 8, "WAVE", 4) == 0 ? "WAV audio" : memcmp(d + 8, "AVI ", 4) == 0 ? "AVI video" : "RIFF container";
    }
    if (SIG(4, "ftyp")) { *group = "media"; return "MP4 / ISO media"; }
    if (SIG(0, "ID3") || (n >= 2 && d[0] == 0xFF && (d[1] & 0xE6) == 0xE2)) { *group = "media"; return "MP3 audio"; }
    if (SIG(0, "OggS")) { *group = "media"; return "Ogg media"; }
    if (SIG(0, "\x1A\x45\xDF\xA3")) { *group = "media"; return "Matroska / WebM media"; }
    if (SIG(0, "ElfFile\0")) { *group = "system"; return "Windows event log (EVTX)"; }
    if (SIG(0, "regf")) { *group = "system"; return "registry hive"; }
    if (SIG(0, "SQLite format 3\0")) { *group = "system"; return "SQLite database"; }
    if (SIG(4, "SCCA") || SIG(0, "MAM\x04")) { *group = "system"; return "Prefetch file"; }
    if (SIG(4, "\xEF\xCD\xAB\x89")) { *group = "system"; return "ESE database"; }
    if (SIG(0, "MDMP")) { *group = "system"; return "minidump"; }
    if (SIG(0, "PAGEDU")) { *group = "system"; return "kernel memory dump"; }
    if (SIG(0, "\xCA\xFE\xBA\xBE")) { *group = "program"; return "Java class / Mach-O universal binary"; }
#undef SIG
    return text_kind(d, n, group);
}

static const char *ext_of(const char *name, size_t len)
{
    for (size_t i = len; i > 0; i--) {
        if (name[i - 1] == '.') return name + i;
        if (name[i - 1] == '\\' || name[i - 1] == '/') break;
    }
    return "";
}

static int in_list(const char *ext, size_t el, const char *const *list)
{
    for (; *list; list++) {
        size_t k = 0;
        while (k < el && (*list)[k] && lower(ext[k]) == (*list)[k]) k++;
        if (k == el && (*list)[k] == '\0') return 1;
    }
    return 0;
}

// Extensions a user reads as "this is a picture / document / recording".
static const char *const data_exts[] = {
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "ico", "svg",
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "odt", "ods",
    "txt", "log", "csv", "xml", "json", "ini", "htm", "html", "md",
    "mp3", "mp4", "avi", "mkv", "mov", "wav", "wmv", "flac",
    "zip", "rar", "7z", "iso", NULL };
// Extensions Windows runs when double-clicked.
static const char *const run_exts[] = {
    "exe", "scr", "com", "pif", "cpl", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "hta", "msi", "lnk", "jar", "dll", NULL };

const char *magic_name_reason(const char *name, const char *group)
{
    size_t len = strlen(name);
    // U+202E RIGHT-TO-LEFT OVERRIDE in UTF-8.
    if (strstr(name, "\xE2\x80\xAE") != NULL) return "right-to-left override character in the name (displayed extension is reversed)";
    const char *ext = ext_of(name, len);
    size_t el = strlen(ext);
    if (el == 0) return NULL;
    size_t stem = (size_t)(ext - name) - 1;          // length before the last dot
    // "invoice.pdf           .exe": the real extension is pushed off screen.
    size_t spaces = 0;
    for (size_t i = stem; i > 0 && name[i - 1] == ' '; i--) spaces++;
    if (spaces >= 8 && in_list(ext, el, run_exts)) return "long run of spaces hides the real extension";
    if (in_list(ext, el, run_exts)) {
        size_t inner_end = stem - spaces;
        const char *inner = ext_of(name, inner_end);
        size_t il = inner_end - (size_t)(inner - name);
        if (inner[0] && inner != name && il && il <= 5 && in_list(inner, il, data_exts))
            return "double extension: a document-like name that is really a program / script";
    }
    if (group != NULL && strcmp(group, "program") == 0 && in_list(ext, el, data_exts))
        return "program content behind a picture / document / media extension";
    return NULL;
}
