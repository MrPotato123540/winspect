// pfparse - Windows Prefetch (SCCA) header parser, portable C
//
// A prefetch file starts with an 84-byte header:
//   0  u32 format version         4  "SCCA" signature
//   12 u32 file size              16 executable name, UTF-16LE, 60 bytes
//   76 u32 prefetch hash
// followed by a "file information" block whose layout depends on the version.
// The fields we want (run count, last run time(s)) sit at fixed offsets:
//   v17  last run @120 (1 time)   run count @144
//   v23  last run @128 (1 time)   run count @152
//   v26  last runs @128 (8 times) run count @208
//   v30/31 last runs @128 (8)     run count @208, or @200 in the shorter
//        variant - told apart by the first field of the block (the offset of
//        the metrics array: 0x130 for the long form, 0x128 for the short one).
// All integers are little-endian; we read byte-by-byte so the code is correct
// on any host and never does an unaligned load.

#include "pfparse.h"

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

// UTF-16LE (up to nchars units, stops at NUL) -> UTF-8. Unpaired surrogates
// become '?'. Always NUL-terminates out.
static void utf16le_to_utf8(const unsigned char *s, size_t nchars, char *out, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < nchars; i++) {
        uint32_t c = (uint32_t)s[2 * i] | ((uint32_t)s[2 * i + 1] << 8);
        if (c == 0) {
            break;
        }
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
        unsigned char buf[4] = { 0, 0, 0, 0 };
        size_t len;
        if (c < 0x80)       { buf[0] = (unsigned char)c; len = 1; }
        else if (c < 0x800) { buf[0] = (unsigned char)(0xC0 | (c >> 6));
                              buf[1] = (unsigned char)(0x80 | (c & 0x3F)); len = 2; }
        else if (c < 0x10000) { buf[0] = (unsigned char)(0xE0 | (c >> 12));
                                buf[1] = (unsigned char)(0x80 | ((c >> 6) & 0x3F));
                                buf[2] = (unsigned char)(0x80 | (c & 0x3F)); len = 3; }
        else { buf[0] = (unsigned char)(0xF0 | (c >> 18));
               buf[1] = (unsigned char)(0x80 | ((c >> 12) & 0x3F));
               buf[2] = (unsigned char)(0x80 | ((c >> 6) & 0x3F));
               buf[3] = (unsigned char)(0x80 | (c & 0x3F)); len = 4; }
        if (o + len + 1 > n) {
            break;
        }
        memcpy(out + o, buf, len);
        o += len;
    }
    out[o] = '\0';
}

int pf_parse(const unsigned char *d, size_t n, pf_info *out)
{
    memset(out, 0, sizeof *out);
    if (n < 84 || memcmp(d + 4, "SCCA", 4) != 0) {
        return -1;
    }
    out->version = rd32(d);
    utf16le_to_utf8(d + 16, 30, out->exe, sizeof out->exe);
    out->hash = rd32(d + 76);

    size_t times_off, nslots, count_off;
    switch (out->version) {
    case 17: times_off = 120; nslots = 1; count_off = 144; break;
    case 23: times_off = 128; nslots = 1; count_off = 152; break;
    case 26: times_off = 128; nslots = 8; count_off = 208; break;
    case 30:
    case 31:
        times_off = 128; nslots = 8;
        // First field of the file-info block = metrics array offset.
        count_off = (rd32(d + 84) == 0x128) ? 200 : 208;
        break;
    default:
        return -2;
    }
    if (count_off + 4 > n || times_off + nslots * 8 > n) {
        return -2;
    }
    out->run_count = rd32(d + count_off);
    for (size_t i = 0; i < nslots; i++) {
        uint64_t t = rd64(d + times_off + i * 8);
        if (t != 0) {
            out->times[out->ntimes++] = t;
        }
    }
    return 0;
}

// The file-information block (right after the 84-byte header) begins with the
// same table of section pointers in every version:
//   +16 filename strings offset   +20 filename strings size (bytes)
//   +24 volumes info offset       +28 number of volumes   +32 volumes info size
// Offsets are from the start of the file. Volume entries are 40 bytes (v17),
// 104 (v23/26) or 96 (v30/31); each starts with the device-path offset
// (relative to the volumes section) and length in characters, then the volume
// creation FILETIME at +8 and serial number at +16.

int pf_filenames(const unsigned char *d, size_t n, pf_name_cb cb, void *ctx)
{
    if (n < 120) {
        return -1;
    }
    size_t off = rd32(d + 100), size = rd32(d + 104);
    if (off > n || size > n - off) {
        return -1;
    }
    int count = 0;
    size_t i = 0;
    while (i + 2 <= size) {
        // Find the end of this UTF-16 string (a 0x0000 unit) within the section.
        size_t j = i;
        while (j + 2 <= size && (d[off + j] | d[off + j + 1]) != 0) {
            j += 2;
        }
        if (j > i) {
            char name[1024];
            utf16le_to_utf8(d + off + i, (j - i) / 2, name, sizeof name);
            cb(name, ctx);
            count++;
        }
        i = j + 2;
    }
    return count;
}

struct exe_find { const char *exe; size_t elen; char *out; size_t outn; int found; };

static int pf_ieq_n(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char x = a[i], y = b[i];
        if (x >= 'a' && x <= 'z') x = (char)(x - 32);
        if (y >= 'a' && y <= 'z') y = (char)(y - 32);
        if (x != y) return 0;
        if (x == '\0') return 1;
    }
    return 1;
}

static void exe_cb(const char *name, void *vctx)
{
    struct exe_find *f = (struct exe_find *)vctx;
    if (f->found) return;
    const char *base = strrchr(name, '\\');
    base = base ? base + 1 : name;
    size_t bl = strlen(base);
    // Exact match, or a prefix match when the stored name was cut at 29 chars.
    if ((bl == f->elen && pf_ieq_n(base, f->exe, bl)) ||
        (f->elen == 29 && bl > 29 && pf_ieq_n(base, f->exe, 29))) {
        size_t L = strlen(name);
        if (L < f->outn) {
            memcpy(f->out, name, L + 1);
            f->found = 1;
        }
    }
}

int pf_exe_path(const unsigned char *d, size_t n, const char *exe, char *out, size_t outn)
{
    if (outn == 0) return 0;
    out[0] = '\0';
    struct exe_find f = { exe, strlen(exe), out, outn, 0 };
    if (f.elen == 0) return 0;
    pf_filenames(d, n, exe_cb, &f);
    return f.found;
}

int pf_volumes(const unsigned char *d, size_t n, pf_vol_cb cb, void *ctx)
{
    if (n < 120) {
        return -1;
    }
    uint32_t ver = rd32(d);
    size_t esize = (ver == 17) ? 40 : (ver == 23 || ver == 26) ? 104 : 96;
    size_t off = rd32(d + 108), count = rd32(d + 112), size = rd32(d + 116);
    if (off > n || size > n - off || count > 64 || count * esize > size) {
        return -1;
    }
    for (size_t v = 0; v < count; v++) {
        const unsigned char *e = d + off + v * esize;
        size_t poff = rd32(e), plen = rd32(e + 4);
        char dev[512] = "";
        if (poff < size && plen * 2 <= size - poff) {
            utf16le_to_utf8(d + off + poff, plen, dev, sizeof dev);
        }
        cb(dev, rd32(e + 16), rd64(e + 8), ctx);
    }
    return (int)count;
}

int pf_mam_header(const unsigned char *d, size_t n, unsigned *format,
                  uint32_t *usize, size_t *payload_off)
{
    if (n < 8 || d[0] != 'M' || d[1] != 'A' || d[2] != 'M') {
        return 0;
    }
    // Byte 3: low nibble = compression format (4 = XPRESS Huffman); a set high
    // bit means a 4-byte CRC32 follows the size, pushing the payload to 12.
    *format = d[3] & 0x0F;
    *usize = rd32(d + 4);
    *payload_off = (d[3] & 0x80) ? 12 : 8;
    return *payload_off <= n;
}
