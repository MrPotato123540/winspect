#ifndef WINSPECT_PFPARSE_H
#define WINSPECT_PFPARSE_H

// Portable (no Windows headers) parser for the Windows Prefetch "SCCA" format,
// so it can be unit-tested on any OS. The Windows-only part - reading the .pf
// file and undoing the MAM (XPRESS Huffman) compression - lives in prefetch.c.
// Layout knowledge is from the public libscca format documentation (concepts
// only, no code taken).

#include <stddef.h>
#include <stdint.h>

#define PF_MAX_TIMES 8

typedef struct {
    uint32_t version;               // 17 (XP), 23 (Vista/7), 26 (8.1), 30/31 (10/11)
    char     exe[128];              // executable name, UTF-8
    uint32_t hash;                  // path hash that also appears in the file name
    uint32_t run_count;
    int      ntimes;                // how many of times[] are valid (non-zero)
    uint64_t times[PF_MAX_TIMES];   // FILETIMEs, most recent first
} pf_info;

// Parse a decompressed SCCA buffer. Returns 0 on success, -1 if it is not an
// SCCA file, -2 if the version is unknown or the buffer is too short.
int pf_parse(const unsigned char *d, size_t n, pf_info *out);

// Walk the referenced-file list (NUL-separated UTF-16 strings in the
// "filename strings" section). Calls cb once per name (UTF-8). Returns how many
// names were reported, or -1 if the section lies outside the buffer.
typedef void (*pf_name_cb)(const char *name, void *ctx);
int pf_filenames(const unsigned char *d, size_t n, pf_name_cb cb, void *ctx);

// Full path of the executable itself: the referenced file whose last path
// component equals info->exe (case-insensitive; the header keeps at most 29
// characters of the name, so a 29-character exe matches as a prefix). Paths
// are in device form ("\VOLUME{01d...}\USERS\BOB\DOWNLOADS\X.EXE"). Returns 1
// and fills out when found, else 0 with out = "". (PECmd shows the same.)
int pf_exe_path(const unsigned char *d, size_t n, const char *exe, char *out, size_t outn);

// Walk the volume list: device path (UTF-8), volume serial and creation
// FILETIME for each volume the program touched. Returns the count or -1.
typedef void (*pf_vol_cb)(const char *device, uint32_t serial, uint64_t created, void *ctx);
int pf_volumes(const unsigned char *d, size_t n, pf_vol_cb cb, void *ctx);

// If the buffer starts with a Windows 10+ "MAM" compression header, return 1
// and report the compression format, the uncompressed size and where the
// compressed payload begins. Returns 0 if it is not MAM-compressed.
int pf_mam_header(const unsigned char *d, size_t n, unsigned *format,
                  uint32_t *usize, size_t *payload_off);

#endif
