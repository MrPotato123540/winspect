#ifndef WINSPECT_CFB_H
#define WINSPECT_CFB_H

// Minimal, read-only reader for the Compound File Binary format ([MS-CFB],
// "OLE structured storage") - the container used by Jump Lists
// (*.automaticDestinations-ms), old Office documents, MSI files and more.
// Portable C, no Windows headers, bounds-checked against hostile input
// (sector chains are capped at the number of sectors, so a loop in a FAT
// cannot hang the reader). Only stream reading is supported.

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const unsigned char *d;
    size_t n;
    unsigned sector_size, mini_size;
    uint32_t mini_cutoff;
    uint32_t *fat;          // sector allocation table (malloc'd)
    size_t nfat;
    uint32_t *minifat;      // mini sector allocation table (malloc'd)
    size_t nminifat;
    unsigned char *ministream;  // root entry's stream, holding the mini sectors
    size_t ministream_len;
    uint32_t dir_start;
} cfb_file;

// Returns 0 on success, -1 if not a compound file, -2 if malformed.
int cfb_open(cfb_file *f, const unsigned char *d, size_t n);
void cfb_close(cfb_file *f);

// Calls cb for every stream entry: its name (UTF-8) and contents (valid only
// during the call). Returns the number of streams visited, or -2 on error.
typedef void (*cfb_stream_cb)(const char *name, const unsigned char *data, size_t len, void *ctx);
int cfb_streams(const cfb_file *f, cfb_stream_cb cb, void *ctx);

#endif
