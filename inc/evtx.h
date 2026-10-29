#ifndef WINSPECT_EVTX_H
#define WINSPECT_EVTX_H

// Portable reader for Windows XML event log FILES (.evtx), so `events` can
// read logs copied off another machine. Layout (public format notes, e.g.
// libyal's "Windows XML Event Log (EVTX)" document; no code reused):
//   file header (4096 bytes): "ElfFile\0", chunk count @42, ...
//   chunks of 65536 bytes: "ElfChnk\0", string table @128 (64 x u32),
//     template table @384 (32 x u32), records from offset 512
//   record: u32 0x00002a2a | u32 size | u64 record id | FILETIME written |
//     binary XML | u32 size again
//   binary XML: a token stream (element start / attribute / value / end,
//     template instances with an array of typed substitution values). Names
//     and template definitions are stored once per chunk and referenced by
//     chunk-relative offset; the first use stores them inline.
// Each record is rendered to the same XML text EvtRender produces, so the
// existing evt_* field helpers (artparse.c) work on offline logs unchanged.
// Every offset, size and count is checked against the chunk; nesting depth is
// limited. Portable C, no Windows API.

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const unsigned char *d;
    size_t n;
    unsigned chunks;            // chunks present in the file
    int dirty;                  // header flag 1: not closed cleanly
} evtx_file;

// Returns 0, or -1 when the buffer is not an EVTX file.
int evtx_open(evtx_file *f, const unsigned char *d, size_t n);

// Calls cb for every record, in file order. xml is NUL-terminated UTF-8 and
// valid only during the call. Returns the number of records rendered.
typedef void (*evtx_cb)(uint64_t record_id, uint64_t written, const char *xml, void *ctx);
unsigned long evtx_records(const evtx_file *f, evtx_cb cb, void *ctx);

// Renders one record's binary XML (at chunk offset `off`, `len` bytes) to
// out; used by the record loop and by tests. Returns 0 or -1.
int evtx_render(const unsigned char *chunk, size_t off, size_t len, char **out, size_t *outlen);

#endif
