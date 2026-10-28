#ifndef WINSPECT_DESTLIST_H
#define WINSPECT_DESTLIST_H

// Portable parser for the "DestList" stream of an AutomaticDestinations jump
// list (the compound file under Recent\AutomaticDestinations). DestList is the
// jump list's index: one entry per item, in most-recently-used order, saying
// when the item was last used, whether it is pinned, how often it was used
// (Windows 10+) and which stream (hex entry number) holds its shell link.
// Layout (public format notes, e.g. libyal dtformats; no code reused):
//   header 32 bytes: u32 version (1 = Win7/8.x, 3/4 = Win10+), u32 entries,
//                    u32 pinned entries, ..., u32 last entry number @16
//   entry:  0 u64 checksum   8 GUID volume droid   24 GUID file droid
//          40 GUID birth volume droid   56 GUID birth file droid
//          72 char[16] NetBIOS host name   88 u32 entry number
//          96 f32 access count   100 FILETIME last used   108 i32 pin (-1 = not pinned)
//     v1:  112 u16 path length (chars), 114 UTF-16 path
//     v3+: 116 u32 interaction count, 128 u16 path length, 130 path, 4 bytes after
// Bounds-checked throughout; a malformed entry ends the walk.

#include <stddef.h>
#include <stdint.h>

typedef struct {
    unsigned mru;               // position in the list, 0 = most recent
    uint32_t entry;             // entry number = stream name in hex ("1a")
    uint64_t last_used;         // FILETIME
    int pinned;
    int has_interactions;       // 1 on version 3+ only
    uint32_t interactions;
    char host[17];              // NetBIOS name of the machine
    char mac[18];               // from the file droid (v1 UUID node), "" if not v1
    uint64_t droid_time;        // FILETIME from the file droid's v1 timestamp, 0 if none
    char path[1024];            // path or URL as recorded in DestList
} dl_entry;

typedef void (*dl_cb)(const dl_entry *e, void *ctx);

// Walk the entries. Returns how many were reported, or -1 if the header is
// missing/unknown. *version and *pinned_hdr receive the header values.
int destlist_parse(const unsigned char *d, size_t n, uint32_t *version, uint32_t *pinned_hdr,
                   dl_cb cb, void *ctx);

// A version-1 (time-based) UUID carries a 60-bit timestamp in 100 ns units
// since 1582-10-15 and the creating machine's MAC in its last 6 bytes. Given
// the 16 raw GUID bytes (as stored on disk, little-endian fields), return the
// timestamp as a FILETIME and fill mac ("aa:bb:..."); returns 0 / mac = ""
// if the GUID is not version 1.
uint64_t uuid1_info(const unsigned char g[16], char mac[18]);

#endif
