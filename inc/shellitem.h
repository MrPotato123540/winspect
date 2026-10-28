#ifndef WINSPECT_SHELLITEM_H
#define WINSPECT_SHELLITEM_H

// Portable parser for one Windows SHELL ITEM (an ItemID of a PIDL), the unit
// Explorer uses to describe "a thing in the namespace": the item lists stored
// in ShellBags (BagMRU), and inside .lnk files and jump lists. Each item
// starts with u16 size and a type byte. Handled (public format notes, e.g.
// libyal's "Windows Shell Item format"; no code reused):
//   0x1F        root folder      GUID @4 -> known shell folder name or "{GUID}"
//   0x20..0x2F  volume           "C:\" @3
//   0x30..0x3F  file entry       DOS modified time @8, short name @14, then an
//                                extension block 0xBEEF0004 with created /
//                                accessed DOS times and the LONG name (offset
//                                by block version: 3 -> 0x14, 7 -> 0x26,
//                                8 -> 0x2A, 9+ -> 0x2E)
//   0x40..0x4F  network location "\\server\share" @5
//   0x71        control panel item GUID @14
// Any other type (property-store "delegate" items, URIs, MTP devices, ...) is
// reported by type, with the long name of an embedded 0xBEEF0004 block when
// there is one. DOS date/times have 2-second resolution and no time zone
// (file-system UTC for NTFS). Everything is bounds-checked.

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *kind;           // "Root Folder", "Volume", "Directory", "File", ...
    unsigned type;              // the raw type byte
    char name[512];             // display name (UTF-8)
    char created[20], accessed[20], modified[20];   // "YYYY-MM-DD hh:mm:ss" or ""
    uint64_t mft_entry;         // NTFS file reference (entry part) from the ext block, 0 if none
} shellitem;

// Parses the item at d (n bytes available). Returns the item's size (>= 3),
// 0 for the terminating empty item, or -1 if malformed.
int shellitem_parse(const unsigned char *d, size_t n, shellitem *out);

// DOS (FAT) date + time, as stored in shell items (u16 date, then u16 time).
// Returns 1 and fills out ("YYYY-MM-DD hh:mm:ss") if valid and non-zero.
int dos_datetime_str(const unsigned char *p, char *out, size_t n);

#endif
