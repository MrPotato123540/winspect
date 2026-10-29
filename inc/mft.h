#ifndef WINSPECT_MFT_H
#define WINSPECT_MFT_H

// Portable reader for NTFS $MFT records (a copied $MFT file), written from
// public format notes (e.g. libyal's "New Technologies File System (NTFS)"
// document); no code reused.
//   record ("FILE", usually 1024 bytes): fixup array @4/@6 - the last two
//     bytes of every 512-byte sector are moved there and must be put back;
//     sequence @16, first attribute @20, flags @22 (1 in use, 2 directory),
//     base record @32 (non-zero: an extension of another record)
//   attribute: type @0, length @4, non-resident @8; resident content size
//     @16 / offset @20; non-resident real size @48
//   0x10 $STANDARD_INFORMATION: created, modified, MFT changed, accessed
//   0x30 $FILE_NAME: parent reference, the same four times, real size,
//        name length @64, namespace @65 (0 POSIX, 1 Win32, 2 DOS, 3 both), name
//   0x40 $OBJECT_ID: the file's Distributed Link Tracking id (a UUID; for
//        version 1 it carries a creation time and a MAC address)
// Every offset and length is checked against the record; nothing is trusted.

#include <stddef.h>
#include <stdint.h>

#define MFT_ROOT 5

typedef struct {
    uint32_t recno;
    uint16_t seq;
    int in_use, dir, extension, valid;
    uint64_t si[4];             // created, modified, MFT changed, accessed (FILETIME)
    int has_si;
    uint64_t fn[4];
    int has_fn;
    uint64_t parent;            // file reference: low 48 bits record, high 16 sequence
    char name[1024];            // UTF-8, the Win32 name when there is one
    int name_ns;
    uint64_t size;              // $DATA real size (or $FILE_NAME's)
    unsigned char objid[16];
    int has_objid;
} mft_entry;

// Parses one record (rec, n = record size, a modifiable copy: the fixups are
// applied in place). Returns 0, or -1 when it is not a valid FILE record.
int mft_parse(unsigned char *rec, size_t n, uint32_t recno, mft_entry *e);

// Record size declared by a record (allocated size @28), 0 if none.
size_t mft_record_size(const unsigned char *rec, size_t n);

// What path building needs per record, kept small so a table for millions
// of records fits in memory.
typedef struct {
    uint64_t parent;
    uint16_t seq;
    uint8_t valid, in_use, dir;
    const char *name;           // owned by the caller
} mft_node;

// Builds the path of entry i from a table of all entries (by record number):
// "\\dir\\...\\name". A parent counts while it is a directory with the
// referenced sequence number (or, once deleted, that number + 1, since NTFS
// bumps it when a record is freed); a chain that breaks - reused record, not
// a directory, a loop - is rooted at "$Orphan". Returns 0.
int mft_path(const mft_node *tab, size_t count, uint32_t i, char *out, size_t n);

// Timestomping HINT (shown, never flagged) from the two sets of times. $STANDARD_INFORMATION times
// can be set by any program (SetFileTime); $FILE_NAME times only by the
// kernel. A creation time in $SI that is clearly EARLIER than the one in $FN
// is the classic sign of a backdated file. Whole-second $SI times (no 100 ns
// fraction) while $FN has one strengthen it, but on their own are normal for
// files from archives / FAT media and are not flagged. NULL = nothing to say.
const char *mft_timestomp_reason(const uint64_t si[4], const uint64_t fn[4]);

#endif
