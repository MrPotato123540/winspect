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
// Record size of a whole $MFT copy: from the first FILE record within its
// first 64 KiB (a damaged record 0 does not hide the rest). 0 if none.
size_t mft_file_record_size(const unsigned char *d, size_t n);

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

// ---- reading the live volume -----------------------------------------------
// NTFS boot sector: bytes per sector @11, sectors per cluster @13 (a value
// above 0x80 means 2^(256 - v)), MFT start cluster @48, clusters per file
// record @64 (negative: 2^-v bytes). Returns 0 or -1 when not NTFS.
typedef struct { uint32_t bytes_per_sector, cluster_size, record_size; uint64_t mft_lcn; } ntfs_boot;
int ntfs_parse_boot(const unsigned char *b, size_t n, ntfs_boot *nb);

// The extents of a record's unnamed non-resident $DATA attribute (for record
// 0: where the $MFT itself lies). Run list: per run a header byte (low nibble
// = size of the length field, high nibble = size of the signed, relative
// offset field; 0 offset size = sparse), terminated by 0. rec must already
// have its fixups applied (mft_parse does that). Returns the number of runs
// (lcn -1 = sparse) and the attribute's real size, or -1.
typedef struct { int64_t lcn; uint64_t clusters; } mft_run;
int mft_data_runs(const unsigned char *rec, size_t n, mft_run *runs, int max, uint64_t *real_size);

// The same for any unnamed non-resident attribute type; *start_vcn (may be
// NULL) receives the first VCN this piece covers (non-zero in an extension
// record that continues an attribute).
int mft_attr_runs(const unsigned char *rec, size_t n, uint32_t type, mft_run *runs, int max,
                  uint64_t *real_size, uint64_t *start_vcn);

// Content of an unnamed RESIDENT attribute: 0 and a pointer into rec, 1 when
// the attribute exists but is non-resident (use mft_attr_runs), -1 if absent.
int mft_attr_resident(const unsigned char *rec, size_t n, uint32_t type, const unsigned char **content, size_t *clen);

// $ATTRIBUTE_LIST (0x20): when a file's attributes no longer fit in its
// record they continue in extension records and this list says where. A
// heavily fragmented $MFT is exactly that case: record 0 holds only the first
// part of the run list. Entry: type @0, entry length @4, name length @6,
// starting VCN @8, file reference of the record holding it @16.
// Collects the unnamed $DATA pieces stored in records OTHER than self, sorted
// by starting VCN. Returns how many exist (can exceed max).
typedef struct { uint64_t start_vcn, recno; } mft_ext;
int mft_alist_data(const unsigned char *list, size_t n, uint64_t self, mft_ext *out, int max);

#endif
