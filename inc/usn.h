#ifndef WINSPECT_USN_H
#define WINSPECT_USN_H

// Portable reader for the NTFS change journal ($Extend\$UsnJrnl:$J), from
// Microsoft's documented USN_RECORD_V2 / USN_RECORD_V3 structures:
//   u32 record length | u16 major | u16 minor |
//   v2: u64 file reference | u64 parent reference
//   v3: 128-bit file id     | 128-bit parent file id
//   i64 USN | FILETIME | u32 reason | u32 source info | u32 security id |
//   u32 file attributes | u16 name length (bytes) | u16 name offset | name (UTF-16)
// A copied $J is mostly a sparse run of zeros before the live records; zero
// stretches are skipped. Records are 8-byte aligned. Portable C.

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t usn, time;         // FILETIME
    uint64_t file_ref, parent_ref;   // v3: the low 64 bits of the 128-bit ids
    uint32_t reason, attributes;
    int major;
    char name[1024];            // UTF-8
} usn_rec;

// Next record at or after *off; advances *off past it. Returns 1, or 0 at the end.
int usn_next(const unsigned char *d, size_t n, size_t *off, usn_rec *r);

// "FILE_CREATE|CLOSE" style names of the reason bits.
void usn_reason_str(uint32_t reason, char *out, size_t n);

// Reason to look at a record, or NULL: a program or script deleted
// (FILE_DELETE), or a file renamed INTO a program / script name from a name
// that was not one (old_name: the RENAME_OLD_NAME of the same file, or NULL).
// is_program tells whether a name is a program / script (artparse's list).
const char *usn_flag(uint32_t reason, const char *name, const char *old_name, int (*is_program)(const char *));

// 1 if name is the one NTFS gives a file deleted while other handles were
// still open (POSIX delete semantics, Windows 10 1709 and later): the file is
// moved into the hidden \$Extend\$Deleted folder and renamed to 24 hex
// digits whose first 16 are its own file reference (sequence, then record
// number), e.g. "0072000000020F0F66AEDC71" for record 134927 sequence 114.
// It disappears for good when the last handle closes.
int usn_posix_deleted_name(const char *name, uint64_t file_ref);

#endif
