#ifndef WINSPECT_REGF_H
#define WINSPECT_REGF_H

// Portable reader for registry hive FILES ("regf" format): NTUSER.DAT,
// UsrClass.dat, SYSTEM, SOFTWARE, SAM, Amcache.hve ... as copied off a
// machine or collected by a triage tool. It lets winspect answer the
// per-user questions (UserAssist, RunMRU, ...) for OTHER users and for hives
// that are not loaded at all - without touching the live registry.
// Layout (public format notes, e.g. libyal's "Windows NT Registry File"
// document; no code reused):
//   base block (4096 bytes): "regf", primary/secondary sequence @4/@8,
//     last written FILETIME @12, major/minor version @20/@24, root cell @36,
//     hive bins size @40, file name (UTF-16, 64 bytes) @48, checksum @508
//   hive bins ("hbin") follow; a CELL OFFSET is relative to the first bin
//   (file offset 4096). A cell = i32 size (negative = in use) + data.
//   nk (key):   flags @2, last written @4, subkey count @20, subkey list @28,
//               value count @36, value list @40, name length @72, name @76
//               (flag 0x20: name is Latin-1, else UTF-16)
//   lf/lh/li/ri: subkey index lists (ri = list of lists)
//   vk (value): name length @2, data size @4 (bit 31: data stored inline in
//               the offset field), data offset @8, type @12, flags @16
//               (bit 0: Latin-1 name), name @20
//   db:         "big data" (> 16344 bytes): segment list of data cells
// Every offset, size and count is checked against the file; index lists are
// walked with a depth limit, so a crafted hive cannot loop or read out of
// bounds. Transaction logs (.LOG1/.LOG2) are NOT replayed: a "dirty" hive
// (primary != secondary sequence) is reported as such.

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const unsigned char *d;     // whole file (caller keeps it alive)
    size_t n;
    size_t bins;                // bytes of hive-bin data actually present
    uint32_t root;              // root key cell offset
    uint32_t seq1, seq2;        // primary / secondary sequence numbers
    uint32_t major, minor;
    uint64_t last_written;      // FILETIME
    int checksum_ok;
    char file_name[160];        // embedded original path (UTF-8)
} regf_hive;

typedef struct {
    char name[512];             // UTF-8
    uint64_t last_written;
    uint32_t subkeys, values;   // counts recorded in the key
} regf_key_info;

typedef struct {
    char name[512];             // UTF-8; "" = the key's (default) value
    uint32_t type;              // REG_* number
    const unsigned char *data;  // valid only during the callback
    size_t len;
} regf_value;

// Open a hive held in memory. Returns 0, -1 not a hive, -2 truncated/unusable.
int regf_open(regf_hive *h, const unsigned char *d, size_t n);

// Key info for a key cell. Returns 0 or -1 if the cell is not a valid key.
int regf_key(const regf_hive *h, uint32_t key, regf_key_info *out);

// Calls cb for every direct subkey (cell offset). Returns the number reported
// or -1 if the key / its index is invalid.
typedef void (*regf_key_cb)(uint32_t subkey, void *ctx);
int regf_subkeys(const regf_hive *h, uint32_t key, regf_key_cb cb, void *ctx);

// Calls cb for every value of a key. Returns the number reported or -1.
// Big-data values are assembled into a temporary buffer for the callback.
typedef void (*regf_value_cb)(const regf_value *v, void *ctx);
int regf_values(const regf_hive *h, uint32_t key, regf_value_cb cb, void *ctx);

// Find a key by backslash path relative to the root ("Software\\Microsoft").
// Case-insensitive (ASCII letters). "" or "\\" is the root. Returns 0 or -1.
int regf_find(const regf_hive *h, const char *path, uint32_t *key);

// Convenience for typed reads of one named value ("" = default). Copies up to
// n bytes of data to out and returns the full data length, or -1 if absent.
long regf_get(const regf_hive *h, uint32_t key, const char *name, uint32_t *type,
              unsigned char *out, size_t n);

#endif
