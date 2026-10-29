#ifndef WINSPECT_ESEDB_H
#define WINSPECT_ESEDB_H

// Minimal read-only reader for ESE ("JET Blue") database FILES such as
// SRUDB.dat (System Resource Usage Monitor), written from public format notes
// (libyal's "Extensible Storage Engine (ESE) Database File (EDB) format"
// document); no code reused. It walks table B+ trees and decodes records:
//   file header (page 0): signature 0x89ABCDEF @4, format revision @232,
//     page size @236; page N lives at (N + 1) * page size
//   page: 40-byte header (80 for 16/32 KiB pages): flags @36 (1 root,
//     2 leaf, 4 parent, 0x80 long-value tree), tags at the page end, each
//     an (offset, size, flags) triple pointing into the page
//   entry: [common key size], local key size, key, data; on parent pages
//     the data is the child page number
//   catalog (MSysObjects, page 4): tables, their columns and long-value trees
//   record: last fixed id | last variable id | variable offset | fixed
//     columns | variable sizes + data | tagged columns (id, offset, flags)
// Long values (stored in the table's long-value tree) are reassembled.
// Compressed values are reported as such, not decoded. Every offset is
// checked; tree depth and loops are bounded. Portable C.

#include <stddef.h>
#include <stdint.h>

// JET_coltyp values used here.
enum { ESE_BIT = 1, ESE_UBYTE = 2, ESE_SHORT = 3, ESE_LONG = 4, ESE_CURRENCY = 5, ESE_FLOAT = 6,
       ESE_DOUBLE = 7, ESE_DATETIME = 8, ESE_BINARY = 9, ESE_TEXT = 10, ESE_LONGBINARY = 11,
       ESE_LONGTEXT = 12, ESE_ULONG = 14, ESE_LONGLONG = 15, ESE_GUID = 16, ESE_USHORT = 17 };

typedef struct {
    uint32_t id, type, size, codepage;
    char name[64];
} ese_column;

typedef struct {
    char name[64];
    uint32_t objid, fdp, lv_fdp;
    ese_column cols[256];
    int ncols;
} ese_table;

typedef struct {
    const unsigned char *d;
    size_t n;
    uint32_t page_size, revision, hdr;
} ese_db;

// One column value of a row: data points into the page or into a buffer
// valid during the row callback. present = 0 for NULL / absent.
typedef struct {
    int present, compressed;
    const unsigned char *data;
    size_t len;
} ese_val;

int ese_open(ese_db *db, const unsigned char *d, size_t n);
// Catalog lookup. Returns 0, -1 if the table is not there.
int ese_table_open(const ese_db *db, const char *name, ese_table *t);
// Calls cb for every row; get the columns with ese_get. Returns rows or -1.
typedef struct ese_row ese_row;
typedef void (*ese_row_cb)(const ese_row *row, void *ctx);
long ese_rows(const ese_db *db, const ese_table *t, ese_row_cb cb, void *ctx);
// Column value by name. Returns 1 if present.
int ese_get(const ese_row *row, const char *col, ese_val *v);
// Convenience: integer of a fixed column (0 when absent), double for DateTime.
int64_t ese_int(const ese_row *row, const char *col);
double ese_double(const ese_row *row, const char *col);

#endif
