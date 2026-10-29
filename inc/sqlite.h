#ifndef WINSPECT_SQLITE_H
#define WINSPECT_SQLITE_H

// Minimal read-only reader for SQLite 3 database FILES (browser history and
// the like), written from the public file-format document (sqlite.org
// "Database File Format"); no SQLite code is used. It walks table b-trees and
// decodes records - no SQL, no indexes needed:
//   header (100 bytes): page size @16, reserved bytes @20, text encoding @56
//   page: b-tree header (type 0x0D leaf / 0x05 interior table), cell pointers
//   leaf cell: payload size varint | rowid varint | payload (spilling into a
//     chain of overflow pages when larger than the page allows)
//   record: header of serial types, then the values
// A write-ahead log (<db>-wal) can be applied on top: the newest committed copy
// of each page wins, as SQLite itself would read it. Every offset is checked;
// overflow chains and tree depth are bounded. Portable C, no Windows API.

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const unsigned char *d;     // main file (caller keeps it alive)
    size_t n;
    uint32_t page_size, usable;
    uint32_t pages;             // pages in the main file
    int encoding;               // 1 UTF-8, 2 UTF-16le, 3 UTF-16be
    // WAL overlay: page number -> frame data (NULL = use the main file).
    const unsigned char **wal;
    uint32_t wal_pages;
} sqlite_db;

enum { SQ_NULL, SQ_INT, SQ_FLOAT, SQ_TEXT, SQ_BLOB };
typedef struct {
    int type;
    int64_t i;
    double f;
    const unsigned char *p;     // TEXT (UTF-8, not NUL-terminated) / BLOB
    size_t n;
} sqlite_val;

// Returns 0, or -1 if not an SQLite 3 file / unsupported page size.
int sqlite_open(sqlite_db *db, const unsigned char *d, size_t n);
// Applies a WAL file (its buffer must stay alive). Returns frames used, -1 on a bad WAL.
int sqlite_apply_wal(sqlite_db *db, const unsigned char *w, size_t n);
void sqlite_close(sqlite_db *db);

// Column names of a table, from its CREATE TABLE text in sqlite_master (a
// table changed by ALTER TABLE ADD COLUMN has it appended there). Fills up to
// max names (NUL-terminated, quotes removed) and returns the count, or -1.
// Table constraints (PRIMARY KEY(...), UNIQUE, CHECK, FOREIGN KEY,
// CONSTRAINT) are not columns and are skipped. Column i of every row from
// sqlite_scan is names[i]; an INTEGER PRIMARY KEY column is stored as NULL
// in the record and its value is the rowid.
int sqlite_columns(const sqlite_db *db, const char *table, char names[][64], int max);
// The same parse on a CREATE TABLE statement (exposed for tests).
int sqlite_parse_columns(const char *sql, size_t n, char names[][64], int max);

// Root page of a table by name (from sqlite_master), 0 if absent.
uint32_t sqlite_table_root(const sqlite_db *db, const char *table);
// Calls cb for each row of the table b-tree at root, in rowid order. Text in
// UTF-16 databases is converted to UTF-8. Returns rows visited or -1.
typedef void (*sqlite_row_cb)(int64_t rowid, const sqlite_val *cols, int ncols, void *ctx);
long sqlite_scan(const sqlite_db *db, uint32_t root, sqlite_row_cb cb, void *ctx);

#endif
