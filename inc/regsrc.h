#ifndef WINSPECT_REGSRC_H
#define WINSPECT_REGSRC_H

// One small interface over two registry sources, so the per-user and SYSTEM
// artifact commands (userassist, mru, bam, shimcache) read either the LIVE
// registry or an offline HIVE FILE (NTUSER.DAT, SYSTEM ... from another user
// or another machine) with the same code:
//   live: a root such as HKCU, or HKLM\SYSTEM
//   hive: a regf file parsed by src/regf.c (the file is read into memory once)
// Paths are relative to that root and use backslashes. Names and string data
// are UTF-8. Everything is read-only.

#include <windows.h>
#include <stdint.h>
#include "regf.h"

typedef struct {
    int is_hive;
    HKEY live;                  // live root (opened by regsrc_open_live)
    regf_hive h;
    unsigned char *buf;         // hive file contents
    char label[300];            // "HKCU" / "HKLM\\SYSTEM" / the hive's path
} regsrc;

typedef struct {
    HKEY hk;                    // live
    uint32_t cell;              // hive
    int open;
} rkey;

// Live source rooted at root\sub (sub may be NULL / ""). Returns 0 or a Win32 error.
LONG regsrc_open_live(regsrc *s, HKEY root, const char *sub, const char *label);
// Hive file. Returns 0, or -1 with a message in err (file unreadable / in use,
// not a hive). A dirty hive (transaction logs not replayed) still opens;
// regsrc_dirty() says so.
int regsrc_open_hive(regsrc *s, const char *path, char *err, size_t errn);
int regsrc_dirty(const regsrc *s);
void regsrc_close(regsrc *s);

// Open a key by path under the source root. Returns 0; otherwise -1 (hive:
// not found) or the Win32 error (live: ERROR_FILE_NOT_FOUND, ERROR_ACCESS_DENIED ...).
int rk_open(regsrc *s, const char *path, rkey *k);
void rk_close(rkey *k);
// Last-write time of the key (FILETIME), 0 if unknown.
uint64_t rk_lastwrite(regsrc *s, const rkey *k);

typedef void (*rk_name_cb)(const char *name, void *ctx);
typedef void (*rk_value_cb)(const char *name, uint32_t type, const unsigned char *data,
                            size_t len, void *ctx);
int rk_subkeys(regsrc *s, const rkey *k, rk_name_cb cb, void *ctx);
int rk_values(regsrc *s, const rkey *k, rk_value_cb cb, void *ctx);
// One value: copies up to n bytes, returns the full length or -1 if absent.
long rk_get(regsrc *s, const rkey *k, const char *name, uint32_t *type, unsigned char *out, size_t n);
// 1 if the value exists. Its DATA is never read (live: size query only;
// hive: no copy) - for values that hold secrets, e.g. Winlogon DefaultPassword.
int rk_exists(regsrc *s, const rkey *k, const char *name);
// REG_SZ / REG_EXPAND_SZ value as UTF-8 ("" if absent or another type). Returns 1 if found.
int rk_get_str(regsrc *s, const rkey *k, const char *name, char *out, size_t n);

// The control set that is "current": live -> "CurrentControlSet"; a SYSTEM
// hive has no CurrentControlSet link, so Select\Current picks ControlSet00N.
void regsrc_control_set(regsrc *s, char *out, size_t n);

// UTF-16LE bytes -> UTF-8 (stops at NUL or the end).
void regsrc_u16(const unsigned char *d, size_t len, char *out, size_t n);

#endif
