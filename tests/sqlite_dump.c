// sqlite_dump - print every row of a table as one JSON array per line:
//   [rowid, col1, col2, ...]   (text as strings, blobs as hex strings "x:..")
// Usage: sqlite_dump <db> <table> [<db-wal>]; "cols:<table>" prints the
// column names instead. Used by tests/sqlite_diff.py.
#include "sqlite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void str(const unsigned char *p, size_t n)
{
    putchar('"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c == '"' || c == '\\') printf("\\%c", c);
        else if (c < 0x20) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}

static void cb(int64_t rowid, const sqlite_val *c, int n, void *ctx)
{
    (void)ctx;
    printf("[%lld", (long long)rowid);
    for (int i = 0; i < n; i++) {
        putchar(',');
        switch (c[i].type) {
        case SQ_NULL: fputs("null", stdout); break;
        case SQ_INT: printf("%lld", (long long)c[i].i); break;
        case SQ_FLOAT: printf("%.17g", c[i].f); break;
        case SQ_TEXT: str(c[i].p, c[i].n); break;
        default:
            fputs("\"x:", stdout);
            for (size_t k = 0; k < c[i].n; k++) printf("%02x", c[i].p[k]);
            putchar('"');
        }
    }
    puts("]");
}

static unsigned char *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END);
    long L = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = (unsigned char *)malloc(L > 0 ? (size_t)L : 1);
    if (d && fread(d, 1, (size_t)L, f) != (size_t)L) { free(d); d = NULL; }
    fclose(f);
    *n = (size_t)L;
    return d;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    size_t n, wn = 0;
    unsigned char *d = slurp(argv[1], &n), *w = argc > 3 ? slurp(argv[3], &wn) : NULL;
    sqlite_db db;
    if (d == NULL || sqlite_open(&db, d, n) != 0) { puts("not sqlite"); return 1; }
    if (w && sqlite_apply_wal(&db, w, wn) < 0) { puts("bad wal"); return 1; }
    if (strncmp(argv[2], "cols:", 5) == 0) {           // print the column names instead
        char names[256][64];
        int nc = sqlite_columns(&db, argv[2] + 5, names, 256);
        for (int i = 0; i < nc; i++) puts(names[i]);
        sqlite_close(&db);
        free(d);
        free(w);
        return nc < 0;
    }
    uint32_t root = sqlite_table_root(&db, argv[2]);
    if (root == 0) { puts("no table"); return 1; }
    long r = sqlite_scan(&db, root, cb, NULL);
    fprintf(stderr, "%ld rows\n", r);
    sqlite_close(&db);
    free(d);
    free(w);
    return 0;
}
