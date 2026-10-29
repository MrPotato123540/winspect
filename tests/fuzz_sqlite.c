// Mutation fuzz of src/sqlite.c from a REAL database (and optionally its WAL):
// each round corrupts bytes / dwords of a copy - page types, cell pointers,
// varints, payload sizes, overflow page numbers, header fields - then reads
// sqlite_master, every table and its column list. Run under ASan/UBSan.
// Build: cc -I inc -fsanitize=address,undefined src/sqlite.c tests/fuzz_sqlite.c -o fuzz_sqlite
// Run:   ./fuzz_sqlite <db> [rounds] [<db-wal>]
#include "sqlite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long rows;
static unsigned long long rng = 0x9E3779B97F4A7C15ULL;
static unsigned long long rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

static void row_cb(int64_t id, const sqlite_val *c, int n, void *ctx)
{
    (void)id; (void)ctx;
    volatile unsigned char x = 0;
    for (int i = 0; i < n; i++) if ((c[i].type == SQ_TEXT || c[i].type == SQ_BLOB) && c[i].n) x ^= c[i].p[c[i].n - 1];
    (void)x;
    rows++;
}

typedef struct { char names[64][64]; int n; } tabs;
static void master_cb(int64_t id, const sqlite_val *c, int n, void *ctx)
{
    (void)id;
    tabs *t = (tabs *)ctx;
    if (n >= 2 && c[1].type == SQ_TEXT && c[1].n < 63 && t->n < 64) {
        memcpy(t->names[t->n], c[1].p, c[1].n);
        t->names[t->n][c[1].n] = 0;
        t->n++;
    }
}

static unsigned char *slurp(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long L = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc(L > 0 ? (size_t)L : 1);
    if (d && fread(d, 1, (size_t)L, f) != (size_t)L) { free(d); d = NULL; }
    fclose(f);
    *n = (size_t)L;
    return d;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    long rounds = argc > 2 ? atol(argv[2]) : 2000;
    size_t n, wn = 0;
    unsigned char *orig = slurp(argv[1], &n), *worig = argc > 3 ? slurp(argv[3], &wn) : NULL;
    if (orig == NULL) return 1;
    unsigned char *buf = malloc(n), *wbuf = wn ? malloc(wn) : NULL;
    for (long r = 0; r < rounds; r++) {
        memcpy(buf, orig, n);
        if (wbuf) memcpy(wbuf, worig, wn);
        int muts = 1 + (int)(rnd() % 10);
        for (int m = 0; m < muts; m++) {
            unsigned char *t = (wbuf && rnd() % 3 == 0) ? wbuf : buf;
            size_t tn = t == wbuf ? wn : n;
            size_t at = (size_t)(rnd() % tn);
            switch (rnd() % 3) {
            case 0: t[at] ^= (unsigned char)(1u << (rnd() % 8)); break;
            case 1: t[at] = (unsigned char)rnd(); break;
            default: if (at + 4 <= tn) {
                    static const unsigned char v[][4] = { {0,0,0,0}, {0xFF,0xFF,0xFF,0xFF}, {0,0,0,1}, {0x7F,0xFF,0xFF,0xFF}, {0,0,0x10,0} };
                    memcpy(t + at, v[rnd() % 5], 4);
                }
            }
        }
        size_t len = rnd() % 6 == 0 ? (size_t)(rnd() % n) : n;
        sqlite_db db;
        if (sqlite_open(&db, buf, len) != 0) continue;
        if (wbuf) sqlite_apply_wal(&db, wbuf, rnd() % 4 == 0 ? (size_t)(rnd() % wn) : wn);
        tabs t;
        memset(&t, 0, sizeof t);
        sqlite_scan(&db, 1, master_cb, &t);
        for (int i = 0; i < t.n; i++) {
            uint32_t root = sqlite_table_root(&db, t.names[i]);
            if (root) sqlite_scan(&db, root, row_cb, NULL);
            char cols[32][64];
            sqlite_columns(&db, t.names[i], cols, 32);
        }
        sqlite_close(&db);
    }
    printf("fuzz_sqlite: %ld rounds, %lu rows read, no sanitizer findings\n", rounds, rows);
    free(buf); free(wbuf); free(orig); free(worig);
    return 0;
}
