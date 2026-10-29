// Mutation fuzz of src/esedb.c from a REAL ESE database: each round corrupts
// bytes of a copy (page headers and flags, tag arrays, key / record sizes,
// column offsets, child page numbers, long-value references) and reads the
// catalog and several tables. Run under ASan/UBSan.
// Build: cc -I inc -fsanitize=address,undefined src/esedb.c tests/fuzz_ese.c -o fuzz_ese
// Run:   ./fuzz_ese <db> [rounds] [table ...]
#include "esedb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long rng = 0x9E3779B97F4A7C15ULL;
static unsigned long long rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static unsigned long nrows;
static const ese_table *cur;

static void row(const ese_row *r, void *ctx)
{
    (void)ctx;
    for (int i = 0; i < cur->ncols; i++) {
        ese_val v;
        if (ese_get(r, cur->cols[i].name, &v) && v.len) { volatile unsigned char x = v.data[v.len - 1]; (void)x; }
        ese_int(r, cur->cols[i].name);
    }
    nrows++;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    long rounds = argc > 2 ? atol(argv[2]) : 200;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long L = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc((size_t)L), *b = malloc((size_t)L);
    if (!d || !b || fread(d, 1, (size_t)L, f) != (size_t)L) return 1;
    fclose(f);
    static ese_table t;
    for (long r = 0; r < rounds; r++) {
        memcpy(b, d, (size_t)L);
        int muts = 1 + (int)(rnd() % 200);
        for (int m = 0; m < muts; m++) {
            size_t at = 8192 + (size_t)(rnd() % ((size_t)L - 8192));
            switch (rnd() % 3) {
            case 0: b[at] ^= (unsigned char)(1u << (rnd() % 8)); break;
            case 1: b[at] = (unsigned char)rnd(); break;
            default: if (at + 4 <= (size_t)L) { unsigned v = (unsigned)(rnd() % 4 ? rnd() % 4096 : rnd()); memcpy(b + at, &v, 4); }
            }
        }
        ese_db db;
        size_t len = rnd() % 10 == 0 ? 4096 + (size_t)(rnd() % ((size_t)L - 4096)) : (size_t)L;
        if (ese_open(&db, b, len) != 0) continue;
        for (int k = 3; k < argc; k++) {
            if (ese_table_open(&db, argv[k], &t) != 0) continue;
            cur = &t;
            ese_rows(&db, &t, row, NULL);
        }
    }
    printf("fuzz_ese: %ld rounds, %lu rows read, no sanitizer findings\n", rounds, nrows);
    free(b);
    free(d);
    return 0;
}
