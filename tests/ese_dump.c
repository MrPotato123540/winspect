// ese_dump - list a table's columns and rows (integers, doubles, hex for
// binary) as read by src/esedb.c. Usage: ese_dump <db> <table> [max rows]
#include "esedb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ese_table T;
static long left;

static void row(const ese_row *r, void *ctx)
{
    (void)ctx;
    if (left-- <= 0) return;
    for (int i = 0; i < T.ncols; i++) {
        ese_val v;
        printf("%s%s=", i ? "\t" : "", T.cols[i].name);
        if (!ese_get(r, T.cols[i].name, &v)) { fputs("null", stdout); continue; }
        uint32_t ty = T.cols[i].type;
        if (ty == ESE_DATETIME || ty == ESE_DOUBLE) printf("%.10f", ese_double(r, T.cols[i].name));
        else if (v.len <= 8 && ty != ESE_BINARY && ty != ESE_LONGBINARY && ty != ESE_TEXT && ty != ESE_LONGTEXT)
            printf("%lld", (long long)ese_int(r, T.cols[i].name));
        else {
            if (v.compressed) fputs("c:", stdout);
            for (size_t k = 0; k < v.len && k < 200; k++) printf("%02x", v.data[k]);
        }
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long L = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc((size_t)L);
    if (!d || fread(d, 1, (size_t)L, f) != (size_t)L) return 1;
    fclose(f);
    ese_db db;
    if (ese_open(&db, d, (size_t)L) != 0) { puts("not ESE"); return 1; }
    if (ese_table_open(&db, argv[2], &T) != 0) { puts("no table"); return 1; }
    fprintf(stderr, "table %s fdp %u lv %u, %d columns\n", T.name, T.fdp, T.lv_fdp, T.ncols);
    for (int i = 0; i < T.ncols; i++) fprintf(stderr, "  %u %s type %u size %u\n", T.cols[i].id, T.cols[i].name, T.cols[i].type, T.cols[i].size);
    left = argc > 3 ? atol(argv[3]) : 1000000;
    long n = ese_rows(&db, &T, row, NULL);
    fprintf(stderr, "%ld rows\n", n);
    free(d);
    return 0;
}
