// Differential-test helper for src/regf.c. Modes (JSON on stdout):
//   regf_dump <hive> header         base-block fields
//   regf_dump <hive> stats          walk every key: key/value counts + value types
//   regf_dump <hive> key <path>     one key: name, last write, subkey names, values
// Build: cc -I inc src/regf.c src/jsonutil.c tests/regf_dump.c -o regf_dump
#include "regf.h"
#include "jsonutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static regf_hive H;
static unsigned long keys, vals, types[16], visits;

static void count_value(const regf_value *v, void *ctx)
{
    (void)ctx;
    vals++;
    types[v->type < 15 ? v->type : 15]++;
}

static void walk(uint32_t key, void *ctx)
{
    int depth = ctx ? *(int *)ctx : 0;
    if (depth > 512 || ++visits > 10000000UL) return;
    regf_key_info ki;
    if (regf_key(&H, key, &ki) != 0) return;
    keys++;
    regf_values(&H, key, count_value, NULL);
    int d2 = depth + 1;
    regf_subkeys(&H, key, walk, &d2);
}

static int firstsub = 1;
static void sub_name(uint32_t key, void *ctx)
{
    (void)ctx;
    regf_key_info ki;
    if (regf_key(&H, key, &ki) != 0) return;
    if (!firstsub) putchar(',');
    json_str(ki.name);
    firstsub = 0;
}

static int firstval = 1;
static void show_value(const regf_value *v, void *ctx)
{
    (void)ctx;
    printf("%s{\"name\":", firstval ? "" : ",");
    json_str(v->name);
    printf(",\"type\":%u,\"len\":%lu,\"hex\":\"", (unsigned)v->type, (unsigned long)v->len);
    for (size_t i = 0; i < v->len && i < 256; i++) printf("%02x", v->data[i]);
    fputs("\"}", stdout);
    firstval = 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 2;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *d = malloc(n > 0 ? (size_t)n : 1);
    if (!d || fread(d, 1, (size_t)n, fp) != (size_t)n) return 2;
    fclose(fp);
    int rc = regf_open(&H, d, (size_t)n);
    if (rc != 0) { printf("{\"error\":%d}\n", rc); return 1; }
    if (strcmp(argv[2], "header") == 0) {
        regf_key_info ki;
        regf_key(&H, H.root, &ki);
        printf("{\"seq1\":%u,\"seq2\":%u,\"last_written\":%llu,\"major\":%u,\"minor\":%u,"
               "\"root\":%u,\"checksum_ok\":%d,\"file_name\":", H.seq1, H.seq2,
               (unsigned long long)H.last_written, H.major, H.minor, H.root, H.checksum_ok);
        json_str(H.file_name);
        fputs(",\"root_name\":", stdout);
        json_str(ki.name);
        printf(",\"root_subkeys\":%u}\n", ki.subkeys);
    } else if (strcmp(argv[2], "stats") == 0) {
        int z = 0;
        walk(H.root, &z);
        printf("{\"keys\":%lu,\"values\":%lu,\"types\":{", keys, vals);
        for (int t = 0; t < 16; t++) printf("%s\"%d\":%lu", t ? "," : "", t, types[t]);
        puts("}}");
    } else if (strcmp(argv[2], "key") == 0 && argc > 3) {
        uint32_t k;
        regf_key_info ki;
        if (regf_find(&H, argv[3], &k) != 0 || regf_key(&H, k, &ki) != 0) { puts("{\"error\":\"not found\"}"); return 1; }
        fputs("{\"name\":", stdout);
        json_str(ki.name);
        printf(",\"last_written\":%llu,\"subkeys\":[", (unsigned long long)ki.last_written);
        regf_subkeys(&H, k, sub_name, NULL);
        fputs("],\"values\":[", stdout);
        regf_values(&H, k, show_value, NULL);
        puts("]}");
    }
    free(d);
    return 0;
}
