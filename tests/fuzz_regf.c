// Mutation fuzz of src/regf.c starting from a REAL hive: each round corrupts
// a few bytes / dwords of a copy (cell sizes, offsets, counts, signatures are
// all fair game) and walks the whole tree. Meant to run under ASan/UBSan.
// Build: cc -I inc -fsanitize=address,undefined src/regf.c src/shellitem.c tests/fuzz_regf.c -o fuzz_regf
// Run:   ./fuzz_regf <hive> [rounds]
#include "regf.h"
#include "shellitem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static regf_hive H;
static unsigned long visits;

static void val(const regf_value *v, void *ctx)
{
    (void)ctx;
    volatile unsigned char x = 0;
    for (size_t i = 0; i < v->len; i += 64) x ^= v->data[i];   // touch the data
    (void)x;
    // Every binary value also goes through the shell-item parser: a hive full
    // of ShellBags makes a realistic corpus for it.
    if (v->type == 3 && v->data != NULL) {
        shellitem it;
        shellitem_parse(v->data, v->len, &it);
    }
}

static void walk(uint32_t key, void *ctx)
{
    int depth = *(int *)ctx;
    regf_key_info ki;
    if (depth > 64 || ++visits > 200000 || regf_key(&H, key, &ki) != 0) return;
    regf_values(&H, key, val, NULL);
    int d2 = depth + 1;
    regf_subkeys(&H, key, walk, &d2);
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    long rounds = argc > 2 ? atol(argv[2]) : 2000;
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 2;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *orig = malloc((size_t)n), *d = malloc((size_t)n);
    if (!orig || !d || fread(orig, 1, (size_t)n, fp) != (size_t)n) return 2;
    fclose(fp);
    srand(12345);
    for (long r = 0; r < rounds; r++) {
        memcpy(d, orig, (size_t)n);
        int edits = 1 + rand() % 16;
        for (int e = 0; e < edits; e++) {
            size_t pos = (size_t)(((unsigned long)rand() << 16 ^ (unsigned long)rand()) % (unsigned long)n);
            if (rand() % 2) {
                d[pos] = (unsigned char)rand();
            } else if (pos + 4 <= (size_t)n) {
                static const unsigned vals[] = { 0, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u, 0x20, 0x1000 };
                unsigned v = vals[rand() % 6];
                memcpy(d + pos, &v, 4);
            }
        }
        size_t len = (rand() % 8 == 0) ? (size_t)(rand() % n) : (size_t)n;   // sometimes truncate
        visits = 0;
        if (regf_open(&H, d, len) == 0) {
            int z = 0;
            walk(H.root, &z);
            uint32_t k;
            regf_find(&H, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &k);
        }
    }
    printf("fuzz_regf: %ld rounds, no sanitizer findings\n", rounds);
    free(orig);
    free(d);
    return 0;
}
