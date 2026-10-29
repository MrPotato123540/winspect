// Mutation fuzz of src/evtx.c starting from a REAL .evtx file: each round
// takes one 64 KiB chunk of a copy, corrupts a few bytes / dwords (record
// sizes, token bytes, name and template offsets, substitution counts and
// sizes are all fair game) and renders every record. Run under ASan/UBSan.
// Build: cc -I inc -fsanitize=address,undefined src/evtx.c tests/fuzz_evtx.c -o fuzz_evtx
// Run:   ./fuzz_evtx <file.evtx> [rounds]
#include "evtx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long rendered;

static void cb(uint64_t id, uint64_t written, const char *xml, void *ctx)
{
    (void)id; (void)written; (void)ctx;
    volatile size_t n = strlen(xml);           // the text must be NUL-terminated
    (void)n;
    rendered++;
}

static unsigned long long rng = 88172645463325252ULL;
static unsigned long long rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    long rounds = argc > 2 ? atol(argv[2]) : 2000;
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) return 1;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *orig = (unsigned char *)malloc((size_t)n);
    if (orig == NULL || fread(orig, 1, (size_t)n, fp) != (size_t)n) return 1;
    fclose(fp);
    // Header + one chunk per round keeps each round fast.
    size_t chunks = ((size_t)n - 4096) / 65536;
    if (chunks == 0) return 1;
    unsigned char *buf = (unsigned char *)malloc(4096 + 65536);
    for (long r = 0; r < rounds; r++) {
        size_t c = (size_t)(rnd() % chunks);
        memcpy(buf, orig, 4096);
        memcpy(buf + 4096, orig + 4096 + c * 65536, 65536);
        int muts = 1 + (int)(rnd() % 8);
        for (int m = 0; m < muts; m++) {
            size_t at = 4096 + (size_t)(rnd() % 65536);
            switch (rnd() % 4) {
            case 0: buf[at] ^= (unsigned char)(1u << (rnd() % 8)); break;
            case 1: buf[at] = (unsigned char)rnd(); break;
            case 2: if (at + 4 <= 4096 + 65536) {
                        static const unsigned v[] = { 0, 1, 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFF, 512, 65535, 65536 };
                        unsigned x = v[rnd() % 8];
                        memcpy(buf + at, &x, 4);
                    }
                    break;
            default: { // corrupt a token byte right after a record header
                    size_t rec = 4096 + 512 + (size_t)(rnd() % 4096);
                    buf[rec] = (unsigned char)(rnd() % 0x50);
                }
            }
        }
        // Sometimes cut the chunk short (a truncated copy).
        size_t len = 4096 + 65536;
        if (rnd() % 5 == 0) len = 4096 + 512 + (size_t)(rnd() % 65024);
        evtx_file f;
        if (evtx_open(&f, buf, len) == 0) evtx_records(&f, cb, NULL);
    }
    printf("fuzz_evtx: %ld rounds, %lu records rendered, no sanitizer findings\n", rounds, rendered);
    free(buf);
    free(orig);
    return 0;
}
