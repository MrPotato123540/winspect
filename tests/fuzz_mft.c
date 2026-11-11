// Mutation fuzz of src/mft.c from a REAL $MFT: each round corrupts a copy of
// a few hundred records (fixup arrays, attribute types / lengths / offsets,
// name lengths, parent references) and parses them, then builds every path
// over the damaged table (loops, self-parents, out-of-range references).
// Build: cc -I inc -fsanitize=address,undefined src/mft.c tests/fuzz_mft.c -o fuzz_mft
// Run:   ./fuzz_mft <$MFT> [rounds]
#include "mft.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long rng = 0x2545F4914F6CDD1DULL;
static unsigned long long rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    long rounds = argc > 2 ? atol(argv[2]) : 500;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long L = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc((size_t)L);
    if (!d || fread(d, 1, (size_t)L, f) != (size_t)L) return 1;
    fclose(f);
    size_t rs = 1024, total = (size_t)L / rs, win = 256;
    unsigned char *buf = malloc(win * rs);
    mft_entry *tab = calloc(win, sizeof *tab);
    mft_node *nodes = calloc(win, sizeof *nodes);
    unsigned long parsed = 0;
    char path[4096];
    for (long r = 0; r < rounds; r++) {
        size_t start = total > win ? (size_t)(rnd() % (total - win)) : 0;
        size_t n = total < win ? total : win;
        memcpy(buf, d + start * rs, n * rs);
        int muts = 1 + (int)(rnd() % 40);
        for (int m = 0; m < muts; m++) {
            size_t at = (size_t)(rnd() % (n * rs));
            switch (rnd() % 4) {
            case 0: buf[at] ^= (unsigned char)(1u << (rnd() % 8)); break;
            case 1: buf[at] = (unsigned char)rnd(); break;
            case 2: if (at + 2 <= n * rs) { buf[at] = 0xFF; buf[at + 1] = 0xFF; } break;
            default: if (at + 8 <= n * rs) {                  // a parent reference pointing anywhere
                    unsigned long long v = rnd() % (n + 8);
                    memcpy(buf + at, &v, 8);
                }
            }
        }
        for (size_t i = 0; i < n; i++) {
            size_t len = rnd() % 50 == 0 ? (size_t)(rnd() % rs) : rs;     // sometimes a short buffer
            if (mft_parse(buf + i * rs, len, (uint32_t)i, &tab[i]) == 0) parsed++;
            nodes[i] = (mft_node){ tab[i].parent, tab[i].seq, (uint8_t)tab[i].valid, (uint8_t)tab[i].in_use,
                                   (uint8_t)tab[i].dir, tab[i].name };
        }
        for (size_t i = 0; i < n; i++) {
            mft_path(nodes, n, (uint32_t)i, path, sizeof path);
            mft_timestomp_reason(tab[i].si, tab[i].fn);
            // The volume-reading helpers see the same corrupted records: run
            // lists of any attribute, resident content, attribute lists, and
            // arbitrary bytes taken as a boot sector.
            static const uint32_t types[] = { 0x20, 0x80, 0xA0 };
            mft_run rr[16];
            uint64_t real, vcn;
            const unsigned char *cp;
            size_t cl;
            mft_ext ex[8];
            for (int t = 0; t < 3; t++) {
                mft_attr_runs(buf + i * rs, rs, types[t], rr, 16, &real, &vcn);
                if (mft_attr_resident(buf + i * rs, rs, types[t], &cp, &cl) == 0) mft_alist_data(cp, cl, 0, ex, 8);
            }
            mft_alist_data(buf + i * rs, rs, i, ex, 8);
            ntfs_boot nb;
            memcpy(buf + i * rs + 3, "NTFS    ", 8);
            ntfs_parse_boot(buf + i * rs, rs, &nb);
        }
    }
    printf("fuzz_mft: %ld rounds, %lu records parsed, no sanitizer findings\n", rounds, parsed);
    free(buf); free(tab); free(nodes); free(d);
    return 0;
}
