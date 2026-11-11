// defhist_dump - print what defhist.c reads from a Defender Detection History
// file as "key<TAB>value" lines, for tests/defhist_check.py. With a second
// argument N it instead fuzzes: N corrupted copies of the file are parsed
// (run under ASan / UBSan).
#include "defhist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long rs = 0x9E3779B97F4A7C15ULL;
static unsigned rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (unsigned)(rs >> 16); }

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) { perror(argv[1]); return 1; }
    static unsigned char d[1 << 20], m[1 << 20];
    size_t n = fread(d, 1, sizeof d, fp);
    fclose(fp);
    static dh_record r;
    if (argc > 2) {
        long rounds = atol(argv[2]), ok = 0;
        for (long i = 0; i < rounds; i++) {
            size_t len = n;
            memcpy(m, d, n);
            int muts = 1 + (int)(rnd() % 12);
            for (int k = 0; k < muts; k++) {
                size_t at = rnd() % len;
                switch (rnd() % 5) {
                case 0: m[at] ^= (unsigned char)(1u << (rnd() % 8)); break;
                case 1: m[at] = (unsigned char)rnd(); break;
                case 2: if (at + 4 <= len) { unsigned v = rnd() % 3 ? rnd() : 0xFFFFFFFFu; memcpy(m + at, &v, 4); } break;   // a size / type field
                case 3: len = 1 + rnd() % len; break;                                                                          // truncate
                default: if (at + 8 <= len) memset(m + at, 0, 8);
                }
            }
            if (dh_parse(m, len, &r) == 0) {
                ok++;
                char u[64];
                const dh_resource *p = dh_primary(&r);
                if (p) dh_web_url(p->location, u, sizeof u);
            }
        }
        printf("fuzz_defhist: %ld rounds, %ld still parsed, no sanitizer findings\n", rounds, ok);
        return 0;
    }
    if (dh_parse(d, n, &r) != 0) { puts("not a detection history file"); return 1; }
    printf("guid\t%s\nthreat\t%s\nthreat_id\t%llu\nstatus_time\t%llu\ndetect_time\t%llu\nremediation_time\t%llu\n", r.guid, r.threat,
           (unsigned long long)r.threat_id, (unsigned long long)r.status_time, (unsigned long long)r.detect_time,
           (unsigned long long)r.remediation_time);
    printf("user\t%s\nprocess\t%s\nremediation_user\t%s\n", r.user, r.process, r.remediation_user);
    for (int i = 0; i < r.nres; i++) printf("resource\t%s\t%s\t%s\n", r.res[i].type, r.res[i].location, r.res[i].sha256);
    const dh_resource *p = dh_primary(&r);
    printf("primary\t%s\n", p ? p->location : "");
    return 0;
}
