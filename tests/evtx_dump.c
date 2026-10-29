// evtx_dump - print every record evtx.c renders, one per line:
//   <record id>\t<written FILETIME>\t<xml>
// Used by tests/evtx_check.py to compare against published expected values.
#include "evtx.h"

#include <stdio.h>
#include <stdlib.h>

static void cb(uint64_t id, uint64_t written, const char *xml, void *ctx)
{
    (void)ctx;
    printf("%llu\t%llu\t%s\n", (unsigned long long)id, (unsigned long long)written, xml);
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) { perror(argv[1]); return 1; }
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *d = (unsigned char *)malloc(n > 0 ? (size_t)n : 1);
    if (d == NULL || fread(d, 1, (size_t)n, fp) != (size_t)n) { fclose(fp); return 1; }
    fclose(fp);
    evtx_file f;
    if (evtx_open(&f, d, (size_t)n) != 0) { puts("not an evtx file"); free(d); return 1; }
    unsigned long c = evtx_records(&f, cb, NULL);
    fprintf(stderr, "%lu record(s)\n", c);
    free(d);
    return 0;
}
