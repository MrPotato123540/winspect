// Differential-test helper: prints "name<TAB>size<TAB>md5" for every stream
// of a compound file, using winspect's own CFB reader (src/cfb.c). The same
// listing produced by an independent reader (e.g. Python's olefile) must match.
// Build: cc -I inc src/cfb.c src/md5.c tests/cfb_dump.c -o cfb_dump
#include "cfb.h"
#include "md5.h"
#include <stdio.h>
#include <stdlib.h>

static void cb(const char *name, const unsigned char *data, size_t len, void *ctx)
{
    (void)ctx;
    char hex[33];
    md5_hex(data, len, hex);
    printf("%s\t%lu\t%s\n", name, (unsigned long)len, hex);
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 2;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *d = malloc((size_t)n);
    if (!d || fread(d, 1, (size_t)n, fp) != (size_t)n) return 2;
    fclose(fp);
    cfb_file f;
    int rc = cfb_open(&f, d, (size_t)n);
    if (rc != 0) { printf("open failed %d\n", rc); return 1; }
    int k = cfb_streams(&f, cb, NULL);
    cfb_close(&f);
    free(d);
    return k < 0;
}
