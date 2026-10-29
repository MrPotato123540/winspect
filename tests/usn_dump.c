// usn_dump - print every record usn.c reads from a $J file:
//   usn<TAB>FILETIME<TAB>file ref<TAB>parent ref<TAB>reason hex<TAB>reasons<TAB>name
#include "usn.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long L = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc(L > 0 ? (size_t)L : 1);
    if (!d || fread(d, 1, (size_t)L, f) != (size_t)L) return 1;
    fclose(f);
    size_t off = 0;
    usn_rec r;
    char rs[512];
    while (usn_next(d, (size_t)L, &off, &r)) {
        usn_reason_str(r.reason, rs, sizeof rs);
        printf("%llu\t%llu\t0x%llx\t0x%llx\t0x%08lx\t%s\t%s\n", (unsigned long long)r.usn, (unsigned long long)r.time,
               (unsigned long long)r.file_ref, (unsigned long long)r.parent_ref, (unsigned long)r.reason, rs, r.name);
    }
    free(d);
    return 0;
}
