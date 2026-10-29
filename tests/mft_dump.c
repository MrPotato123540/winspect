// mft_dump - print what mft.c reads from a $MFT file, one record per line:
//   recno<TAB>seq<TAB>in_use<TAB>dir<TAB>si created<TAB>si modified<TAB>si mft<TAB>si accessed
//   <TAB>fn created ... (4)<TAB>size<TAB>objid hex<TAB>path
// Times are raw FILETIMEs. Used by tests/mft_check.py.
#include "mft.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long L = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc((size_t)L);
    if (!d || fread(d, 1, (size_t)L, f) != (size_t)L) return 1;
    fclose(f);
    size_t rs = mft_record_size(d, (size_t)L);
    if (rs == 0) rs = 1024;
    size_t count = (size_t)L / rs;
    mft_entry *tab = calloc(count, sizeof *tab);
    mft_node *nodes = calloc(count, sizeof *nodes);
    for (size_t i = 0; i < count; i++) {
        mft_parse(d + i * rs, rs, (uint32_t)i, &tab[i]);
        nodes[i] = (mft_node){ tab[i].parent, tab[i].seq, (uint8_t)tab[i].valid, (uint8_t)tab[i].in_use,
                               (uint8_t)tab[i].dir, tab[i].name };
    }
    char path[4096];
    for (size_t i = 0; i < count; i++) {
        const mft_entry *e = &tab[i];
        if (!e->valid || !e->has_fn || e->extension) continue;
        mft_path(nodes, count, (uint32_t)i, path, sizeof path);
        printf("%zu\t%u\t%d\t%d", i, e->seq, e->in_use, e->dir);
        for (int k = 0; k < 4; k++) printf("\t%llu", (unsigned long long)e->si[k]);
        for (int k = 0; k < 4; k++) printf("\t%llu", (unsigned long long)e->fn[k]);
        printf("\t%llu\t", (unsigned long long)e->size);
        if (e->has_objid) for (int k = 0; k < 16; k++) printf("%02x", e->objid[k]);
        printf("\t%s\n", path);
    }
    free(nodes);
    free(tab);
    free(d);
    return 0;
}
