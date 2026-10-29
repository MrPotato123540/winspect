// rb_dump - print what artparse.c reads from Recycle Bin metadata files
// ($I... or INFO2), one tab-separated line per entry:
//   version  size  deletion-time(UTC)  index  drive  purged  path
// Used by CI to compare against independently published expected values.
#include "artparse.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    for (int a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb");
        if (f == NULL) { perror(argv[a]); return 1; }
        static unsigned char buf[1 << 20];
        size_t n = fread(buf, 1, sizeof buf, f);
        fclose(f);
        rb_entry e;
        char ts[32];
        size_t cnt = rb_info2_count(buf, n);
        if (cnt) {
            for (size_t i = 0; i < cnt; i++) {
                if (rb_info2_record(buf, n, i, &e) != 0) continue;
                filetime_utc_str(e.deleted, ts, sizeof ts);
                printf("%d\t%llu\t%s\t%u\t%u\t%d\t%s\n", e.version, (unsigned long long)e.size, ts,
                       e.index, e.drive, e.purged, e.path);
            }
        } else if (rb_parse_i(buf, n, &e) == 0) {
            filetime_utc_str(e.deleted, ts, sizeof ts);
            printf("%d\t%llu\t%s\t-\t-\t0\t%s\n", e.version, (unsigned long long)e.size, ts, e.path);
        } else {
            printf("invalid\t%s\n", argv[a]);
        }
    }
    return 0;
}
