// Differential-test helper: prints the DestList of an AutomaticDestinations
// jump list as JSON using winspect's own CFB reader + DestList parser.
// Build: cc -I inc src/cfb.c src/destlist.c src/jsonutil.c tests/destlist_dump.c -o destlist_dump
#include "cfb.h"
#include "destlist.h"
#include "jsonutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int first = 1, streams = 0;
static char names[8192];
static size_t nl;

static void ent(const dl_entry *e, void *ctx)
{
    (void)ctx;
    printf("%s{\"mru\":%u,\"entry\":%u,\"last_used\":%llu,\"pinned\":%d,\"interactions\":",
           first ? "" : ",", e->mru, (unsigned)e->entry, (unsigned long long)e->last_used, e->pinned);
    if (e->has_interactions) printf("%u", (unsigned)e->interactions); else fputs("null", stdout);
    fputs(",\"host\":", stdout); json_str(e->host);
    fputs(",\"mac\":", stdout);  json_str(e->mac);
    printf(",\"droid_time\":%llu,\"path\":", (unsigned long long)e->droid_time);
    json_str(e->path);
    putchar('}');
    first = 0;
}

static void on_stream(const char *name, const unsigned char *d, size_t n, void *ctx)
{
    (void)ctx;
    if (strcmp(name, "DestList") != 0) {
        int w = snprintf(names + nl, sizeof names - nl, "%s\"%s\"", streams ? "," : "", name);
        if (w > 0 && (size_t)w < sizeof names - nl) nl += (size_t)w;
        streams++;
        return;
    }
    uint32_t ver = 0, pinned = 0;
    fputs("\"entries\":[", stdout);
    int c = destlist_parse(d, n, &ver, &pinned, ent, NULL);
    printf("],\"count\":%d,\"version\":%u,\"pinned_header\":%u,", c, (unsigned)ver, (unsigned)pinned);
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 2;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *d = malloc(n > 0 ? (size_t)n : 1);
    if (!d || fread(d, 1, (size_t)n, fp) != (size_t)n) return 2;
    fclose(fp);
    cfb_file f;
    if (cfb_open(&f, d, (size_t)n) != 0) { puts("{\"error\":\"not a compound file\"}"); return 1; }
    putchar('{');
    cfb_streams(&f, on_stream, NULL);
    printf("\"link_streams\":[%s]}\n", names);
    cfb_close(&f);
    free(d);
    return 0;
}
