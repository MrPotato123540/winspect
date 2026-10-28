// Differential-test helper: parses one .lnk with winspect's own parser
// (src/lnkparse.c) and prints the fields as one JSON object, so a script can
// compare them with the output of an independent parser.
// Build: cc -I inc src/lnkparse.c src/shellitem.c src/jsonutil.c tests/lnk_dump.c -o lnk_dump
#include "lnkparse.h"
#include "jsonutil.h"
#include <stdio.h>
#include <stdlib.h>

static int first_item = 1;
static void dump_item(const shellitem *it, void *ctx)
{
    (void)ctx;
    printf("%s{\"kind\":", first_item ? "" : ",");
    json_str(it->kind ? it->kind : "");
    printf(",\"type\":%u,\"name\":", it->type);
    json_str(it->name);
    fputs(",\"short_name\":", stdout); json_str(it->short_name);
    fputs(",\"modified\":", stdout);   json_str(it->modified);
    fputs(",\"guid\":", stdout);       json_str(it->guid);
    putchar('}');
    first_item = 0;
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
    static lnk_info li;
    int rc = lnk_parse(d, (size_t)n, &li);
    printf("{\"rc\":%d,\"target\":", rc);      json_str(li.target);
    fputs(",\"relative\":", stdout);           json_str(li.relative);
    fputs(",\"workdir\":", stdout);            json_str(li.workdir);
    fputs(",\"arguments\":", stdout);          json_str(li.arguments);
    printf(",\"has_volume\":%d,\"drive_type\":%u,\"drive_serial\":%u,\"volume_label\":",
           li.has_volume, (unsigned)li.drive_type, (unsigned)li.drive_serial);
    json_str(li.volume_label);
    fputs(",\"net_share\":", stdout);          json_str(li.net_share);
    fputs(",\"env_target\":", stdout);         json_str(li.env_target);
    fputs(",\"machine_id\":", stdout);         json_str(li.machine_id);
    fputs(",\"mac\":", stdout);                json_str(li.mac);
    printf(",\"anomalies\":%u,\"idlist_path\":", (unsigned)li.anomalies);
    json_str(li.idlist_path);
    fputs(",\"items\":[", stdout);
    if (li.flags & 1) {
        size_t idsize = (size_t)d[0x4C] | ((size_t)d[0x4D] << 8);
        if (0x4E + idsize <= (size_t)n) lnk_idlist_items(d + 0x4E, idsize, dump_item, NULL);
    }
    puts("]}");
    free(d);
    return 0;
}
