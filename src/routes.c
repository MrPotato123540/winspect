// winspect routes - the IPv4 routing table
//
// The routing table decides where each packet goes. GetIpForwardTable returns
// it; we print destination, mask, gateway (next hop), interface index, metric
// and type. A route nobody expects can quietly redirect traffic, so this is a
// cheap thing to eyeball. Read-only enumeration (the data `route print` shows).

#include "routes.h"
#include "jsonutil.h"

#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fmt_ip(DWORD addr, char *out, size_t n)
{
    const unsigned char *b = (const unsigned char *)&addr;
    snprintf(out, n, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static const char *route_type(DWORD t)
{
    switch (t) {
    case MIB_IPROUTE_TYPE_DIRECT:   return "direct";
    case MIB_IPROUTE_TYPE_INDIRECT: return "indirect";
    case MIB_IPROUTE_TYPE_OTHER:    return "other";
    case MIB_IPROUTE_TYPE_INVALID:  return "invalid";
    default:                        return "?";
    }
}

int cmd_routes(int argc, char **argv)
{
    int mode = 0;   // 0 text, 1 json, 2 csv
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else {
            fprintf(stderr, "routes: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    ULONG size = 0;
    DWORD r = GetIpForwardTable(NULL, &size, FALSE);
    if (r != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        if (r == ERROR_NO_DATA) {
            if (mode == 1) { puts("[]"); }
            else if (mode == 2) { puts("destination,mask,gateway,interface,metric,type"); }
            else { puts("routing table is empty"); }
            return 0;
        }
        fprintf(stderr, "routes: GetIpForwardTable sizing failed (error %lu)\n", (unsigned long)r);
        return 1;
    }
    MIB_IPFORWARDTABLE *t = (MIB_IPFORWARDTABLE *)malloc(size);
    if (t == NULL) {
        return 1;
    }
    r = GetIpForwardTable(t, &size, TRUE);
    if (r != NO_ERROR) {
        fprintf(stderr, "routes: GetIpForwardTable failed (error %lu)\n", (unsigned long)r);
        free(t);
        return 1;
    }

    if (mode == 0) {
        printf("  %-16s %-16s %-16s %-5s %-7s %s\n",
               "destination", "mask", "gateway", "if", "metric", "type");
    } else if (mode == 2) {
        puts("destination,mask,gateway,interface,metric,type");
    } else {
        putchar('[');
    }

    int first = 1;
    for (DWORD i = 0; i < t->dwNumEntries; i++) {
        const MIB_IPFORWARDROW *row = &t->table[i];
        char dest[24], mask[24], gw[24];
        fmt_ip(row->dwForwardDest, dest, sizeof dest);
        fmt_ip(row->dwForwardMask, mask, sizeof mask);
        fmt_ip(row->dwForwardNextHop, gw, sizeof gw);

        if (mode == 0) {
            printf("  %-16s %-16s %-16s %-5lu %-7lu %s\n",
                   dest, mask, gw, (unsigned long)row->dwForwardIfIndex,
                   (unsigned long)row->dwForwardMetric1, route_type(row->dwForwardType));
        } else if (mode == 2) {
            csv_str(dest); putchar(',');
            csv_str(mask); putchar(',');
            csv_str(gw);   printf(",%lu,%lu,", (unsigned long)row->dwForwardIfIndex,
                                   (unsigned long)row->dwForwardMetric1);
            csv_str(route_type(row->dwForwardType)); putchar('\n');
        } else {
            printf("%s{\"destination\":", first ? "" : ",");
            json_str(dest);
            fputs(",\"mask\":", stdout);    json_str(mask);
            fputs(",\"gateway\":", stdout); json_str(gw);
            printf(",\"interface\":%lu,\"metric\":%lu,\"type\":",
                   (unsigned long)row->dwForwardIfIndex, (unsigned long)row->dwForwardMetric1);
            json_str(route_type(row->dwForwardType));
            putchar('}');
            first = 0;
        }
    }
    DWORD count = t->dwNumEntries;
    free(t);

    if (mode == 0) {
        printf("\n%lu route(s)\n", (unsigned long)count);
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
