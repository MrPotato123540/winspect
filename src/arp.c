// winspect arp - the local IPv4 neighbour (ARP) cache
//
// The ARP cache maps IPv4 addresses on the local segment to hardware (MAC)
// addresses. GetIpNetTable returns that table; we print each entry's IP, MAC,
// adapter index and type (static/dynamic). Read-only - a plain enumeration, the
// same data `arp -a` shows.

#include "arp.h"
#include "jsonutil.h"

#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *arp_type(DWORD t)
{
    switch (t) {
    case MIB_IPNET_TYPE_OTHER:   return "other";
    case MIB_IPNET_TYPE_INVALID: return "invalid";
    case MIB_IPNET_TYPE_DYNAMIC: return "dynamic";
    case MIB_IPNET_TYPE_STATIC:  return "static";
    default:                     return "?";
    }
}

int cmd_arp(int argc, char **argv)
{
    int mode = 0;   // 0 text, 1 json, 2 csv
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else {
            fprintf(stderr, "arp: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    ULONG size = 0;
    DWORD r = GetIpNetTable(NULL, &size, FALSE);
    if (r != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        // ERROR_NO_DATA simply means an empty cache.
        if (r == ERROR_NO_DATA) {
            if (mode == 1) { puts("[]"); } else if (mode == 2) { puts("ip,mac,adapter,type"); }
            else { puts("arp cache is empty"); }
            return 0;
        }
        fprintf(stderr, "arp: GetIpNetTable sizing failed (error %lu)\n", (unsigned long)r);
        return 1;
    }
    MIB_IPNETTABLE *t = (MIB_IPNETTABLE *)malloc(size);
    if (t == NULL) {
        return 1;
    }
    r = GetIpNetTable(t, &size, TRUE);
    if (r != NO_ERROR) {
        fprintf(stderr, "arp: GetIpNetTable failed (error %lu)\n", (unsigned long)r);
        free(t);
        return 1;
    }

    if (mode == 0) {
        printf("  %-18s %-18s %-8s %s\n", "ip", "mac", "adapter", "type");
    } else if (mode == 2) {
        puts("ip,mac,adapter,type");
    } else {
        putchar('[');
    }

    int first = 1;
    for (DWORD i = 0; i < t->dwNumEntries; i++) {
        const MIB_IPNETROW *row = &t->table[i];
        const unsigned char *ipb = (const unsigned char *)&row->dwAddr;
        char ip[24];
        snprintf(ip, sizeof ip, "%u.%u.%u.%u", ipb[0], ipb[1], ipb[2], ipb[3]);

        char mac[32] = "";
        size_t p = 0;
        for (DWORD b = 0; b < row->dwPhysAddrLen && p + 3 < sizeof mac; b++) {
            p += (size_t)snprintf(mac + p, sizeof mac - p, "%s%02X",
                                  b ? "-" : "", row->bPhysAddr[b]);
        }

        if (mode == 0) {
            printf("  %-18s %-18s %-8lu %s\n", ip, mac[0] ? mac : "-",
                   (unsigned long)row->dwIndex, arp_type(row->dwType));
        } else if (mode == 2) {
            csv_str(ip); putchar(',');
            csv_str(mac); printf(",%lu,", (unsigned long)row->dwIndex);
            csv_str(arp_type(row->dwType)); putchar('\n');
        } else {
            printf("%s{\"ip\":", first ? "" : ",");
            json_str(ip);
            fputs(",\"mac\":", stdout); json_str(mac);
            printf(",\"adapter\":%lu,\"type\":", (unsigned long)row->dwIndex);
            json_str(arp_type(row->dwType));
            putchar('}');
            first = 0;
        }
    }
    DWORD count = t->dwNumEntries;
    free(t);

    if (mode == 0) {
        printf("\n%lu entr%s\n", (unsigned long)count, count == 1 ? "y" : "ies");
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
