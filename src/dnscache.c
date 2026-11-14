// winspect dns - DNS resolver cache
//
// The DNS Client service (Dnscache) keeps every answer until its TTL runs
// out. Two calls expose it:
//   DnsGetCacheDataTable  dnsapi.dll export that ipconfig uses; it returns a
//                         linked list of (name, record type) pairs. It is
//                         not in the SDK headers, so it is looked up by name
//                         and its absence is handled.
//   DnsQuery_W with DNS_QUERY_NO_WIRE_ONLY
//                         answers from the cache only - the documented way
//                         to read a cached record set without causing any
//                         network traffic.
// Read-only: nothing is added to or flushed from the cache.

#include "dnscache.h"
#include "ioc.h"
#include "jsonutil.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Layout used by ipconfig (stable since Windows XP; widely documented).
typedef struct ws_dns_cache_entry {
    struct ws_dns_cache_entry *next;
    PWSTR name;
    WORD type;
    WORD data_length;
    DWORD flags;
} ws_dns_cache_entry;

typedef BOOL (WINAPI *get_cache_table_fn)(ws_dns_cache_entry **);

#ifndef DNS_QUERY_NO_WIRE_ONLY
#define DNS_QUERY_NO_WIRE_ONLY 0x00000010
#endif

static const char *type_name(WORD t, char *buf, size_t n)
{
    switch (t) {
    case DNS_TYPE_A:     return "A";
    case DNS_TYPE_NS:    return "NS";
    case DNS_TYPE_CNAME: return "CNAME";
    case DNS_TYPE_SOA:   return "SOA";
    case DNS_TYPE_PTR:   return "PTR";
    case DNS_TYPE_MX:    return "MX";
    case DNS_TYPE_TEXT:  return "TXT";
    case DNS_TYPE_AAAA:  return "AAAA";
    case DNS_TYPE_SRV:   return "SRV";
    case 64:             return "SVCB";
    case 65:             return "HTTPS";
    default: snprintf(buf, n, "TYPE%u", t); return buf;
    }
}

static void utf8(const WCHAR *w, char *out, size_t n)
{
    out[0] = '\0';
    if (w != NULL) WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)n, NULL, NULL);
    out[n - 1] = '\0';
}

// The data part of one record as text. Types without a simple text form are
// reported by length only rather than guessed at.
static void record_data(const DNS_RECORDW *r, char *out, size_t n)
{
    out[0] = '\0';
    switch (r->wType) {
    case DNS_TYPE_A: {
        const unsigned char *b = (const unsigned char *)&r->Data.A.IpAddress;
        snprintf(out, n, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        break;
    }
    case DNS_TYPE_AAAA: {
        struct in6_addr a6;
        memcpy(&a6, &r->Data.AAAA.Ip6Address, sizeof a6);
        const unsigned char *b = (const unsigned char *)&a6;
        // Plain, uncompressed groups: unambiguous and needs no helper call.
        snprintf(out, n, "%x:%x:%x:%x:%x:%x:%x:%x", b[0] << 8 | b[1], b[2] << 8 | b[3], b[4] << 8 | b[5],
                 b[6] << 8 | b[7], b[8] << 8 | b[9], b[10] << 8 | b[11], b[12] << 8 | b[13], b[14] << 8 | b[15]);
        break;
    }
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
    case DNS_TYPE_NS:
        utf8(r->Data.PTR.pNameHost, out, n);
        break;
    case DNS_TYPE_MX: {
        char host[256];
        utf8(r->Data.MX.pNameExchange, host, sizeof host);
        snprintf(out, n, "%u %s", r->Data.MX.wPreference, host);
        break;
    }
    case DNS_TYPE_SRV: {
        char host[256];
        utf8(r->Data.SRV.pNameTarget, host, sizeof host);
        snprintf(out, n, "%s:%u (priority %u, weight %u)", host, r->Data.SRV.wPort, r->Data.SRV.wPriority, r->Data.SRV.wWeight);
        break;
    }
    case DNS_TYPE_TEXT: {
        size_t o = 0;
        for (DWORD i = 0; i < r->Data.TXT.dwStringCount && o + 4 < n; i++) {
            char s[512];
            utf8(r->Data.TXT.pStringArray[i], s, sizeof s);
            int w = snprintf(out + o, n - o, "%s%s", i ? " " : "", s);
            if (w < 0 || (size_t)w >= n - o) break;
            o += (size_t)w;
        }
        break;
    }
    default:
        snprintf(out, n, "(%u byte(s) of data)", r->wDataLength);
    }
}

typedef struct { int mode, first; const char *find; unsigned rows, names; } dctx;

static void emit(dctx *c, const char *name, const char *type, const char *data, DWORD ttl, int have_ttl, const char *section)
{
    if (c->find && !ioc_contains_ci(name, c->find) && !ioc_contains_ci(data, c->find)) return;
    c->rows++;
    if (c->mode == 0) {
        if (have_ttl) printf("    %-45s %-6s %7lu  %s\n", name, type, (unsigned long)ttl, data);
        else          printf("    %-45s %-6s %7s  %s\n", name, type, "-", data);
    } else if (c->mode == 2) {
        csv_str(name); putchar(',');
        csv_str(type); putchar(',');
        csv_str(data); putchar(',');
        if (have_ttl) printf("%lu", (unsigned long)ttl);
        putchar(',');
        csv_str(section); putchar('\n');
    } else {
        printf("%s{\"name\":", c->first ? "" : ",");
        json_str(name);
        fputs(",\"type\":", stdout); json_str(type);
        fputs(",\"data\":", stdout); json_str(data);
        if (have_ttl) printf(",\"ttl\":%lu", (unsigned long)ttl); else fputs(",\"ttl\":null", stdout);
        fputs(",\"section\":", stdout); json_str(section);
        putchar('}');
        c->first = 0;
    }
}

int cmd_dns(int argc, char **argv)
{
    dctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)     c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0) c.mode = 2;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc) c.find = argv[++a];
        else {
            fprintf(stderr, "dns: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    HMODULE dnsapi = LoadLibraryExA("dnsapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    get_cache_table_fn get_table = dnsapi ? (get_cache_table_fn)(void (*)(void))GetProcAddress(dnsapi, "DnsGetCacheDataTable") : NULL;
    ws_dns_cache_entry *head = NULL;
    SetLastError(0);
    if (get_table == NULL || !get_table(&head)) {
        DWORD err = GetLastError();
        // FALSE with no error is what an empty cache returns. Recent Windows 11
        // builds also refuse the cache to non-administrators (ipconfig
        // /displaydns then says "The requested operation requires elevation").
        if (c.mode == 1) puts("[]");
        else if (c.mode == 2) puts("name,type,data,ttl,section");
        int rc = 0;
        if (get_table == NULL) {
            fputs("dns: this system does not expose the resolver cache (DnsGetCacheDataTable missing)\n", stderr);
            rc = 1;
        } else if (err == ERROR_ACCESS_DENIED || err == ERROR_ELEVATION_REQUIRED) {
            fputs("dns: access to the resolver cache denied - run as administrator\n", stderr);
            rc = 1;
        } else {
            fprintf(stderr, "dns: the resolver cache could not be read (error %lu): it is empty, the DNS Client service is not running, "
                            "or this Windows requires elevation - try again as administrator\n", (unsigned long)err);
        }
        if (dnsapi) FreeLibrary(dnsapi);
        return rc;
    }
    if (c.mode == 0) {
        puts("dns  (resolver cache; TTL = seconds left)\n");
        printf("    %-45s %-6s %7s  %s\n", "name", "type", "ttl", "data");
    } else if (c.mode == 2) {
        puts("name,type,data,ttl,section");
    } else {
        putchar('[');
    }
    for (ws_dns_cache_entry *e = head; e != NULL;) {
        char name[512], tb[16];
        utf8(e->name, name, sizeof name);
        c.names++;
        DNS_RECORDW *recs = NULL;
        DNS_STATUS st = e->name ? DnsQuery_W(e->name, e->type, DNS_QUERY_NO_WIRE_ONLY, NULL, (PDNS_RECORD *)&recs, NULL) : 1;
        if (st == 0 && recs != NULL) {
            for (DNS_RECORDW *r = recs; r != NULL; r = r->pNext) {
                char owner[512], data[1024], tb2[16];
                utf8(r->pName, owner, sizeof owner);
                record_data(r, data, sizeof data);
                const char *sec = r->Flags.S.Section == DnsSectionAnswer ? "answer"
                                : r->Flags.S.Section == DnsSectionAuthority ? "authority"
                                : r->Flags.S.Section == DnsSectionAddtional ? "additional" : "question";
                emit(&c, owner[0] ? owner : name, type_name(r->wType, tb2, sizeof tb2), data, r->dwTtl, 1, sec);
            }
            DnsRecordListFree((PDNS_RECORD)recs, DnsFreeRecordList);
        } else {
            // In the table but with no record set: a cached NEGATIVE answer
            // (the name did not exist / had no record of this type).
            emit(&c, name, type_name(e->type, tb, sizeof tb), st == DNS_ERROR_RCODE_NAME_ERROR ? "(cached: name does not exist)"
                 : st == DNS_INFO_NO_RECORDS ? "(cached: no record of this type)" : "(no cached data)", 0, 0, "");
        }
        ws_dns_cache_entry *next = e->next;
        // The table and its strings come from the DNS API heap.
        if (e->name) DnsFree(e->name, DnsFreeFlat);
        DnsFree(e, DnsFreeFlat);
        e = next;
    }
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) printf("\n%u record(s) for %u cached name/type pair(s)\n", c.rows, c.names);
    FreeLibrary(dnsapi);
    return 0;
}
