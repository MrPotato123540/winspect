#ifndef WINSPECT_DNSCACHE_H
#define WINSPECT_DNSCACHE_H

// winspect dns - the DNS resolver cache: the names this machine looked up
// recently and what they resolved to (what `ipconfig /displaydns` prints),
// one row per record: name, type (A, AAAA, CNAME, PTR, SRV, MX, TXT ...),
// data and remaining TTL. Names are still listed minutes to hours after the
// process that asked for them has exited, which makes the cache a quick
// answer to "did this host talk to that domain?". Entries that come from
// the hosts file are in the cache too (see `winspect hosts`). Nothing is
// flagged: a name is not suspicious by its look. --find keeps rows whose
// name or data contains the text. The cache is answered from memory
// (DNS_QUERY_NO_WIRE_ONLY): no query leaves the machine. Needs the DNS Client
// service; recent Windows 11 builds also need administrator (as ipconfig
// /displaydns does). When DnsGetCacheDataTable refuses (some 24H2 builds do,
// even to an administrator) the cache is read through WMI
// (ROOT\StandardCimv2 MSFT_DNSClientCache, as Get-DnsClientCache does).
// An empty or unreadable cache is said so. Read-only. Usage:
//   winspect dns [--find <text>] [--json | --csv]
int cmd_dns(int argc, char **argv);

#endif
