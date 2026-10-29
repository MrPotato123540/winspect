// winspect net - per-process network endpoints (the "netstat -ano" question)
//
// Windows keeps the TCP and UDP endpoint tables in the kernel; iphlpapi exposes
// them to user mode through GetExtendedTcpTable / GetExtendedUdpTable. The
// *_OWNER_PID table flavours add the one field that makes this useful for triage:
// the PID that owns each endpoint. So we can answer "what is this process talking
// to?" and "who opened this listening port?" without a driver.
//
// We read four tables - TCP/IPv4, TCP/IPv6, UDP/IPv4, UDP/IPv6 - with the same
// two-step size-probe-then-read pattern the rest of winspect uses, and print one
// row per endpoint. A pid argument filters to a single process.
//
// Addresses and ports in these structs are in NETWORK byte order (big-endian).
// Ports therefore need a byte swap to read as a number; IPv4 addresses are laid
// out as four bytes we can print in order; IPv6 we hand to RtlIpv6AddressToStringA.

#include "net.h"
#include "jsonutil.h"
#include "ioc.h"

// winsock2.h must be included before windows.h, or the two sets of socket
// definitions collide. ws2ipdef.h adds the IPv6 address structs; iphlpapi.h
// brings the extended TCP/UDP owner-PID tables.
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>   // GetExtendedTcpTable, MIB_*_OWNER_PID
#include <tlhelp32.h>   // process name map (CreateToolhelp32Snapshot)
#include <stdio.h>
#include <stdlib.h>     // malloc, free, strtoul
#include <string.h>     // strcmp

// RtlIpv6AddressToStringA lives in ntdll and formats a 16-byte IPv6 address to
// its canonical text form. We declare it ourselves to avoid pulling in headers
// that would clash with the ones above; the signature is stable and documented.
typedef PSTR (NTAPI *RtlIpv6ToStr_t)(const struct in6_addr *, PSTR);

// Network-order port field -> host-order port (ioc_port_from_net, unit-tested;
// an earlier inline version forgot to mask the swap and printed bogus ports).
static unsigned port_of(DWORD netorder)
{
    return ioc_port_from_net(netorder);
}

// Formats an IPv4 address (4 bytes, network order) as "a.b.c.d".
static void fmt_v4(DWORD addr, char *out, size_t n)
{
    const unsigned char *b = (const unsigned char *)&addr;
    snprintf(out, n, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

// Formats a 16-byte IPv6 address via ntdll's RtlIpv6AddressToStringA. On the
// rare chance the export cannot be resolved we fall back to a raw hex dump so
// output is never silently wrong.
static void fmt_v6(const UCHAR addr[16], char *out, size_t n)
{
    static RtlIpv6ToStr_t fn = NULL;
    static int tried = 0;
    if (!tried) {
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (nt != NULL) {
            fn = (RtlIpv6ToStr_t)(void(*)(void))GetProcAddress(nt, "RtlIpv6AddressToStringA");
        }
        tried = 1;
    }
    if (fn != NULL) {
        struct in6_addr a;
        memcpy(&a, addr, 16);
        char tmp[46] = "";            // max textual IPv6 length is 45 + NUL
        fn(&a, tmp);
        snprintf(out, n, "%s", tmp);
        return;
    }
    snprintf(out, n, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
             addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
}

// Readable name for a TCP connection state (MIB_TCP_STATE values).
static const char *tcp_state(DWORD s)
{
    switch (s) {
    case MIB_TCP_STATE_CLOSED:     return "CLOSED";
    case MIB_TCP_STATE_LISTEN:     return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:    return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
    default:                       return "?";
    }
}

// A PID -> process-name map, built once from a Toolhelp snapshot. We resolve the
// owner this way rather than opening each process (no special rights needed, and
// it works uniformly for every protocol family). This answers the question that
// makes `net` useful for triage: not just which PID, but which program.
// (GetOwnerModuleFromTcpEntry is the deeper per-connection alternative; the exe
// name covers the common case and stays simple.)
struct procname { DWORD pid; char name[64]; char path[520]; };
struct procmap { struct procname *v; unsigned n; };

static void procmap_build(struct procmap *m)
{
    m->v = NULL;
    m->n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return;
    }
    unsigned cap = 256;
    m->v = (struct procname *)malloc(cap * sizeof *m->v);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof pe;
    if (m->v != NULL && Process32First(snap, &pe)) {
        do {
            if (m->n == cap) {
                unsigned nc = cap * 2;
                struct procname *nv = (struct procname *)realloc(m->v, nc * sizeof *m->v);
                if (nv == NULL) { break; }
                m->v = nv; cap = nc;
            }
            m->v[m->n].pid = pe.th32ProcessID;
            snprintf(m->v[m->n].name, sizeof m->v[m->n].name, "%s", pe.szExeFile);
            // Full image path (best effort, query-limited access is enough):
            // the flags below judge WHERE the program lives, not just its name.
            m->v[m->n].path[0] = '\0';
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hp != NULL) {
                WCHAR w[520];
                DWORD wl = 520;
                if (QueryFullProcessImageNameW(hp, 0, w, &wl)) {
                    WideCharToMultiByte(CP_UTF8, 0, w, -1, m->v[m->n].path,
                                        (int)sizeof m->v[m->n].path, NULL, NULL);
                }
                CloseHandle(hp);
            }
            m->n++;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static const char *procmap_path(const struct procmap *m, DWORD pid)
{
    for (unsigned i = 0; i < m->n; i++) {
        if (m->v[i].pid == pid) {
            return m->v[i].path;
        }
    }
    return "";
}

static const char *procmap_name(const struct procmap *m, DWORD pid)
{
    for (unsigned i = 0; i < m->n; i++) {
        if (m->v[i].pid == pid) {
            return m->v[i].name;
        }
    }
    return "";
}

// One normalized endpoint row, so the four source tables all feed one printer.
struct endpoint {
    const char *proto;        // "TCP" / "TCP6" / "UDP" / "UDP6"
    char        local[64];    // "addr:port"
    char        remote[64];   // "addr:port" or "" for UDP
    const char *state;        // TCP state name, or "" for UDP
    DWORD       pid;
    const char *proc;         // owning process exe name (may be "")
    int         listening;    // TCP LISTEN or any UDP (no established peer)
    int         is_udp;       // for --tcp/--udp filtering
    const char *rscope;       // remote address scope: public/private/... ("" if none)
    int         exposed;      // listening on every interface (0.0.0.0 / ::)
};

// Output state carried through the emit calls so each mode manages its own
// separators and headers in one place.
struct emit_ctx {
    int   mode;       // 0 text, 1 json, 2 csv
    int   first;      // JSON: have we emitted a row yet?
    DWORD filter;     // 0 = all pids, else only this one
    int   want_tcp;   // protocol-family filters
    int   want_udp;
    int   listening_only;
    int   established_only;
    int   external_only;      // --external: remote peer is a public address
    int   exposed_only;       // --exposed: listening on all interfaces
    int   flagged_only;       // --flagged: only rows with a reason
    unsigned flagged;
    const struct procmap *map;
    unsigned count;
};

#define NET_TEXT 0
#define NET_JSON 1
#define NET_CSV  2

static void emit_row(struct emit_ctx *c, const struct endpoint *e)
{
    if (c->filter != 0 && e->pid != c->filter) {
        return;
    }
    if (e->is_udp && !c->want_udp) { return; }
    if (!e->is_udp && !c->want_tcp) { return; }
    if (c->listening_only && !e->listening) { return; }
    if (c->established_only && e->listening) { return; }
    if (c->external_only && strcmp(e->rscope, "public") != 0) { return; }
    if (c->exposed_only && !(e->listening && e->exposed)) { return; }

    // Who is talking? A script host or a program from a user-writable folder
    // with a live connection to the internet - or listening on every
    // interface - is what an analyst looks at first (beaconing, reverse shells,
    // dropped tools opening a port).
    const char *path = procmap_path(c->map, e->pid);
    const char *who = path[0] ? path : e->proc;
    const char *reason = NULL;
    int public_peer = !e->listening && strcmp(e->rscope, "public") == 0;
    if (public_peer && ioc_script_host(who))
        reason = "script host / LOLBin connected to a public address";
    else if (public_peer && ioc_user_writable(who))
        reason = "program in a user-writable dir connected to a public address";
    else if (e->listening && e->exposed && ioc_user_writable(who))
        reason = "program in a user-writable dir listens on all interfaces";
    if (c->flagged_only && reason == NULL) { return; }
    if (reason) { c->flagged++; }
    c->count++;
    if (c->mode == NET_TEXT) {
        printf("  %s%-5s %-28s %-28s %-12s %-6lu %s\n", reason ? "[!] " : "    ",
               e->proto, e->local, e->remote[0] ? e->remote : "-",
               e->state[0] ? e->state : "-", (unsigned long)e->pid,
               e->proc[0] ? e->proc : "?");
        if (reason) {
            printf("        %s  <- %s\n", who, reason);
        }
    } else if (c->mode == NET_CSV) {
        printf("%s,", e->proto);
        csv_str(e->local); putchar(',');
        csv_str(e->remote); putchar(',');
        csv_str(e->state); putchar(',');
        printf("%lu,", (unsigned long)e->pid);
        csv_str(e->proc); putchar(',');
        csv_str(e->rscope);
        fputs(e->listening && e->exposed ? ",true," : ",false,", stdout);
        csv_str(path); putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"proto\":\"%s\",\"local\":", c->first ? "" : ",", e->proto);
        json_str(e->local);
        fputs(",\"remote\":", stdout);
        if (e->remote[0]) { json_str(e->remote); } else { fputs("null", stdout); }
        fputs(",\"state\":", stdout);
        if (e->state[0]) { json_str(e->state); } else { fputs("null", stdout); }
        printf(",\"pid\":%lu,\"process\":", (unsigned long)e->pid);
        json_str(e->proc);
        fputs(",\"remote_scope\":", stdout);
        json_str(e->rscope);
        printf(",\"listening_all_interfaces\":%s,\"path\":", e->listening && e->exposed ? "true" : "false");
        json_str(path);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

// Reads one extended table with the standard size-probe pattern. Returns a
// malloc'd buffer the caller frees, or NULL on failure.
static void *read_table(int udp, int v6, DWORD *out_err)
{
    ULONG size = 0;
    DWORD err;
    ULONG af = v6 ? AF_INET6 : AF_INET;
    // First call: ask for the required size (buffer NULL).
    if (udp) {
        err = GetExtendedUdpTable(NULL, &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
    } else {
        err = GetExtendedTcpTable(NULL, &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    if (err != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        *out_err = err;
        return NULL;
    }
    void *buf = malloc(size);
    if (buf == NULL) {
        *out_err = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }
    if (udp) {
        err = GetExtendedUdpTable(buf, &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
    } else {
        err = GetExtendedTcpTable(buf, &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    if (err != NO_ERROR) {
        free(buf);
        *out_err = err;
        return NULL;
    }
    *out_err = NO_ERROR;
    return buf;
}

static void walk_tcp4(struct emit_ctx *c)
{
    DWORD err;
    MIB_TCPTABLE_OWNER_PID *t = read_table(0, 0, &err);
    if (t == NULL) {
        return;
    }
    for (DWORD i = 0; i < t->dwNumEntries; i++) {
        const MIB_TCPROW_OWNER_PID *r = &t->table[i];
        struct endpoint e;
        e.proto = "TCP";
        char ip[46];
        fmt_v4(r->dwLocalAddr, ip, sizeof ip);
        snprintf(e.local, sizeof e.local, "%s:%u", ip, port_of(r->dwLocalPort));
        e.exposed = (r->dwLocalAddr == 0);
        fmt_v4(r->dwRemoteAddr, ip, sizeof ip);
        // A remote port of 0 on a non-connected socket (e.g. LISTEN) is noise.
        if (r->dwState == MIB_TCP_STATE_LISTEN) {
            e.remote[0] = '\0';
            e.rscope = "";
        } else {
            snprintf(e.remote, sizeof e.remote, "%s:%u", ip, port_of(r->dwRemotePort));
            e.rscope = ioc_ip_scope(ip);
        }
        e.state = tcp_state(r->dwState);
        e.pid = r->dwOwningPid;
        e.proc = procmap_name(c->map, e.pid);
        e.is_udp = 0;
        e.listening = (r->dwState == MIB_TCP_STATE_LISTEN);
        emit_row(c, &e);
    }
    free(t);
}

// 1 if a 16-byte IPv6 address is :: (bound to every interface).
static int all_zero16(const UCHAR a[16])
{
    for (int i = 0; i < 16; i++) {
        if (a[i] != 0) return 0;
    }
    return 1;
}

static void walk_tcp6(struct emit_ctx *c)
{
    DWORD err;
    MIB_TCP6TABLE_OWNER_PID *t = read_table(0, 1, &err);
    if (t == NULL) {
        return;
    }
    for (DWORD i = 0; i < t->dwNumEntries; i++) {
        const MIB_TCP6ROW_OWNER_PID *r = &t->table[i];
        struct endpoint e;
        e.proto = "TCP6";
        char ip[46];
        fmt_v6(r->ucLocalAddr, ip, sizeof ip);
        snprintf(e.local, sizeof e.local, "[%s]:%u", ip, port_of(r->dwLocalPort));
        if (r->dwState == MIB_TCP_STATE_LISTEN) {
            e.remote[0] = '\0';
        } else {
            fmt_v6(r->ucRemoteAddr, ip, sizeof ip);
            snprintf(e.remote, sizeof e.remote, "[%s]:%u", ip, port_of(r->dwRemotePort));
        }
        e.state = tcp_state(r->dwState);
        e.pid = r->dwOwningPid;
        e.proc = procmap_name(c->map, e.pid);
        e.is_udp = 0;
        e.listening = (r->dwState == MIB_TCP_STATE_LISTEN);
        // IPv6 peers are not scope-classified here (no IPv6 table in ioc.c yet).
        e.rscope = e.remote[0] ? "ipv6" : "";
        e.exposed = all_zero16(r->ucLocalAddr);
        emit_row(c, &e);
    }
    free(t);
}

static void walk_udp4(struct emit_ctx *c)
{
    DWORD err;
    MIB_UDPTABLE_OWNER_PID *t = read_table(1, 0, &err);
    if (t == NULL) {
        return;
    }
    for (DWORD i = 0; i < t->dwNumEntries; i++) {
        const MIB_UDPROW_OWNER_PID *r = &t->table[i];
        struct endpoint e;
        e.proto = "UDP";
        char ip[46];
        fmt_v4(r->dwLocalAddr, ip, sizeof ip);
        snprintf(e.local, sizeof e.local, "%s:%u", ip, port_of(r->dwLocalPort));
        e.remote[0] = '\0';        // UDP is connectionless: no fixed peer
        e.state = "";
        e.pid = r->dwOwningPid;
        e.proc = procmap_name(c->map, e.pid);
        e.is_udp = 1;
        e.listening = 1;           // a bound UDP socket is effectively "listening"
        e.rscope = "";
        e.exposed = (r->dwLocalAddr == 0);
        emit_row(c, &e);
    }
    free(t);
}

static void walk_udp6(struct emit_ctx *c)
{
    DWORD err;
    MIB_UDP6TABLE_OWNER_PID *t = read_table(1, 1, &err);
    if (t == NULL) {
        return;
    }
    for (DWORD i = 0; i < t->dwNumEntries; i++) {
        const MIB_UDP6ROW_OWNER_PID *r = &t->table[i];
        struct endpoint e;
        e.proto = "UDP6";
        char ip[46];
        fmt_v6(r->ucLocalAddr, ip, sizeof ip);
        snprintf(e.local, sizeof e.local, "[%s]:%u", ip, port_of(r->dwLocalPort));
        e.remote[0] = '\0';
        e.state = "";
        e.pid = r->dwOwningPid;
        e.proc = procmap_name(c->map, e.pid);
        e.is_udp = 1;
        e.listening = 1;
        e.rscope = "";
        e.exposed = all_zero16(r->ucLocalAddr);
        emit_row(c, &e);
    }
    free(t);
}

int cmd_net(int argc, char **argv)
{
    const char *pid_arg = NULL;
    int mode = NET_TEXT;
    int want_tcp = 0, want_udp = 0;        // neither set => both
    int listening_only = 0, established_only = 0;
    int external_only = 0, exposed_only = 0, flagged_only = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)            mode = NET_JSON;
        else if (strcmp(argv[a], "--csv") == 0)        mode = NET_CSV;
        else if (strcmp(argv[a], "--tcp") == 0)        want_tcp = 1;
        else if (strcmp(argv[a], "--udp") == 0)        want_udp = 1;
        else if (strcmp(argv[a], "--listening") == 0)  listening_only = 1;
        else if (strcmp(argv[a], "--established") == 0) established_only = 1;
        else if (strcmp(argv[a], "--external") == 0)   external_only = 1;
        else if (strcmp(argv[a], "--exposed") == 0)    exposed_only = 1;
        else if (strcmp(argv[a], "--flagged") == 0)    flagged_only = 1;
        else if (pid_arg == NULL)                      pid_arg = argv[a];
        else {
            fprintf(stderr, "net: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (!want_tcp && !want_udp) {           // no family filter given: show both
        want_tcp = want_udp = 1;
    }

    DWORD filter = 0;
    if (pid_arg != NULL) {
        char *end = NULL;
        unsigned long pid = strtoul(pid_arg, &end, 10);
        if (end == pid_arg || *end != '\0' || pid == 0) {
            fprintf(stderr, "net: '%s' is not a valid pid\n", pid_arg);
            return 1;
        }
        filter = (DWORD)pid;
    }

    struct procmap map;
    procmap_build(&map);

    struct emit_ctx c;
    c.mode = mode;
    c.first = 1;
    c.filter = filter;
    c.want_tcp = want_tcp;
    c.want_udp = want_udp;
    c.listening_only = listening_only;
    c.established_only = established_only;
    c.external_only = external_only;
    c.exposed_only = exposed_only;
    c.flagged_only = flagged_only;
    c.flagged = 0;
    c.map = &map;
    c.count = 0;

    if (mode == NET_TEXT) {
        if (filter) { printf("endpoints for pid %lu\n\n", (unsigned long)filter); }
        printf("      %-5s %-28s %-28s %-12s %-6s %s\n",
               "proto", "local", "remote", "state", "pid", "process");
    } else if (mode == NET_CSV) {
        puts("proto,local,remote,state,pid,process,remote_scope,listening_all_interfaces,path,reason");
    } else {
        putchar('[');
    }

    walk_tcp4(&c);
    walk_tcp6(&c);
    walk_udp4(&c);
    walk_udp6(&c);

    if (mode == NET_TEXT) {
        printf("\n%u endpoints, %u flagged\n", c.count, c.flagged);
    } else if (mode == NET_JSON) {
        puts("]");
    }
    free(map.v);
    return 0;
}
