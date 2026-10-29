// winspect events - high-signal event log timeline
//
// The event logs record most of what an intruder does - but among millions of
// routine events. Incident responders start with a short list of event IDs
// that almost always matter (the same starting point tools like Chainsaw or
// Hayabusa use; we take only that idea, with our own fixed list, no rule
// engine):
//
//   System     7045  a service was installed (classic persistence / PsExec)
//              104   an event log was cleared
//   Security   1102  the Security log was cleared
//              4625  failed logon (password guessing)
//              4720  user account created
//              4728/4732/4756  member added to a security group
//              4698  scheduled task created     4697  service installed
//   Defender   1116/1117  malware detected / action taken
//              5001  real-time protection disabled
//   Tasks      106   task registered
//   RDP        1149  remote desktop authentication succeeded
//   PowerShell 4104 at WARNING level: a script block Windows itself judged
//              suspicious (logged even when script block logging is off)
//
// We query each channel newest-first with an XPath filter (EvtQuery), render
// each event as XML (EvtRender) and pull the few fields that matter with the
// portable evt_* helpers (artparse.c, unit-tested). Rows from all channels are
// merged into one timeline, newest first.
//
// --since <hours> narrows every query to a time window (XPath timediff);
// --summary groups failed logons (4625) by source address with distinct
// account counts - the "who is guessing passwords?" view.
//
// Read-only: EvtQuery/EvtNext/EvtRender only. The Security channel needs
// elevation; a denied or missing channel is reported, never silently skipped.
//
// --evtx <file> (repeatable) reads copied .evtx files instead (evtx.c renders
// each record to the same XML EvtRender gives); every record goes through the
// same channel / event ID / level filters, --since and --max, and --summary.

#include "events.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"
#include "evtx.h"

#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char time[24];
    char channel[16];
    unsigned id;
    char summary[640];
    const char *reason;     // static string or NULL
} evrow;

typedef struct {
    evrow *v;
    size_t n, cap;
} evlist;

static void add_row(evlist *l, const evrow *r)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 64;
        evrow *nv = (evrow *)realloc(l->v, nc * sizeof *nv);
        if (nv == NULL) return;
        l->v = nv;
        l->cap = nc;
    }
    l->v[l->n++] = *r;
}

static int newest_first(const void *a, const void *b)
{
    return -strcmp(((const evrow *)a)->time, ((const evrow *)b)->time);
}

// Build the one-line summary (+ optional flag) for an event we know.
static void describe(const char *xml, unsigned id, evrow *r)
{
    char a[512], b[512], c[256], d[256];
    r->reason = NULL;
    switch (id) {
    case 7045:
    case 4697:
        evt_data(xml, "ServiceName", a, sizeof a);
        if (!evt_data(xml, "ImagePath", b, sizeof b)) evt_data(xml, "ServiceFileName", b, sizeof b);
        evt_data(xml, "AccountName", c, sizeof c);
        snprintf(r->summary, sizeof r->summary, "service installed: %s -> %s%s%s", a, b,
                 c[0] ? " as " : "", c);
        if (ioc_script_host(b))        r->reason = "service runs a script host / LOLBin";
        else if (ioc_user_writable(b)) r->reason = "service binary in user-writable dir";
        break;
    case 104:
    case 1102:
        // The clearer's name lives in <UserData>, not <EventData>.
        evt_system(xml, "SubjectUserName", a, sizeof a);
        evt_system(xml, "SubjectDomainName", b, sizeof b);
        snprintf(r->summary, sizeof r->summary, "%s log cleared by %s%s%s",
                 id == 1102 ? "Security" : "an event", b, b[0] ? "\\" : "", a[0] ? a : "?");
        r->reason = "event log cleared (anti-forensics?)";
        break;
    case 4625:
        evt_data(xml, "TargetUserName", a, sizeof a);
        evt_data(xml, "IpAddress", b, sizeof b);
        evt_data(xml, "LogonType", c, sizeof c);
        snprintf(r->summary, sizeof r->summary, "failed logon: %s from %s (type %s)", a,
                 b[0] ? b : "-", c);
        break;
    case 4720:
        evt_data(xml, "TargetUserName", a, sizeof a);
        evt_data(xml, "SubjectUserName", b, sizeof b);
        snprintf(r->summary, sizeof r->summary, "user account created: %s (by %s)", a, b);
        r->reason = "new local/domain account";
        break;
    case 4728:
    case 4732:
    case 4756:
        evt_data(xml, "MemberName", a, sizeof a);
        if (a[0] == '\0' || strcmp(a, "-") == 0) evt_data(xml, "MemberSid", a, sizeof a);
        evt_data(xml, "TargetUserName", b, sizeof b);
        evt_data(xml, "SubjectUserName", c, sizeof c);
        snprintf(r->summary, sizeof r->summary, "added to group %s: %s (by %s)", b, a, c);
        if (ioc_contains_ci(b, "admin")) r->reason = "member added to an admin group";
        break;
    case 4698:
        evt_data(xml, "TaskName", a, sizeof a);
        evt_data(xml, "SubjectUserName", b, sizeof b);
        snprintf(r->summary, sizeof r->summary, "scheduled task created: %s (by %s)", a, b);
        break;
    case 106:
        evt_data(xml, "TaskName", a, sizeof a);
        evt_data(xml, "UserContext", b, sizeof b);
        snprintf(r->summary, sizeof r->summary, "task registered: %s (user %s)", a, b);
        break;
    case 1116:
    case 1117:
        evt_data(xml, "Threat Name", a, sizeof a);
        evt_data(xml, "Path", b, sizeof b);
        evt_data(xml, "Action Name", c, sizeof c);
        snprintf(r->summary, sizeof r->summary, "Defender %s: %s at %s%s%s",
                 id == 1116 ? "detected" : "acted on", a, b, c[0] ? " - " : "", c);
        r->reason = "malware detection";
        break;
    case 5001:
        snprintf(r->summary, sizeof r->summary, "Defender real-time protection was disabled");
        r->reason = "protection turned off";
        break;
    case 1149:
        evt_system(xml, "Param1", a, sizeof a);
        evt_system(xml, "Param2", b, sizeof b);
        evt_system(xml, "Param3", c, sizeof c);
        snprintf(r->summary, sizeof r->summary, "RDP logon: %s%s%s from %s", b, b[0] ? "\\" : "", a, c);
        break;
    case 4104:
        evt_data(xml, "ScriptBlockText", a, sizeof a);
        evt_data(xml, "Path", d, sizeof d);
        for (char *p = a; *p; p++) {
            if (*p == '\r' || *p == '\n' || *p == '\t') *p = ' ';
        }
        if (strlen(a) > 160) strcpy(a + 157, "...");
        snprintf(r->summary, sizeof r->summary, "suspicious PowerShell%s%s: %s",
                 d[0] ? " in " : "", d, a);
        r->reason = "Windows flagged this script block as suspicious";
        break;
    default:
        snprintf(r->summary, sizeof r->summary, "event %u", id);
        break;
    }
}

typedef struct {
    const char *channel;    // full channel path
    const char *label;      // short name for the table
    const char *xpath;
} chan;

static const chan channels[] = {
    { "System", "System",
      "*[System[(EventID=7045 or EventID=104)]]" },
    { "Security", "Security",
      "*[System[(EventID=1102 or EventID=4625 or EventID=4720 or EventID=4728 or "
      "EventID=4732 or EventID=4756 or EventID=4698 or EventID=4697)]]" },
    { "Microsoft-Windows-Windows Defender/Operational", "Defender",
      "*[System[(EventID=1116 or EventID=1117 or EventID=5001)]]" },
    { "Microsoft-Windows-TaskScheduler/Operational", "Tasks",
      "*[System[(EventID=106)]]" },
    { "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "RDP",
      "*[System[(EventID=1149)]]" },
    { "Microsoft-Windows-PowerShell/Operational", "PowerShell",
      "*[System[(EventID=4104) and (Level=3)]]" },
};

// Failed logons only, for --summary.
static const chan fail_channel = { "Security", "Security", "*[System[(EventID=4625)]]" };

// One rendered event (live or from an .evtx file): a listed row, or with
// fails != NULL a failed-logon count.
static void handle_xml(const char *xml, const char *label, evlist *out, evt_fail_table *fails)
{
    evrow r;
    memset(&r, 0, sizeof r);
    char idtxt[16];
    evt_system(xml, "EventID", idtxt, sizeof idtxt);
    r.id = (unsigned)strtoul(idtxt, NULL, 10);
    evt_time(xml, r.time, sizeof r.time);
    snprintf(r.channel, sizeof r.channel, "%s", label);
    if (fails != NULL) {
        char ip[64], user[128];
        evt_data(xml, "IpAddress", ip, sizeof ip);
        evt_data(xml, "TargetUserName", user, sizeof user);
        evt_fail_add(fails, ip, user, r.time);
    } else {
        describe(xml, r.id, &r);
        add_row(out, &r);
    }
}

// Query one channel; returns 0 ok, else the Win32 error. hours > 0 limits it
// to the last <hours> hours. With fails != NULL, 4625 events are counted per
// source address instead of being listed.
static DWORD read_channel(const chan *ch, unsigned max, unsigned hours, evlist *out,
                          evt_fail_table *fails)
{
    WCHAR wpath[256], wxpath[512];
    char xpath[512];
    MultiByteToWideChar(CP_UTF8, 0, ch->channel, -1, wpath, 256);
    if (evt_xpath_since(ch->xpath, hours, xpath, sizeof xpath) != 0) {
        return ERROR_INVALID_PARAMETER;
    }
    MultiByteToWideChar(CP_UTF8, 0, xpath, -1, wxpath, 512);
    EVT_HANDLE q = EvtQuery(NULL, wpath, wxpath, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (q == NULL) {
        return GetLastError();
    }
    unsigned got_total = 0;
    WCHAR *wxml = NULL;
    DWORD wcap = 0;
    while (got_total < max) {
        EVT_HANDLE ev[16];
        DWORD got = 0;
        if (!EvtNext(q, 16, ev, 5000, 0, &got)) {
            break;      // ERROR_NO_MORE_ITEMS or timeout: done
        }
        for (DWORD i = 0; i < got; i++) {
            if (got_total < max) {
                DWORD used = 0, props = 0;
                if (!EvtRender(NULL, ev[i], EvtRenderEventXml, wcap, wxml, &used, &props) &&
                        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    // Byte count from EvtRender; round up to whole WCHARs.
                    DWORD chars = (used + 1) / (DWORD)sizeof(WCHAR);
                    DWORD bytes = chars * (DWORD)sizeof(WCHAR);
                    WCHAR *nb = (WCHAR *)realloc(wxml, (size_t)chars * sizeof(WCHAR));
                    if (nb != NULL) {
                        wxml = nb;
                        wcap = bytes;
                        EvtRender(NULL, ev[i], EvtRenderEventXml, wcap, wxml, &used, &props);
                    }
                }
                if (wxml != NULL && used > 0) {
                    int need = WideCharToMultiByte(CP_UTF8, 0, wxml, -1, NULL, 0, NULL, NULL);
                    char *xml = need > 0 ? (char *)malloc((size_t)need) : NULL;
                    if (xml != NULL) {
                        WideCharToMultiByte(CP_UTF8, 0, wxml, -1, xml, need, NULL, NULL);
                        handle_xml(xml, ch->label, out, fails);
                        free(xml);
                        got_total++;
                    }
                }
            }
            EvtClose(ev[i]);
        }
    }
    free(wxml);
    EvtClose(q);
    return 0;
}

// ---- offline: .evtx files --------------------------------------------------------

typedef struct {
    evlist *out;
    evt_fail_table *fails;
    char since[24];             // "" or the earliest time to keep (UTC)
    unsigned long seen, kept;
} offctx;

static void off_record(uint64_t id, uint64_t written, const char *xml, void *vctx)
{
    (void)id; (void)written;
    offctx *o = (offctx *)vctx;
    o->seen++;
    char chname[160], idtxt[16], lvl[8], when[24];
    evt_system(xml, "Channel", chname, sizeof chname);
    evt_system(xml, "EventID", idtxt, sizeof idtxt);
    evt_system(xml, "Level", lvl, sizeof lvl);
    unsigned eid = (unsigned)strtoul(idtxt, NULL, 10), level = (unsigned)strtoul(lvl, NULL, 10);
    const chan *c = NULL;
    if (o->fails) {
        if (_stricmp(chname, fail_channel.channel) == 0 && evt_xpath_match(fail_channel.xpath, eid, level)) c = &fail_channel;
    } else {
        for (size_t i = 0; i < sizeof channels / sizeof channels[0] && c == NULL; i++)
            if (_stricmp(chname, channels[i].channel) == 0 && evt_xpath_match(channels[i].xpath, eid, level))
                c = &channels[i];
    }
    if (c == NULL) return;
    evt_time(xml, when, sizeof when);
    if (o->since[0] && strcmp(when, o->since) < 0) return;
    handle_xml(xml, c->label, o->out, o->fails);
    o->kept++;
}

// Reads every file; rows of the same channel are later cut to `max` newest.
static int read_evtx_files(char **files, int nfiles, unsigned hours, evlist *out, evt_fail_table *fails)
{
    offctx o;
    memset(&o, 0, sizeof o);
    o.out = out;
    o.fails = fails;
    if (hours) {
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        uint64_t t = ((uint64_t)now.dwHighDateTime << 32 | now.dwLowDateTime) - (uint64_t)hours * 36000000000ULL;
        char iso[32];
        filetime_utc_str(t, iso, sizeof iso);
        snprintf(o.since, sizeof o.since, "%s", iso);
    }
    int rc = 0;
    for (int i = 0; i < nfiles; i++) {
        HANDLE h = CreateFileA(files[i], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "events: cannot open '%s' (error %lu)\n", files[i], (unsigned long)GetLastError());
            rc = 1;
            continue;
        }
        LARGE_INTEGER sz;
        unsigned char *d = NULL;
        DWORD got = 0;
        if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (1LL << 31) &&
                (d = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL) {
            if (!ReadFile(h, d, (DWORD)sz.QuadPart, &got, NULL)) got = 0;
        }
        CloseHandle(h);
        evtx_file f;
        if (d == NULL || evtx_open(&f, d, got) != 0) {
            fprintf(stderr, "events: '%s' is not an .evtx file\n", files[i]);
            free(d);
            rc = 1;
            continue;
        }
        if (f.dirty) fprintf(stderr, "events: note: %s was not closed cleanly (copied while in use?)\n", files[i]);
        evtx_records(&f, off_record, &o);
        free(d);
    }
    return rc;
}

// Keep at most `max` rows per channel (rows already sorted newest first).
static void cap_per_channel(evlist *l, unsigned max)
{
    size_t w = 0;
    for (size_t i = 0; i < l->n; i++) {
        unsigned seen = 0;
        for (size_t j = 0; j < w; j++) if (strcmp(l->v[j].channel, l->v[i].channel) == 0) seen++;
        if (seen < max) l->v[w++] = l->v[i];
    }
    l->n = w;
}

// --summary: failed logons grouped by source address.
static int fail_summary(unsigned max, unsigned hours, int mode, char **files, int nfiles)
{
    static evt_fail_table t;
    memset(&t, 0, sizeof t);
    DWORD err = nfiles ? (DWORD)read_evtx_files(files, nfiles, hours, NULL, &t)
                       : read_channel(&fail_channel, max, hours, NULL, &t);
    if (nfiles && err) return 1;
    if (err != 0) {
        fprintf(stderr, "events: Security log: %s (error %lu)\n",
                err == ERROR_ACCESS_DENIED ? "access denied - run elevated" : "cannot query",
                (unsigned long)err);
        return 1;
    }
    if (mode == 0) {
        printf("events --summary  (failed logons by source%s)\n\n",
               hours ? ", time-limited" : "");
        printf("    %-40s %6s %6s  %-19s  %-19s\n", "source", "fails", "users", "first (UTC)", "last (UTC)");
    } else if (mode == 2) {
        puts("source,failures,distinct_users,first,last,users,reason");
    } else {
        putchar('[');
    }
    for (unsigned i = 0; i < t.n; i++) {
        const evt_fail_src *s = &t.src[i];
        const char *v = evt_fail_verdict(s);
        char users[512] = "";
        size_t ul = 0;
        for (unsigned u = 0; u < s->nusers && ul + 70 < sizeof users; u++) {
            ul += (size_t)snprintf(users + ul, sizeof users - ul, "%s%s", u ? ", " : "", s->users[u]);
        }
        if (mode == 0) {
            printf("%s%-40s %6u %6u  %-19s  %-19s\n", v ? "[!] " : "    ", s->ip, s->count,
                   s->nusers, s->first, s->last);
            printf("        accounts: %s\n", users);
            if (v) printf("        <- %s\n", v);
        } else if (mode == 2) {
            csv_str(s->ip);
            printf(",%u,%u,", s->count, s->nusers);
            csv_str(s->first); putchar(',');
            csv_str(s->last);  putchar(',');
            csv_str(users);    putchar(',');
            csv_str(v ? v : ""); putchar('\n');
        } else {
            printf("%s{\"source\":", i ? "," : "");
            json_str(s->ip);
            printf(",\"failures\":%u,\"distinct_users\":%u,\"first\":", s->count, s->nusers);
            json_str(s->first);
            fputs(",\"last\":", stdout);  json_str(s->last);
            fputs(",\"users\":[", stdout);
            for (unsigned u = 0; u < s->nusers; u++) {
                if (u) putchar(',');
                json_str(s->users[u]);
            }
            printf("],\"suspicious\":%s,\"reason\":", v ? "true" : "false");
            json_str(v ? v : "");
            putchar('}');
        }
    }
    if (mode == 1) {
        puts("]");
    } else if (mode == 0) {
        printf("\n%u source(s)%s\n", t.n, t.n >= EVT_FAIL_MAX_SRC ? " (table full - narrow with --since)" : "");
    }
    return 0;
}

int cmd_events(int argc, char **argv)
{
    int mode = 0, summary = 0;
    unsigned max = 0, hours = 0;
    char *files[32];
    int nfiles = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--evtx") == 0 && a + 1 < argc) {
            if (nfiles == 32) { fputs("events: at most 32 --evtx files\n", stderr); return 1; }
            files[nfiles++] = argv[++a];
        }
        else if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else if (strcmp(argv[a], "--summary") == 0) summary = 1;
        else if (strcmp(argv[a], "--since") == 0 && a + 1 < argc) {
            hours = (unsigned)strtoul(argv[++a], NULL, 10);
            if (hours == 0 || hours > 24u * 3650u) {
                fputs("events: --since takes hours, 1..87600\n", stderr);
                return 1;
            }
        }
        else if (strcmp(argv[a], "--max") == 0 && a + 1 < argc) {
            max = (unsigned)strtoul(argv[++a], NULL, 10);
            if (max == 0 || max > 10000) {
                fputs("events: --max must be 1..10000\n", stderr);
                return 1;
            }
        }
        else {
            fprintf(stderr, "events: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (summary) {
        return fail_summary(max ? max : 10000, hours, mode, files, nfiles);
    }
    if (max == 0) {
        max = 20;
    }

    evlist rows = { NULL, 0, 0 };
    char notes[1024] = "";
    size_t nl = 0;
    unsigned readable = 0;
    for (size_t i = 0; nfiles == 0 && i < sizeof channels / sizeof channels[0]; i++) {
        DWORD err = read_channel(&channels[i], max, hours, &rows, NULL);
        if (err == 0) {
            readable++;
            continue;
        }
        const char *why = err == ERROR_ACCESS_DENIED ? "access denied - run elevated"
                        : err == ERROR_EVT_CHANNEL_NOT_FOUND ? "channel not present"
                        : "cannot query";
        int w = snprintf(notes + nl, sizeof notes - nl, "  %s: %s (error %lu)\n",
                         channels[i].label, why, (unsigned long)err);
        if (w > 0 && (size_t)w < sizeof notes - nl) nl += (size_t)w;
    }
    if (nfiles) {
        if (read_evtx_files(files, nfiles, hours, &rows, NULL) != 0 && rows.n == 0) {
            free(rows.v);
            return 1;
        }
        readable = 1;
    }
    qsort(rows.v, rows.n, sizeof *rows.v, newest_first);
    if (nfiles) cap_per_channel(&rows, max);

    unsigned flagged = 0;
    if (mode == 0) {
        printf("events  (high-signal IDs, newest first, up to %u per channel", max);
        if (hours) printf(", last %u h", hours);
        puts(")\n");
        printf("  %-19s  %-10s %-5s %s\n", "time (UTC)", "channel", "id", "summary");
    } else if (mode == 2) {
        puts("time,channel,id,summary,reason");
    } else {
        putchar('[');
    }
    for (size_t i = 0; i < rows.n; i++) {
        const evrow *r = &rows.v[i];
        flagged += r->reason != NULL;
        if (mode == 0) {
            printf("  %-19s  %-10s %-5u %s\n", r->time, r->channel, r->id, r->summary);
            if (r->reason) {
                printf("  %-19s  [!] %s\n", "", r->reason);
            }
        } else if (mode == 2) {
            csv_str(r->time);    putchar(',');
            csv_str(r->channel); printf(",%u,", r->id);
            csv_str(r->summary); putchar(',');
            csv_str(r->reason ? r->reason : ""); putchar('\n');
        } else {
            printf("%s{\"time\":", i ? "," : "");
            json_str(r->time);
            fputs(",\"channel\":", stdout); json_str(r->channel);
            printf(",\"id\":%u,\"summary\":", r->id);
            json_str(r->summary);
            printf(",\"suspicious\":%s,\"reason\":", r->reason ? "true" : "false");
            json_str(r->reason ? r->reason : "");
            putchar('}');
        }
    }
    if (mode == 1) {
        puts("]");
    } else if (mode == 0) {
        printf("\n%lu event(s), %u flagged\n", (unsigned long)rows.n, flagged);
        if (notes[0]) {
            printf("\nchannels not read:\n%s", notes);
        }
    }
    if (mode != 0 && notes[0]) {
        fputs(notes, stderr);
    }
    free(rows.v);
    return readable > 0 ? 0 : 1;
}
