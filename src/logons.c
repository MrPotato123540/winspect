// winspect logons - logon history from the event logs
//
// `last` on Linux answers "who was on this machine, from where, until when"
// from wtmp. Windows spreads the same facts over several Security events
// keyed by a logon ID; this command joins them back together:
//
//   4624 logon  --(TargetLogonId)-->  4634 / 4647 logoff     => duration
//               --(SubjectLogonId)--> 4672 special privileges => "admin"
//
// and adds the Terminal Services session log, which survives even where
// Security auditing is thin. Parsing and the flag rules live in
// logonparse.c (portable, unit-tested); this file only collects, joins and
// prints. Read-only: EvtQuery or the .evtx reader.

#include "logons.h"
#include "logonparse.h"
#include "evsrc.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define LSM_CHANNEL "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

typedef struct {
    logon_rec r;
    const char *reason;
    int admin;
    char logoff[24];
    int64_t duration;           // seconds, -1 unknown
} row;

typedef struct {
    row *v;
    size_t n, cap;
    char since[24];             // "" or earliest time kept
    int oom;
} rows;

static void on_event(const char *xml, void *vctx)
{
    rows *l = (rows *)vctx;
    char channel[160];
    evt_system(xml, "Channel", channel, sizeof channel);
    row w;
    if (!logon_parse(xml, channel, &w.r)) return;
    if (l->since[0] && strcmp(w.r.time, l->since) < 0) return;
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 256;
        row *nv = (row *)realloc(l->v, nc * sizeof *nv);
        if (nv == NULL) { l->oom = 1; return; }
        l->v = nv;
        l->cap = nc;
    }
    w.reason = logon_reason(&w.r);
    w.admin = 0;
    w.logoff[0] = '\0';
    w.duration = -1;
    l->v[l->n++] = w;
}

static int by_time(const void *a, const void *b)
{
    const row *x = (const row *)a, *y = (const row *)b;
    int c = strcmp(x->r.time, y->r.time);
    if (c) return c;
    // Same second: the logon before the events that refer to it.
    return (x->r.kind != LK_LOGON) - (y->r.kind != LK_LOGON);
}

// "YYYY-MM-DD HH:MM:SS" -> seconds since 1970 (proleptic Gregorian), -1 if malformed.
static int64_t to_epoch(const char *t)
{
    int Y, M, D, h, m, s;
    if (sscanf(t, "%4d-%2d-%2d %2d:%2d:%2d", &Y, &M, &D, &h, &m, &s) != 6) return -1;
    // Days from civil date (Howard Hinnant's public-domain formulation of the
    // standard era arithmetic): shift the year so it starts in March.
    Y -= M <= 2;
    int64_t era = (Y >= 0 ? Y : Y - 399) / 400;
    unsigned yoe = (unsigned)(Y - era * 400);
    unsigned doy = (153u * (unsigned)(M + (M > 2 ? -3 : 9)) + 2u) / 5u + (unsigned)D - 1u;
    unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    int64_t days = era * 146097 + (int64_t)doe - 719468;
    return days * 86400 + h * 3600 + m * 60 + s;
}

// Joins logoffs and privilege events to their logon. Rows are sorted oldest
// first. Walking from the newest row backwards, a table remembers for every
// logon ID the EARLIEST logoff seen so far; when the logon itself comes up,
// that entry is its logoff (IDs are reused after a reboot, so the entry is
// dropped once used).
static void join_sessions(rows *l)
{
    size_t slots = 64;
    while (slots < l->n * 2) slots *= 2;
    struct slot { uint64_t id; size_t idx; int used; } *tab = (struct slot *)calloc(slots, sizeof *tab);
    if (tab == NULL) return;
    for (size_t k = l->n; k-- > 0;) {
        row *w = &l->v[k];
        if (w->r.logon_id[0] == '\0') continue;
        uint64_t id = strtoull(w->r.logon_id, NULL, 16);
        size_t h = (size_t)((id * 0x9E3779B97F4A7C15ULL) >> 20) & (slots - 1);
        while (tab[h].used && tab[h].id != id) h = (h + 1) & (slots - 1);
        if (w->r.kind == LK_LOGOFF) {
            tab[h].used = 1;
            tab[h].id = id;
            tab[h].idx = k;
        } else if (w->r.kind == LK_LOGON && tab[h].used && tab[h].idx != (size_t)-1) {
            const row *off = &l->v[tab[h].idx];
            snprintf(w->logoff, sizeof w->logoff, "%s", off->r.time);
            int64_t a = to_epoch(w->r.time), b = to_epoch(off->r.time);
            if (a >= 0 && b >= a) w->duration = b - a;
            tab[h].idx = (size_t)-1;                 // consumed; keeps the probe chain intact
        }
    }
    free(tab);
    // 4672 is written right after its 4624 (same or next second), so a short
    // look back is enough and stays linear.
    for (size_t k = 0; k < l->n; k++) {
        if (l->v[k].r.kind != LK_PRIVILEGED) continue;
        int64_t tp = to_epoch(l->v[k].r.time);
        for (size_t back = 1; back <= 64 && back <= k; back++) {
            row *c = &l->v[k - back];
            int64_t tc = to_epoch(c->r.time);
            if (tp >= 0 && tc >= 0 && tp - tc > 5) break;
            if (c->r.kind == LK_LOGON && strcmp(c->r.logon_id, l->v[k].r.logon_id) == 0) {
                c->admin = 1;
                break;
            }
        }
    }
}

static void fmt_duration(int64_t s, char *out, size_t n)
{
    if (s < 0) { out[0] = '\0'; return; }
    if (s < 60) snprintf(out, n, "%llds", (long long)s);
    else if (s < 3600) snprintf(out, n, "%lldm %llds", (long long)(s / 60), (long long)(s % 60));
    else if (s < 86400) snprintf(out, n, "%lldh %lldm", (long long)(s / 3600), (long long)(s % 3600 / 60));
    else snprintf(out, n, "%lldd %lldh", (long long)(s / 86400), (long long)(s % 86400 / 3600));
}

static const char *type_text(const logon_rec *r, char *buf, size_t n)
{
    const char *t = logon_type_name(r->type);
    if (t[0]) return t;
    if (r->type) { snprintf(buf, n, "type %u", r->type); return buf; }
    return "";
}

typedef struct {
    char user[192], source[96];
    unsigned type;
    enum logon_kind kind;
    unsigned count, admin;
    char first[24], last[24];
    const char *reason;
} group;

int cmd_logons(int argc, char **argv)
{
    int mode = 0, all = 0, only_flagged = 0, summary = 0;
    unsigned max = 5000, hours = 0, want_type = 0;
    const char *user = NULL;
    char *files[32];
    int nfiles = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--evtx") == 0 && a + 1 < argc) {
            if (nfiles == 32) { fputs("logons: at most 32 --evtx files\n", stderr); return 1; }
            files[nfiles++] = argv[++a];
        }
        else if (strcmp(argv[a], "--json") == 0)    mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)     mode = 2;
        else if (strcmp(argv[a], "--all") == 0)     all = 1;
        else if (strcmp(argv[a], "--flagged") == 0) only_flagged = 1;
        else if (strcmp(argv[a], "--summary") == 0) summary = 1;
        else if (strcmp(argv[a], "--user") == 0 && a + 1 < argc) user = argv[++a];
        else if (strcmp(argv[a], "--type") == 0 && a + 1 < argc) {
            want_type = (unsigned)strtoul(argv[++a], NULL, 10);
            if (want_type == 0 || want_type > 13) { fputs("logons: --type takes a logon type, 2..13\n", stderr); return 1; }
        }
        else if (strcmp(argv[a], "--since") == 0 && a + 1 < argc) {
            hours = (unsigned)strtoul(argv[++a], NULL, 10);
            if (hours == 0 || hours > 24u * 3650u) { fputs("logons: --since takes hours, 1..87600\n", stderr); return 1; }
        }
        else if (strcmp(argv[a], "--max") == 0 && a + 1 < argc) {
            max = (unsigned)strtoul(argv[++a], NULL, 10);
            if (max == 0 || max > 1000000) { fputs("logons: --max must be 1..1000000\n", stderr); return 1; }
        }
        else {
            fprintf(stderr, "logons: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    rows l;
    memset(&l, 0, sizeof l);
    char notes[512] = "";
    size_t nl = 0;
    unsigned readable = 0;
    if (nfiles) {
        if (hours) {
            FILETIME now;
            GetSystemTimeAsFileTime(&now);
            uint64_t t = ((uint64_t)now.dwHighDateTime << 32 | now.dwLowDateTime) - (uint64_t)hours * 36000000000ULL;
            char iso[32];
            filetime_utc_str(t, iso, sizeof iso);
            snprintf(l.since, sizeof l.since, "%.19s", iso);
        }
        for (int i = 0; i < nfiles; i++) {
            int dirty = 0;
            int rc = evsrc_file(files[i], on_event, &l, &dirty);
            if (rc == 1) fprintf(stderr, "logons: cannot open '%s' (error %lu)\n", files[i], (unsigned long)GetLastError());
            else if (rc == 2) fprintf(stderr, "logons: '%s' is not an .evtx file\n", files[i]);
            else {
                readable++;
                if (dirty) fprintf(stderr, "logons: note: %s was not closed cleanly (copied while in use?)\n", files[i]);
            }
        }
    } else {
        static const struct { const char *channel, *label, *xpath; } chans[] = {
            { "Security", "Security",
              "*[System[(EventID=4624 or EventID=4634 or EventID=4647 or EventID=4648 or EventID=4672 or "
              "EventID=4778 or EventID=4779)]]" },
            { LSM_CHANNEL, "TerminalServices-LocalSessionManager",
              "*[System[(EventID=21 or EventID=23 or EventID=24 or EventID=25)]]" },
        };
        for (size_t i = 0; i < sizeof chans / sizeof chans[0]; i++) {
            char xpath[768];
            if (evt_xpath_since(chans[i].xpath, hours, xpath, sizeof xpath) != 0) continue;
            DWORD err = evsrc_live(chans[i].channel, xpath, max, on_event, &l);
            if (err == 0) { readable++; continue; }
            const char *why = err == ERROR_ACCESS_DENIED ? "access denied - run elevated"
                            : err == ERROR_EVT_CHANNEL_NOT_FOUND ? "channel not present"
                            : "cannot query";
            int w = snprintf(notes + nl, sizeof notes - nl, "  %s: %s (error %lu)\n", chans[i].label, why, (unsigned long)err);
            if (w > 0 && (size_t)w < sizeof notes - nl) nl += (size_t)w;
        }
    }
    if (readable == 0) {
        if (mode == 1) puts("[]");
        if (notes[0]) fprintf(stderr, "logons: no log could be read:\n%s", notes);
        free(l.v);
        return 1;
    }
    if (l.oom) fputs("logons: out of memory, the list is incomplete\n", stderr);

    qsort(l.v, l.n, sizeof *l.v, by_time);
    join_sessions(&l);

    // ---- select ---------------------------------------------------------------
    unsigned shown = 0, flagged = 0, hidden = 0;
    static group groups[4096];
    unsigned ng = 0, group_overflow = 0;
    if (mode == 0 && !summary) {
        printf("logons  (newest first, UTC%s)\n\n", all ? "" : "; service and system-account logons hidden, --all shows them");
        printf("    %-19s  %-11s %-18s %-30s %-22s %s\n", "time", "event", "type", "account", "source", "detail");
    } else if (mode == 2 && !summary) {
        puts("time,event,id,logon_type,type_name,account,by,source,workstation,server,process,auth,ntlm,logon_id,session,admin,logoff,duration_s,reason");
    } else if (mode == 1) {
        putchar('[');
    }
    int first = 1;
    for (size_t k = l.n; k-- > 0;) {
        const row *w = &l.v[k];
        const logon_rec *r = &w->r;
        if (r->kind == LK_LOGOFF || r->kind == LK_PRIVILEGED) continue;     // folded into the logon
        if (!all && logon_is_noise(r)) { hidden++; continue; }
        if (want_type && r->type != want_type) continue;
        if (user && !ioc_contains_ci(r->user, user) && !ioc_contains_ci(r->by, user)) continue;
        if (only_flagged && w->reason == NULL) continue;
        shown++;
        if (w->reason) flagged++;
        char tb[24];
        const char *tname = type_text(r, tb, sizeof tb);
        const char *src = r->source[0] ? r->source : r->workstation;

        if (summary) {
            unsigned g = 0;
            for (; g < ng; g++) {
                if (groups[g].type == r->type && groups[g].kind == r->kind && _stricmp(groups[g].user, r->user) == 0 &&
                        _stricmp(groups[g].source, src) == 0) break;
            }
            if (g == ng) {
                if (ng == sizeof groups / sizeof groups[0]) { group_overflow++; continue; }
                memset(&groups[g], 0, sizeof groups[g]);
                snprintf(groups[g].user, sizeof groups[g].user, "%s", r->user);
                snprintf(groups[g].source, sizeof groups[g].source, "%s", src);
                groups[g].type = r->type;
                groups[g].kind = r->kind;
                snprintf(groups[g].last, sizeof groups[g].last, "%s", r->time);    // newest comes first
                ng++;
            }
            groups[g].count++;
            groups[g].admin += (unsigned)w->admin;
            snprintf(groups[g].first, sizeof groups[g].first, "%s", r->time);
            if (w->reason) groups[g].reason = w->reason;
            continue;
        }

        char dur[32];
        fmt_duration(w->duration, dur, sizeof dur);
        if (mode == 0) {
            char detail[512];
            size_t o = 0;
            detail[0] = '\0';
#define ADD(...) do { int w_ = snprintf(detail + o, sizeof detail - o, __VA_ARGS__); \
                      if (w_ > 0 && (size_t)w_ < sizeof detail - o) o += (size_t)w_; } while (0)
            if (w->admin) ADD("admin");
            if (r->auth[0]) ADD("%s%s%s%s", o ? ", " : "", r->auth, r->lm[0] ? " " : "", r->lm);
            if (r->kind == LK_EXPLICIT) ADD("%sby %s%s%s", o ? ", " : "", r->by, r->server[0] ? " for " : "", r->server);
            if (r->session[0]) ADD("%ssession %s", o ? ", " : "", r->session);
            if (w->logoff[0]) ADD("%suntil %s (%s)", o ? ", " : "", w->logoff + 11, dur);
            if (r->process[0] && (r->kind == LK_EXPLICIT || r->type == 9 || r->type == 2)) {
                const char *b = strrchr(r->process, '\\');
                ADD("%svia %s", o ? ", " : "", b ? b + 1 : r->process);
            }
#undef ADD
            printf("%s %-19s  %-11s %-18s %-30s %-22s %s\n", w->reason ? "[!]" : "   ", r->time,
                   logon_kind_name(r->kind), tname, r->user, src, detail);
            if (w->reason) printf("        <- %s\n", w->reason);
        } else if (mode == 2) {
            printf("%s,%s,%u,", r->time, logon_kind_name(r->kind), r->id);
            if (r->type) printf("%u", r->type);
            putchar(',');
            csv_str(tname); putchar(',');
            csv_str(r->user); putchar(',');
            csv_str(r->by); putchar(',');
            csv_str(r->source); putchar(',');
            csv_str(r->workstation); putchar(',');
            csv_str(r->server); putchar(',');
            csv_str(r->process); putchar(',');
            csv_str(r->auth); putchar(',');
            csv_str(r->lm); putchar(',');
            csv_str(r->logon_id); putchar(',');
            csv_str(r->session);
            printf(",%d,%s,", w->admin, w->logoff);
            if (w->duration >= 0) printf("%lld", (long long)w->duration);
            putchar(',');
            csv_str(w->reason ? w->reason : ""); putchar('\n');
        } else {
            printf("%s{\"time\":\"%s\",\"event\":\"%s\",\"id\":%u,\"logon_type\":%u,\"type_name\":", first ? "" : ",",
                   r->time, logon_kind_name(r->kind), r->id, r->type);
            json_str(tname);
            fputs(",\"account\":", stdout);     json_str(r->user);
            fputs(",\"by\":", stdout);          json_str(r->by);
            fputs(",\"source\":", stdout);      json_str(r->source);
            fputs(",\"workstation\":", stdout); json_str(r->workstation);
            fputs(",\"server\":", stdout);      json_str(r->server);
            fputs(",\"process\":", stdout);     json_str(r->process);
            fputs(",\"auth\":", stdout);        json_str(r->auth);
            fputs(",\"ntlm\":", stdout);        json_str(r->lm);
            fputs(",\"logon_id\":", stdout);    json_str(r->logon_id);
            fputs(",\"session\":", stdout);     json_str(r->session);
            printf(",\"admin\":%s,\"logoff\":\"%s\",\"duration_s\":", w->admin ? "true" : "false", w->logoff);
            if (w->duration >= 0) printf("%lld", (long long)w->duration); else fputs("null", stdout);
            printf(",\"suspicious\":%s,\"reason\":", w->reason ? "true" : "false");
            json_str(w->reason ? w->reason : "");
            putchar('}');
            first = 0;
        }
    }

    if (summary) {
        if (mode == 0) {
            printf("logons --summary  (by account, type and source%s)\n\n", all ? "" : "; service and system-account logons hidden");
            printf("    %6s %-11s %-18s %-30s %-22s %-19s  %-19s\n", "count", "event", "type", "account", "source", "first (UTC)", "last (UTC)");
        } else if (mode == 2) {
            puts("count,event,logon_type,type_name,account,source,first,last,admin_sessions,reason");
        }
        for (unsigned g = 0; g < ng; g++) {
            const group *q = &groups[g];
            logon_rec tmp;
            memset(&tmp, 0, sizeof tmp);
            tmp.type = q->type;
            char tb[24];
            const char *tname = type_text(&tmp, tb, sizeof tb);
            if (mode == 0) {
                printf("%s %6u %-11s %-18s %-30s %-22s %-19s  %-19s%s\n", q->reason ? "[!]" : "   ", q->count,
                       logon_kind_name(q->kind), tname, q->user, q->source, q->first, q->last, q->admin ? "  admin" : "");
                if (q->reason) printf("        <- %s\n", q->reason);
            } else if (mode == 2) {
                printf("%u,%s,", q->count, logon_kind_name(q->kind));
                if (q->type) printf("%u", q->type);
                putchar(',');
                csv_str(tname); putchar(',');
                csv_str(q->user); putchar(',');
                csv_str(q->source);
                printf(",%s,%s,%u,", q->first, q->last, q->admin);
                csv_str(q->reason ? q->reason : ""); putchar('\n');
            } else {
                printf("%s{\"count\":%u,\"event\":\"%s\",\"logon_type\":%u,\"type_name\":", g ? "," : "", q->count,
                       logon_kind_name(q->kind), q->type);
                json_str(tname);
                fputs(",\"account\":", stdout); json_str(q->user);
                fputs(",\"source\":", stdout);  json_str(q->source);
                printf(",\"first\":\"%s\",\"last\":\"%s\",\"admin_sessions\":%u,\"suspicious\":%s,\"reason\":",
                       q->first, q->last, q->admin, q->reason ? "true" : "false");
                json_str(q->reason ? q->reason : "");
                putchar('}');
            }
        }
        if (group_overflow) fprintf(stderr, "logons: summary table full, %u row(s) not grouped (narrow with --since / --user)\n", group_overflow);
    }

    if (mode == 1) {
        puts("]");
    } else if (mode == 0) {
        if (summary) printf("\n%u group(s) from %u event(s), %u flagged", ng, shown, flagged);
        else printf("\n%u event(s), %u flagged", shown, flagged);
        if (hidden) printf("; %u service / system-account event(s) hidden", hidden);
        putchar('\n');
        if (notes[0]) printf("\nlogs not read:\n%s", notes);
    }
    if (mode != 0 && notes[0]) fputs(notes, stderr);
    free(l.v);
    return 0;
}
