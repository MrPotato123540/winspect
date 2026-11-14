// winspect boots - boot / shutdown history and clock changes
//
// bootparse.c (portable, unit-tested) turns each event into a record; this
// file collects them (live System log or .evtx), pairs each boot with the
// shutdown that ended it - in record order, which a clock change cannot
// disturb - and prints.

#include "boots.h"
#include "bootparse.h"
#include "evsrc.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <winevt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    boot_rec r;
    int64_t uptime;             // BK_START: seconds until its shutdown, -1 unknown
    int clean;                  // BK_START: 1 ended by a shutdown event, 0 not, -1 still running / log ends
} brow;

typedef struct {
    brow *v;
    size_t n, cap;
    char since[24];
    int all;                    // --all: also Windows' own forward clock adjustments
    unsigned hidden_clock;
} blist;

static void on_event(const char *xml, void *vctx)
{
    blist *l = (blist *)vctx;
    brow w;
    if (!boot_parse(xml, &w.r)) return;
    // Small clock corrections (time sync) are constant noise.
    if (w.r.kind == BK_CLOCK && w.r.clock_delta > -60 && w.r.clock_delta < 60) return;
    // Forward adjustments Windows makes itself (reason other than 1 = "an
    // application or system component changed the time") follow every wake
    // from sleep or hibernation: hundreds on a laptop. Changes BACK, and every
    // change an application made, are always listed.
    if (w.r.kind == BK_CLOCK && !l->all && w.r.clock_delta > 0 && w.r.clock_reason > 1) { l->hidden_clock++; return; }
    if (l->since[0] && strcmp(w.r.time, l->since) < 0) return;
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 128;
        brow *nv = (brow *)realloc(l->v, nc * sizeof *nv);
        if (nv == NULL) return;
        l->v = nv;
        l->cap = nc;
    }
    w.uptime = -1;
    w.clean = -1;
    l->v[l->n++] = w;
}

int cmd_boots(int argc, char **argv)
{
    int mode = 0, all = 0;
    unsigned max = 5000, hours = 0;
    char *files[32];
    int nfiles = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--evtx") == 0 && a + 1 < argc) {
            if (nfiles == 32) { fputs("boots: at most 32 --evtx files\n", stderr); return 1; }
            files[nfiles++] = argv[++a];
        }
        else if (strcmp(argv[a], "--json") == 0) mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else if (strcmp(argv[a], "--all") == 0)  all = 1;
        else if (strcmp(argv[a], "--since") == 0 && a + 1 < argc) {
            hours = (unsigned)strtoul(argv[++a], NULL, 10);
            if (hours == 0 || hours > 24u * 3650u) { fputs("boots: --since takes hours, 1..87600\n", stderr); return 1; }
        }
        else if (strcmp(argv[a], "--max") == 0 && a + 1 < argc) {
            max = (unsigned)strtoul(argv[++a], NULL, 10);
            if (max == 0 || max > 1000000) { fputs("boots: --max must be 1..1000000\n", stderr); return 1; }
        }
        else {
            fprintf(stderr, "boots: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    blist l;
    memset(&l, 0, sizeof l);
    l.all = all;
    unsigned readable = 0;
    if (nfiles) {
        if (hours) {
            FILETIME now;
            GetSystemTimeAsFileTime(&now);
            uint64_t t = ((uint64_t)now.dwHighDateTime << 32 | now.dwLowDateTime) - (uint64_t)hours * 36000000000ULL;
            char iso[40];
            filetime_utc_str(t, iso, sizeof iso);
            snprintf(l.since, sizeof l.since, "%.19s", iso);
        }
        for (int i = 0; i < nfiles; i++) {
            int dirty = 0;
            int rc = evsrc_file(files[i], on_event, &l, &dirty);
            if (rc == 1) fprintf(stderr, "boots: cannot open '%s' (error %lu)\n", files[i], (unsigned long)GetLastError());
            else if (rc == 2) fprintf(stderr, "boots: '%s' is not an .evtx file\n", files[i]);
            else {
                readable++;
                if (dirty) fprintf(stderr, "boots: note: %s was not closed cleanly (copied while in use?)\n", files[i]);
            }
        }
    } else {
        // Event IDs only; the provider is checked per event (bootparse.c).
        char xpath[512];
        if (evt_xpath_since("*[System[(EventID=12 or EventID=13 or EventID=1 or EventID=41 or EventID=6008 or EventID=1074)]]",
                            hours, xpath, sizeof xpath) == 0) {
            DWORD err = evsrc_live("System", xpath, max, on_event, &l);
            if (err == 0) readable++;
            else fprintf(stderr, "boots: System log: %s (error %lu)\n",
                         err == ERROR_ACCESS_DENIED ? "access denied" : "cannot query", (unsigned long)err);
        }
    }
    if (readable == 0) {
        if (mode == 1) puts("[]");
        free(l.v);
        return 1;
    }
    // Rows stay in the order the events were WRITTEN (record order), not
    // sorted by timestamp: when the clock is set back, a later event carries
    // an earlier time, and sorting would pair boots with the wrong shutdown.
    // A file is already oldest-first; the live query returns newest-first.
    if (nfiles == 0) {
        for (size_t i = 0, j = l.n; i + 1 < j; i++) { j--; brow t = l.v[i]; l.v[i] = l.v[j]; l.v[j] = t; }
    }

    // Pair every boot with what ended it: a shutdown event before the next
    // boot means a clean end; a next boot without one means it was not.
    for (size_t i = 0; i < l.n; i++) {
        if (l.v[i].r.kind != BK_START) continue;
        for (size_t k = i + 1; k < l.n; k++) {
            if (l.v[k].r.kind == BK_STOP) {
                int64_t a = iso_epoch(l.v[i].r.time), b = iso_epoch(l.v[k].r.time);
                if (a >= 0 && b >= a) l.v[i].uptime = b - a;
                l.v[i].clean = 1;
                break;
            }
            if (l.v[k].r.kind == BK_START) { l.v[i].clean = 0; break; }
        }
    }

    if (mode == 0) {
        puts("boots  (boot / shutdown history and clock changes; newest first in the order written, UTC)\n");
        printf("    %-19s  %-13s %s\n", "time", "event", "detail");
    } else if (mode == 2) {
        puts("time,event,id,detail,uptime_s,clean_shutdown,clock_delta_s,action,user,process,clock_reason");
    } else {
        putchar('[');
    }
    unsigned boots = 0, unclean = 0, clock = 0;
    for (size_t k = l.n; k-- > 0;) {
        const brow *w = &l.v[k];
        const boot_rec *r = &w->r;
        char detail[760];
        snprintf(detail, sizeof detail, "%s", r->detail);
        if (r->kind == BK_START) {
            boots++;
            size_t o = strlen(detail);
            char span[32];
            if (w->clean == 1 && w->uptime >= 0) {
                fmt_span(w->uptime, span, sizeof span);
                snprintf(detail + o, sizeof detail - o, "; shut down cleanly %s later (wall clock, sleep included)", span);
            } else if (w->clean == 1) {
                snprintf(detail + o, sizeof detail - o, "; shut down cleanly (uptime unknown: the clock was changed in between)");
            } else if (w->clean == 0) {
                unclean++;
                snprintf(detail + o, sizeof detail - o, "; NO shutdown event before the next boot");
            }
        }
        if (r->kind == BK_CLOCK) clock++;
        if (mode == 0) {
            printf("    %-19s  %-13s %s\n", r->time, boot_kind_name(r->kind), detail);
        } else if (mode == 2) {
            printf("%s,%s,%u,", r->time, boot_kind_name(r->kind), r->id);
            csv_str(detail); putchar(',');
            if (w->uptime >= 0) printf("%lld", (long long)w->uptime);
            putchar(',');
            if (r->kind == BK_START && w->clean >= 0) printf("%d", w->clean);
            putchar(',');
            if (r->kind == BK_CLOCK) printf("%lld", (long long)r->clock_delta);
            putchar(',');
            csv_str(r->action); putchar(',');
            csv_str(r->user); putchar(',');
            csv_str(r->process); putchar(',');
            if (r->kind == BK_CLOCK && r->clock_reason >= 0) printf("%d", r->clock_reason);
            putchar('\n');
        } else {
            printf("%s{\"time\":\"%s\",\"event\":\"%s\",\"id\":%u,\"detail\":", k + 1 < l.n ? "," : "", r->time, boot_kind_name(r->kind), r->id);
            json_str(detail);
            fputs(",\"uptime_s\":", stdout);
            if (w->uptime >= 0) printf("%lld", (long long)w->uptime); else fputs("null", stdout);
            fputs(",\"clean_shutdown\":", stdout);
            if (r->kind == BK_START && w->clean >= 0) fputs(w->clean ? "true" : "false", stdout); else fputs("null", stdout);
            fputs(",\"clock_delta_s\":", stdout);
            if (r->kind == BK_CLOCK) printf("%lld", (long long)r->clock_delta); else fputs("null", stdout);
            fputs(",\"action\":", stdout);  json_str(r->action);
            fputs(",\"user\":", stdout);    json_str(r->user);
            fputs(",\"process\":", stdout); json_str(r->process);
            fputs(",\"clock_reason\":", stdout);
            if (r->kind == BK_CLOCK && r->clock_reason >= 0) printf("%d", r->clock_reason); else fputs("null", stdout);
            putchar('}');
        }
    }
    if (mode == 1) puts("]");
    else if (mode == 0) {
        printf("\n%u boot(s), %u not preceded by a clean shutdown, %u clock change(s) of a minute or more listed", boots, unclean, clock);
        if (l.hidden_clock) printf("; %u forward adjustment(s) made by Windows itself (wake from sleep) hidden, --all shows them", l.hidden_clock);
        putchar('\n');
    }
    free(l.v);
    return 0;
}
