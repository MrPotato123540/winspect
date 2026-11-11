// Boot / shutdown / clock events (see bootparse.h). Portable C.

#include "bootparse.h"
#include "artparse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ci_eq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) if ((*a | 0x20) != (*b | 0x20)) return 0;
    return *a == *b;
}

// Decodes the five XML entities while copying [s, e) into out.
static void xml_text(const char *s, const char *e, char *out, size_t cap)
{
    static const struct { const char *ent; char c; } ents[] = {
        { "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' }, { "&quot;", '"' }, { "&apos;", '\'' } };
    size_t o = 0;
    while (s < e && o + 1 < cap) {
        int hit = 0;
        if (*s == '&') {
            for (size_t i = 0; i < sizeof ents / sizeof ents[0]; i++) {
                size_t L = strlen(ents[i].ent);
                if ((size_t)(e - s) >= L && strncmp(s, ents[i].ent, L) == 0) { out[o++] = ents[i].c; s += L; hit = 1; break; }
            }
        }
        if (!hit) out[o++] = *s++;
    }
    out[o] = '\0';
}

int evt_data_nth(const char *xml, int n, char *out, size_t cap)
{
    out[0] = '\0';
    const char *p = xml;
    int idx = 0;
    while ((p = strstr(p, "<Data")) != NULL) {
        char c = p[5];
        if (c == '>') {                                  // unnamed, has content
            const char *s = p + 6, *e = strstr(s, "</Data>");
            if (e == NULL) return 0;
            if (idx == n) { xml_text(s, e, out, cap); return 1; }
            idx++;
            p = e + 7;
        } else if (c == '/' && p[6] == '>') {            // <Data/>: an empty string
            if (idx == n) return 1;
            idx++;
            p += 7;
        } else {
            p += 5;                                      // named (<Data Name=...>) or another element
        }
    }
    return 0;
}

int evt_provider(const char *xml, char *out, size_t cap)
{
    out[0] = '\0';
    const char *p = strstr(xml, "<Provider");
    if (p == NULL) return 0;
    const char *end = strchr(p, '>');
    const char *nm = strstr(p, "Name=");
    if (end == NULL || nm == NULL || nm > end) return 0;
    char q = nm[5];
    if (q != '"' && q != '\'') return 0;
    const char *s = nm + 6, *e = strchr(s, q);
    if (e == NULL || e > end) return 0;
    xml_text(s, e, out, cap);
    return 1;
}

int64_t iso_epoch(const char *t)
{
    int Y = 0, M = 0, D = 0, h = 0, m = 0, s = 0;
    char sep = 0;
    if (sscanf(t, "%4d-%2d-%2d%c%2d:%2d:%2d", &Y, &M, &D, &sep, &h, &m, &s) != 7) return -1;
    if (M < 1 || M > 12 || D < 1 || D > 31 || h > 23 || m > 59 || s > 60 || h < 0 || m < 0 || s < 0) return -1;
    // Days from a civil date (the standard era arithmetic; March-based year).
    Y -= M <= 2;
    int64_t era = (Y >= 0 ? Y : Y - 399) / 400;
    unsigned yoe = (unsigned)(Y - era * 400);
    unsigned doy = (153u * (unsigned)(M + (M > 2 ? -3 : 9)) + 2u) / 5u + (unsigned)D - 1u;
    unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return (era * 146097 + (int64_t)doe - 719468) * 86400 + h * 3600 + m * 60 + s;
}

void fmt_span(int64_t s, char *out, size_t n)
{
    if (s < 0) s = -s;
    if (s < 60) snprintf(out, n, "%llds", (long long)s);
    else if (s < 3600) snprintf(out, n, "%lldm %llds", (long long)(s / 60), (long long)(s % 60));
    else if (s < 86400) snprintf(out, n, "%lldh %lldm", (long long)(s / 3600), (long long)(s % 3600 / 60));
    else snprintf(out, n, "%lldd %lldh", (long long)(s / 86400), (long long)(s % 86400 / 3600));
}

// Windows writes invisible left-to-right marks (U+200E) around localized
// dates; they only confuse a terminal.
static void strip_marks(char *s)
{
    char *w = s;
    for (char *p = s; *p;) {
        if ((unsigned char)p[0] == 0xE2 && (unsigned char)p[1] == 0x80 && ((unsigned char)p[2] == 0x8E || (unsigned char)p[2] == 0x8F)) p += 3;
        else *w++ = *p++;
    }
    *w = '\0';
}

int boot_parse(const char *xml, boot_rec *r)
{
    memset(r, 0, sizeof *r);
    char idtxt[16], prov[96];
    evt_system(xml, "EventID", idtxt, sizeof idtxt);
    r->id = (unsigned)strtoul(idtxt, NULL, 10);
    if (!evt_provider(xml, prov, sizeof prov)) return 0;
    evt_time(xml, r->time, sizeof r->time);
    char a[320], b[320], c[320];
    if (ci_eq(prov, "Microsoft-Windows-Kernel-General")) {
        if (r->id == 12) {
            r->kind = BK_START;
            evt_data(xml, "MajorVersion", a, sizeof a);
            evt_data(xml, "MinorVersion", b, sizeof b);
            evt_data(xml, "BuildVersion", c, sizeof c);
            snprintf(r->detail, sizeof r->detail, "operating system started (Windows %.8s.%.8s build %.12s)", a, b, c);
        } else if (r->id == 13) {
            r->kind = BK_STOP;
            snprintf(r->detail, sizeof r->detail, "operating system shutting down");
        } else if (r->id == 1) {
            r->kind = BK_CLOCK;
            evt_data(xml, "OldTime", a, sizeof a);
            evt_data(xml, "NewTime", b, sizeof b);
            int64_t t0 = iso_epoch(a), t1 = iso_epoch(b);
            if (t0 < 0 || t1 < 0) return 0;
            r->clock_delta = t1 - t0;
            char span[32];
            fmt_span(r->clock_delta, span, sizeof span);
            snprintf(r->detail, sizeof r->detail, "system clock set %s by %s (%.19s -> %.19s)",
                     r->clock_delta < 0 ? "BACK" : "forward", span, a, b);
            for (char *p = r->detail; *p; p++) if (*p == 'T' && p > r->detail && p[-1] >= '0' && p[-1] <= '9' && p[1] >= '0' && p[1] <= '9') *p = ' ';
        } else return 0;
    } else if (ci_eq(prov, "Microsoft-Windows-Kernel-Power") && r->id == 41) {
        r->kind = BK_POWER_LOSS;
        evt_data(xml, "BugcheckCode", a, sizeof a);
        unsigned long code = strtoul(a, NULL, 0);
        if (code) snprintf(r->detail, sizeof r->detail, "rebooted without a clean shutdown, after a crash (bugcheck 0x%lX)", code);
        else snprintf(r->detail, sizeof r->detail, "rebooted without a clean shutdown (power loss, reset or hang)");
    } else if (ci_eq(prov, "EventLog") && r->id == 6008) {
        r->kind = BK_UNEXPECTED;
        evt_data_nth(xml, 0, a, sizeof a);
        evt_data_nth(xml, 1, b, sizeof b);
        strip_marks(a);
        strip_marks(b);
        snprintf(r->detail, sizeof r->detail, "the previous shutdown, at %.60s on %.60s (local time as logged), was unexpected", a, b);
    } else if (ci_eq(prov, "User32") && r->id == 1074) {
        r->kind = BK_REQUEST;
        char reason[320], comment[320];
        evt_data_nth(xml, 0, a, sizeof a);              // process (computer)
        evt_data_nth(xml, 2, reason, sizeof reason);
        evt_data_nth(xml, 4, r->action, sizeof r->action);
        evt_data_nth(xml, 5, comment, sizeof comment);
        evt_data_nth(xml, 6, r->user, sizeof r->user);
        // "C:\Windows\system32\winlogon.exe (HOSTNAME)" -> the path alone.
        char *paren = strstr(a, " (");
        if (paren) *paren = '\0';
        snprintf(r->process, sizeof r->process, "%.290s", a);
        const char *base = strrchr(a, '\\');
        snprintf(r->detail, sizeof r->detail, "%.30s requested by %.120s via %.80s%s%.120s%s%.120s", r->action[0] ? r->action : "shutdown",
                 r->user[0] ? r->user : "?", base ? base + 1 : a, reason[0] ? ": " : "", reason, comment[0] ? " - " : "", comment);
    } else {
        return 0;
    }
    return 1;
}

const char *boot_kind_name(enum boot_kind k)
{
    switch (k) {
    case BK_START:      return "boot";
    case BK_STOP:       return "shutdown";
    case BK_CLOCK:      return "clock";
    case BK_POWER_LOSS: return "no clean stop";
    case BK_UNEXPECTED: return "unexpected";
    case BK_REQUEST:    return "requested";
    default:            return "";
    }
}
