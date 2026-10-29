// winspect timeline - merge the timestamps of the evidence commands
//
// Every source below is an existing command. It is run in-process with
// --json, its stdout captured (capture.c) and parsed (jsonmini.c), and one
// small extractor per source turns its records into rows of
//   time | source | what happened | detail | suspicious
// Only timestamps that MEAN something are used, e.g. a BagMRU / RunMRU /
// RDP-MRU key's last-write time is the time of its most recent entry only,
// so only the entry at MRU position 0 gets it; a shimcache entry's time is the
// FILE's modification time, never an execution time, and says so.
// All sources print UTC "YYYY-MM-DD hh:mm:ss", so plain string order is time
// order. Read-only.

#include "timeline.h"
#include "capture.h"
#include "jsonmini.h"
#include "jsonutil.h"
#include "prefetch.h"
#include "bam.h"
#include "userassist.h"
#include "shimcache.h"
#include "recyclebin.h"
#include "shellbags.h"
#include "usb.h"
#include "lnk.h"
#include "jumplist.h"
#include "pshistory.h"
#include "rdp.h"
#include "mru.h"
#include "users.h"
#include "bitsjobs.h"
#include "tasks.h"
#include "comhijack.h"
#include "events.h"
#include "sysinfo.h"
#include "amcache.h"
#include "browser.h"
#include "pca.h"
#include "activities.h"
#include "webcache.h"
#include "imgpaths.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    char time[20];
    const char *source;
    char user[64];              // profile name (--root, per-user sources) or ""
    char *what, *detail;
    int suspicious;
} row;

typedef struct {
    row *rows;
    size_t n, cap;
    char since[20];             // "" = no lower bound
    const char *source;         // current source name
    const char *user;           // current profile (--root) or NULL
} tl;

// "YYYY-MM-DD hh:mm:ss" or ISO "...T..." -> canonical 19 chars; 0 if not a time.
static int norm_time(const char *in, char out[20])
{
    if (in == NULL || strlen(in) < 19) return 0;
    for (int i = 0; i < 19; i++) {
        char c = in[i];
        int digit = c >= '0' && c <= '9';
        if (i == 4 || i == 7) { if (c != '-') return 0; }
        else if (i == 10) { if (c != ' ' && c != 'T') return 0; c = ' '; }
        else if (i == 13 || i == 16) { if (c != ':') return 0; }
        else if (!digit) return 0;
        out[i] = c;
    }
    out[19] = 0;
    return strncmp(out, "1601", 4) != 0 && strncmp(out, "0000", 4) != 0;
}

static void add(tl *t, const char *when, const char *what, const char *detail, int suspicious)
{
    char ts[20];
    if (!norm_time(when, ts)) return;
    if (t->since[0] && strcmp(ts, t->since) < 0) return;
    if (t->n == t->cap) {
        size_t nc = t->cap ? t->cap * 2 : 256;
        row *r = (row *)realloc(t->rows, nc * sizeof *r);
        if (r == NULL) return;
        t->rows = r;
        t->cap = nc;
    }
    row *r = &t->rows[t->n];
    memcpy(r->time, ts, sizeof ts);
    r->source = t->source;
    snprintf(r->user, sizeof r->user, "%s", t->user ? t->user : "");
    r->what = _strdup(what);
    r->detail = _strdup(detail ? detail : "");
    if (r->what == NULL || r->detail == NULL) { free(r->what); free(r->detail); return; }
    r->suspicious = suspicious;
    t->n++;
}

static const char *S(const jm_node *o, const char *k) { const char *v = jm_gets(o, k); return v ? v : ""; }
static int B(const jm_node *o, const char *k) { const jm_node *v = jm_get(o, k); return v && v->type == JM_BOOL && v->boolean; }
static double N(const jm_node *o, const char *k) { const jm_node *v = jm_get(o, k); return v && v->type == JM_NUM ? v->num : -1; }

static void cat(char *out, size_t n, const char *a, const char *b)
{
    snprintf(out, n, "%s%s", a, b);
}

// ---- per-source extractors ---------------------------------------------------

static void x_prefetch(tl *t, const jm_node *r)
{
    char w[1200];
    const char *p = S(r, "path");
    cat(w, sizeof w, "program ran: ", p[0] ? p : S(r, "executable"));
    const jm_node *times = jm_get(r, "run_times");
    for (const jm_node *e = times && times->type == JM_ARR ? times->child : NULL; e; e = e->next)
        if (e->type == JM_STR) add(t, e->str, w, S(r, "file"), B(r, "suspicious"));
}

static void x_bam(tl *t, const jm_node *r)
{
    char w[1200];
    cat(w, sizeof w, "program ran: ", S(r, "path"));
    add(t, S(r, "last_run"), w, S(r, "user"), B(r, "user_writable_dir"));
}

static void x_userassist(tl *t, const jm_node *r)
{
    char w[1200];
    cat(w, sizeof w, "opened from the shell: ", S(r, "program"));
    add(t, S(r, "last_run"), w, S(r, "reason"), B(r, "suspicious"));
}

static void x_shimcache(tl *t, const jm_node *r)
{
    char w[1200];
    cat(w, sizeof w, "file modified (AppCompatCache entry, not a run time): ", S(r, "path"));
    add(t, S(r, "file_modified"), w, "", B(r, "user_writable_dir"));
}

static void x_recyclebin(tl *t, const jm_node *r)
{
    char w[1200];
    cat(w, sizeof w, "deleted to Recycle Bin: ", S(r, "path"));
    add(t, S(r, "deleted"), w, S(r, "owner"), B(r, "suspicious"));
}

static void x_shellbags(tl *t, const jm_node *r)
{
    char w[1200];
    if (N(r, "mru_position") != 0) return;   // key time = most recent entry only
    cat(w, sizeof w, "folder browsed (most recent in its BagMRU key): ", S(r, "path"));
    add(t, S(r, "key_written"), w, S(r, "key"), 0);
}

static void x_usb(tl *t, const jm_node *r)
{
    char w[600], d[300];
    const char *name = S(r, "friendly_name");
    snprintf(d, sizeof d, "serial %s", S(r, "serial"));
    snprintf(w, sizeof w, "USB storage first installed: %s", name);
    add(t, S(r, "first_installed"), w, d, 0);
    snprintf(w, sizeof w, "USB storage last connected: %s", name);
    add(t, S(r, "last_connected"), w, d, 0);
    snprintf(w, sizeof w, "USB storage last removed: %s", name);
    add(t, S(r, "last_removed"), w, d, 0);
}

static void x_lnk(tl *t, const jm_node *r)
{
    char w[1200];
    cat(w, sizeof w, "shortcut target created: ", S(r, "target"));
    add(t, S(r, "target_created"), w, S(r, "file"), B(r, "suspicious"));
    cat(w, sizeof w, "shortcut target modified: ", S(r, "target"));
    add(t, S(r, "target_modified"), w, S(r, "file"), B(r, "suspicious"));
}

static void x_jumplist(tl *t, const jm_node *r)
{
    char w[1200], d[200];
    cat(w, sizeof w, "opened (Jump List): ", S(r, "target"));
    snprintf(d, sizeof d, "AppID %s", S(r, "appid"));
    add(t, S(r, "last_used"), w, d, B(r, "suspicious"));
}

// One row per history file: its last-write time is the time of its last
// command (lines carry no times of their own).
typedef struct { char file[520], written[32], last[1024]; unsigned lines; int flagged; } pshist;
static pshist ps_cur;

static void ps_flush(tl *t)
{
    if (ps_cur.file[0] == 0) return;
    char w[1200], d[700];
    snprintf(w, sizeof w, "PowerShell history last written (%u command(s)%s); last: %s", ps_cur.lines,
             ps_cur.flagged ? ", some flagged" : "", ps_cur.last);
    snprintf(d, sizeof d, "%s", ps_cur.file);
    add(t, ps_cur.written, w, d, ps_cur.flagged);
    memset(&ps_cur, 0, sizeof ps_cur);
}

static void x_pshistory(tl *t, const jm_node *r)
{
    if (strcmp(ps_cur.file, S(r, "file")) != 0) {
        ps_flush(t);
        snprintf(ps_cur.file, sizeof ps_cur.file, "%s", S(r, "file"));
        snprintf(ps_cur.written, sizeof ps_cur.written, "%s", S(r, "file_written"));
    }
    ps_cur.lines++;
    ps_cur.flagged |= B(r, "suspicious");
    snprintf(ps_cur.last, sizeof ps_cur.last, "%s", S(r, "command"));
}

static void x_rdp(tl *t, const jm_node *r)
{
    char w[600];
    if (N(r, "position") != 0) return;
    cat(w, sizeof w, "Remote Desktop connection (most recent): ", S(r, "host"));
    add(t, S(r, "time"), w, S(r, "source"), 0);
}

static void x_mru(tl *t, const jm_node *r)
{
    char w[1200];
    if (N(r, "position") != 0) return;
    snprintf(w, sizeof w, "%s (most recent): %s", S(r, "list"), S(r, "value"));
    add(t, S(r, "time"), w, S(r, "reason"), B(r, "suspicious"));
}

static void x_users(tl *t, const jm_node *r)
{
    char w[400];
    cat(w, sizeof w, "last logon: ", S(r, "name"));
    add(t, S(r, "last_logon"), w, "", B(r, "suspicious"));
    cat(w, sizeof w, "password set: ", S(r, "name"));
    add(t, S(r, "password_set"), w, "", B(r, "suspicious"));
}

static void x_bits(tl *t, const jm_node *r)
{
    char w[700];
    cat(w, sizeof w, "BITS job created: ", S(r, "name"));
    add(t, S(r, "created"), w, S(r, "notify"), B(r, "suspicious"));
    cat(w, sizeof w, "BITS job completed: ", S(r, "name"));
    add(t, S(r, "completed"), w, "", B(r, "suspicious"));
}

static void x_tasks(tl *t, const jm_node *r)
{
    char w[700], d[1200];
    cat(w, sizeof w, "scheduled task registered (date written in the task by its author): ", S(r, "task"));
    snprintf(d, sizeof d, "%s %s", S(r, "command"), S(r, "arguments"));
    add(t, S(r, "registered"), w, d, B(r, "suspicious"));
}

static void x_comhijack(tl *t, const jm_node *r)
{
    char w[300];
    cat(w, sizeof w, "per-user COM class registered: ", S(r, "clsid"));
    add(t, S(r, "key_written"), w, S(r, "user_server"), B(r, "suspicious"));
}

static void x_events(tl *t, const jm_node *r)
{
    char w[1200];
    snprintf(w, sizeof w, "event %.0f (%s): %s", N(r, "id"), S(r, "channel"), S(r, "summary"));
    add(t, S(r, "time"), w, S(r, "reason"), B(r, "suspicious"));
}

static void x_amcache(tl *t, const jm_node *r)
{
    char w[1200], d[200];
    cat(w, sizeof w, "program recorded in Amcache: ", S(r, "path"));
    snprintf(d, sizeof d, "SHA-1 %s", S(r, "sha1"));
    add(t, S(r, "recorded"), w, d, B(r, "suspicious"));
}

static void x_browser(tl *t, const jm_node *r)
{
    char w[2400];
    const char *kind = S(r, "kind");
    if (strcmp(kind, "download") == 0)
        snprintf(w, sizeof w, "%s download: %s -> %s", S(r, "browser"), S(r, "url"), S(r, "saved_to"));
    else
        snprintf(w, sizeof w, "%s visit (last): %s", S(r, "browser"), S(r, "url"));
    add(t, S(r, "time"), w, S(r, "reason"), B(r, "suspicious"));
}

static void x_pca(tl *t, const jm_node *r)
{
    char w[1200];
    const char *kind = S(r, "kind");
    if (strcmp(kind, "raw") == 0) return;                      // no reliable time
    snprintf(w, sizeof w, "%s (PCA %s record): %s", strcmp(kind, "launch") == 0 ? "program launched" : "program seen",
             kind, S(r, "path"));
    add(t, S(r, "time"), w, S(r, "file"), B(r, "suspicious"));
}

static void x_activities(tl *t, const jm_node *r)
{
    char w[2400];
    const char *shown = S(r, "description")[0] ? S(r, "description") : S(r, "display_text");
    snprintf(w, sizeof w, "Timeline: %s %s%s%s", S(r, "kind"), S(r, "application"), shown[0] ? " - " : "", shown);
    add(t, S(r, "start"), w, S(r, "reason"), B(r, "suspicious"));
}

static void x_webcache(tl *t, const jm_node *r)
{
    char w[2400];
    snprintf(w, sizeof w, "WebCache %s: %s", strcmp(S(r, "container"), "iedownload") == 0 ? "download" : "visit (last)", S(r, "url"));
    add(t, S(r, "accessed"), w, S(r, "reason"), B(r, "suspicious"));
}

// sysinfo prints one object, not a list. Network first/last-connected times
// are LOCAL time in the registry, so they are left out of this UTC view.
static void x_sysinfo(tl *t, const jm_node *doc)
{
    const jm_node *win = jm_get(doc, "windows"), *comp = jm_get(doc, "computer");
    char w[400];
    snprintf(w, sizeof w, "Windows installed: %s", S(win, "ProductName"));
    add(t, S(win, "install_date_utc"), w, S(win, "CurrentBuild"), 0);
    snprintf(w, sizeof w, "last clean shutdown: %s", S(comp, "name"));
    add(t, S(comp, "last_shutdown_utc"), w, "", 0);
    const jm_node *pr = jm_get(doc, "profiles");
    for (const jm_node *p = pr && pr->type == JM_ARR ? pr->child : NULL; p; p = p->next) {
        snprintf(w, sizeof w, "user profile last loaded: %s", S(p, "path"));
        add(t, S(p, "last_load_utc"), w, S(p, "sid"), 0);
    }
}

typedef struct {
    const char *name;
    capture_fn fn;
    const char *args[13];
    const char *list;           // member holding the records; NULL = top-level array
    void (*x)(tl *, const jm_node *);
    const char *user;           // set for per-user sources of an image
} source;

static const source sources[] = {
    { "prefetch",   cmd_prefetch,   { NULL },               NULL, x_prefetch, NULL },
    { "bam",        cmd_bam,        { NULL },               NULL, x_bam, NULL },
    { "userassist", cmd_userassist, { NULL },               NULL, x_userassist, NULL },
    { "shimcache",  cmd_shimcache,  { NULL },               NULL, x_shimcache, NULL },
    { "jumplist",   cmd_jumplist,   { NULL },               NULL, x_jumplist, NULL },
    { "lnk",        cmd_lnk,        { NULL },               NULL, x_lnk, NULL },
    { "shellbags",  cmd_shellbags,  { NULL },               NULL, x_shellbags, NULL },
    { "recyclebin", cmd_recyclebin, { NULL },               NULL, x_recyclebin, NULL },
    { "usb",        cmd_usb,        { NULL },               NULL, x_usb, NULL },
    { "rdp",        cmd_rdp,        { NULL },               NULL, x_rdp, NULL },
    { "mru",        cmd_mru,        { NULL },               NULL, x_mru, NULL },
    { "pshistory",  cmd_pshistory,  { NULL },               NULL, x_pshistory, NULL },
    { "users",      cmd_users,      { NULL },               "accounts", x_users, NULL },
    { "bits",       cmd_bits,       { NULL },               NULL, x_bits, NULL },
    { "tasks",      cmd_tasks,      { NULL },               NULL, x_tasks, NULL },
    { "comhijack",  cmd_comhijack,  { "--all", NULL },      NULL, x_comhijack, NULL },
    { "events",     cmd_events,     { "--max", "200", NULL }, NULL, x_events, NULL },
    { "sysinfo",    cmd_sysinfo,    { NULL },               NULL, x_sysinfo, NULL },
    { "browser",    cmd_browser,    { NULL },               NULL, x_browser, NULL },
    { "pca",        cmd_pca,        { NULL },               NULL, x_pca, NULL },
    { "activities", cmd_activities, { NULL },               NULL, x_activities, NULL },
};

// The same sources for an offline installation under root (timeline --root):
// machine-wide files once, the per-user ones once for each profile.
static size_t image_sources(const img_paths *ip, source *out, size_t cap)
{
    size_t n = 0;
#define ADD(nm, f, x_, lst, usr, ...) do { if (n < cap) { source *s_ = &out[n++]; memset(s_, 0, sizeof *s_); \
        s_->name = nm; s_->fn = f; s_->x = x_; s_->list = lst; s_->user = usr; \
        const char *a_[] = { __VA_ARGS__, NULL }; \
        for (int i_ = 0; a_[i_] && i_ < 12; i_++) s_->args[i_] = a_[i_]; } } while (0)
    if (ip->prefetch[0]) ADD("prefetch", cmd_prefetch, x_prefetch, NULL, NULL, "--dir", ip->prefetch);
    if (ip->pca[0]) ADD("pca", cmd_pca, x_pca, NULL, NULL, ip->pca);
    if (ip->system[0]) {
        ADD("bam", cmd_bam, x_bam, NULL, NULL, "--hive", ip->system);
        ADD("shimcache", cmd_shimcache, x_shimcache, NULL, NULL, "--hive", ip->system);
        ADD("usb", cmd_usb, x_usb, NULL, NULL, "--hive", ip->system);
    }
    if (ip->amcache[0]) ADD("amcache", cmd_amcache, x_amcache, NULL, NULL, ip->amcache);
    if (ip->recycle[0]) ADD("recyclebin", cmd_recyclebin, x_recyclebin, NULL, NULL, ip->recycle);
    if (ip->sam[0]) ADD("users", cmd_users, x_users, "accounts", NULL, "--sam", ip->sam);
    if (ip->tasks[0]) ADD("tasks", cmd_tasks, x_tasks, NULL, NULL, "--dir", ip->tasks);
    if (ip->software[0] && ip->system[0])
        ADD("sysinfo", cmd_sysinfo, x_sysinfo, NULL, NULL, "--software", ip->software, "--system", ip->system);
    else if (ip->software[0])
        ADD("sysinfo", cmd_sysinfo, x_sysinfo, NULL, NULL, "--software", ip->software);
    if (ip->nevtx && n < cap) {
        source *s_ = &out[n++];
        memset(s_, 0, sizeof *s_);
        s_->name = "events"; s_->fn = cmd_events; s_->x = x_events;
        int k = 0;
        s_->args[k++] = "--max"; s_->args[k++] = "200";
        for (int i = 0; i < ip->nevtx && k + 2 <= 12; i++) { s_->args[k++] = "--evtx"; s_->args[k++] = ip->evtx[i]; }
    }
    for (int u = 0; u < ip->nusers; u++) {
        const img_user *p = &ip->users[u];
        ADD("userassist", cmd_userassist, x_userassist, NULL, p->name, "--hive", p->ntuser);
        ADD("mru", cmd_mru, x_mru, NULL, p->name, "--hive", p->ntuser);
        ADD("rdp", cmd_rdp, x_rdp, NULL, p->name, "--hive", p->ntuser);
        if (p->usrclass[0]) ADD("shellbags", cmd_shellbags, x_shellbags, NULL, p->name, "--ntuser", p->ntuser, "--usrclass", p->usrclass);
        else                ADD("shellbags", cmd_shellbags, x_shellbags, NULL, p->name, "--ntuser", p->ntuser);
        if (p->autodest[0]) ADD("jumplist", cmd_jumplist, x_jumplist, NULL, p->name, p->autodest);
        if (p->recent[0])   ADD("lnk", cmd_lnk, x_lnk, NULL, p->name, p->recent);
        if (p->pshist[0])   ADD("pshistory", cmd_pshistory, x_pshistory, NULL, p->name, p->pshist);
        {
            // The user folder is the one holding NTUSER.DAT.
            static char homes[IMG_MAX_USERS][MAX_PATH * 2];
            snprintf(homes[u], sizeof homes[u], "%s", p->ntuser);
            char *sl = strrchr(homes[u], '\\');
            if (sl) *sl = 0;
            ADD("browser", cmd_browser, x_browser, NULL, p->name, "--home", homes[u]);
            ADD("activities", cmd_activities, x_activities, NULL, p->name, "--home", homes[u]);
            ADD("webcache", cmd_webcache, x_webcache, NULL, p->name, "--home", homes[u]);
        }
        if (p->usrclass[0] && ip->software[0])
            ADD("comhijack", cmd_comhijack, x_comhijack, NULL, p->name, "--usrclass", p->usrclass, "--software", ip->software, "--all");
    }
#undef ADD
    return n;
}

static int in_list(const char *list, const char *name)
{
    size_t L = strlen(name);
    for (const char *p = list; p && *p;) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n == L && _strnicmp(p, name, L) == 0) return 1;
        p = e ? e + 1 : NULL;
    }
    return 0;
}

static int cmp_row(const void *a, const void *b)
{
    const row *x = (const row *)a, *y = (const row *)b;
    int c = strcmp(y->time, x->time);                    // newest first
    return c ? c : strcmp(x->source, y->source);
}

int cmd_timeline(int argc, char **argv)
{
    int mode = 0, only_flagged = 0;
    long hours = 0;
    const char *pick = NULL, *root = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--root") == 0 && a + 1 < argc)         root = argv[++a];
        else if (strcmp(argv[a], "--json") == 0)                    mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)                     mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)                 only_flagged = 1;
        else if (strcmp(argv[a], "--since") == 0 && a + 1 < argc)   hours = strtol(argv[++a], NULL, 10);
        else if (strcmp(argv[a], "--sources") == 0 && a + 1 < argc) pick = argv[++a];
        else {
            fprintf(stderr, "timeline: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (hours < 0) {
        fputs("timeline: --since needs a positive number of hours\n", stderr);
        return 1;
    }
    // Live: the fixed list. --root: the same sources pointed at the image.
    static img_paths ip;
    static source dyn[16 + IMG_MAX_USERS * 8];
    const source *list = sources;
    size_t ns = sizeof sources / sizeof sources[0];
    if (root) {
        if (img_find(root, &ip) != 0) {
            fprintf(stderr, "timeline: no Windows\\System32\\config\\SYSTEM or SOFTWARE under '%s'\n", root);
            return 1;
        }
        ns = image_sources(&ip, dyn, sizeof dyn / sizeof dyn[0]);
        list = dyn;
    }
    if (pick) {
        // Every requested name must be a known source.
        for (const char *p = pick; *p;) {
            const char *e = strchr(p, ',');
            size_t n = e ? (size_t)(e - p) : strlen(p);
            int ok = 0;
            for (size_t i = 0; i < sizeof sources / sizeof sources[0]; i++)
                if (strlen(sources[i].name) == n && _strnicmp(p, sources[i].name, n) == 0) ok = 1;
            if (n == 7 && _strnicmp(p, "amcache", 7) == 0) ok = 1;      // image only
            if (n == 8 && _strnicmp(p, "webcache", 8) == 0) ok = 1;     // image only (locked live)
            if (!ok) {
                fprintf(stderr, "timeline: unknown source '%.*s'\n", (int)n, p);
                return 1;
            }
            if (!e) break;
            p = e + 1;
        }
    }
    tl t;
    memset(&t, 0, sizeof t);
    if (hours > 0) {
        time_t cut = time(NULL) - (time_t)hours * 3600;
        struct tm *g = gmtime(&cut);
        if (g) strftime(t.since, sizeof t.since, "%Y-%m-%d %H:%M:%S", g);
    }
    for (size_t i = 0; i < ns; i++) {
        const source *src = &list[i];
        if (pick && !in_list(pick, src->name)) continue;
        char *av[16];
        int ac = 0;
        for (int k = 0; k < 13 && src->args[k]; k++) av[ac++] = (char *)src->args[k];
        av[ac++] = (char *)"--json";
        av[ac] = NULL;
        int rc = 1;
        char *text = capture_stdout(src->fn, ac, av, &rc);
        if (text == NULL) continue;
        jm_node *doc = jm_parse(text, strlen(text));
        free(text);
        if (doc == NULL) {
            if (rc == 0) fprintf(stderr, "timeline: %s printed no usable JSON\n", src->name);
            continue;
        }
        const jm_node *recs = src->list ? jm_get(doc, src->list) : doc;
        t.source = src->name;
        t.user = src->user;
        if (recs && recs->type == JM_OBJ) src->x(&t, recs);            // a single-object source
        for (const jm_node *r = recs && recs->type == JM_ARR ? recs->child : NULL; r; r = r->next)
            if (r->type == JM_OBJ) src->x(&t, r);
        if (src->x == x_pshistory) ps_flush(&t);
        jm_free(doc);
    }
    if (t.n > 1) qsort(t.rows, t.n, sizeof *t.rows, cmp_row);

    unsigned shown = 0;
    if (mode == 0) {
        printf("timeline  (%s%sUTC, newest first%s%s)\n\n", root ? ip.root : "", root ? ", " : "",
               t.since[0] ? ", since " : "", t.since);
    } else if (mode == 2) {
        puts("time,source,user,event,detail,suspicious");
    } else {
        putchar('[');
    }
    for (size_t i = 0; i < t.n; i++) {
        row *r = &t.rows[i];
        if (only_flagged && !r->suspicious) continue;
        if (mode == 0) {
            printf("%s  %s %-10s %s%s%s%s\n", r->time, r->suspicious ? "[!]" : "   ", r->source,
                   r->user[0] ? "(" : "", r->user, r->user[0] ? ") " : "", r->what);
            if (r->detail[0]) printf("%36s%s\n", "", r->detail);
        } else if (mode == 2) {
            printf("%s,%s,", r->time, r->source);
            csv_str(r->user); putchar(',');
            csv_str(r->what); putchar(',');
            csv_str(r->detail); printf(",%s\n", r->suspicious ? "true" : "false");
        } else {
            printf("%s{\"time\":\"%s\",\"source\":\"%s\",\"user\":", shown ? "," : "", r->time, r->source);
            json_str(r->user);
            fputs(",\"event\":", stdout);
            json_str(r->what);
            fputs(",\"detail\":", stdout);
            json_str(r->detail);
            printf(",\"suspicious\":%s}", r->suspicious ? "true" : "false");
        }
        shown++;
    }
    if (mode == 1) puts("]");
    else if (mode == 0) printf("\n%u event(s)\n", shown);
    for (size_t i = 0; i < t.n; i++) { free(t.rows[i].what); free(t.rows[i].detail); }
    free(t.rows);
    return 0;
}
