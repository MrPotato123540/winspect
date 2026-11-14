// winspect image - offline triage of a mounted / copied Windows installation
//
// Every offline-capable command already exists; this one only finds the
// evidence under <root> and runs those commands on it, in-process with --json
// (capture.c), reading their output with jsonmini.c:
//
//   Windows\System32\config\SYSTEM / SOFTWARE / SAM    sysinfo, users, posture,
//                                                       autoruns, services, programs,
//                                                       defender, certstore, shimcache,
//                                                       bam, usb
//   Windows\AppCompat\Programs\Amcache.hve             amcache
//   Windows\Prefetch                                   prefetch --dir
//   Windows\System32\Tasks                             tasks --dir
//   Windows\System32\winevt\Logs\*.evtx (6 channels)   events --evtx
//   $Recycle.Bin                                        recyclebin
//   Users\<name>\NTUSER.DAT, UsrClass.dat, PSReadLine  autoruns --ntuser, userassist,
//                                                       mru, rdp, comhijack, pshistory
//
// A record is a finding when its command marked it ("suspicious": true with a
// reason); posture contributes its WARN rows, defender every exclusion or
// switched-off protection, bam / shimcache programs in user-writable folders.
// Nothing under <root> is written.

#include "image.h"
#include "capture.h"
#include "imgpaths.h"
#include "jsonmini.h"
#include "jsonutil.h"
#include "sysinfo.h"
#include "users.h"
#include "posture.h"
#include "autoruns.h"
#include "services.h"
#include "programs.h"
#include "defender.h"
#include "certstore.h"
#include "shimcache.h"
#include "bam.h"
#include "amcache.h"
#include "prefetch.h"
#include "tasks.h"
#include "recyclebin.h"
#include "pshistory.h"
#include "userassist.h"
#include "mru.h"
#include "rdp.h"
#include "comhijack.h"
#include "logons.h"
#include "detections.h"
#include "capability.h"
#include "wer.h"
#include "office.h"
#include "events.h"
#include "browser.h"
#include "pca.h"
#include "activities.h"
#include "srum.h"
#include "webcache.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char source[32], user[128], reason[512], detail[1200];
    unsigned count;             // identical rows folded into one
} finding;

typedef struct {
    finding *v;
    size_t n, cap;
} flist;

static void fadd(flist *l, const char *src, const char *user, const char *reason, const char *detail)
{
    // Fold an identical row (the same cache entry recorded several times).
    for (size_t i = 0; i < l->n; i++) {
        finding *f = &l->v[i];
        if (strcmp(f->source, src) == 0 && strcmp(f->user, user ? user : "") == 0 &&
                strncmp(f->reason, reason, sizeof f->reason - 1) == 0 && strncmp(f->detail, detail, sizeof f->detail - 1) == 0) {
            f->count++;
            return;
        }
    }
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 64;
        finding *nv = (finding *)realloc(l->v, nc * sizeof *nv);
        if (nv == NULL) return;
        l->v = nv;
        l->cap = nc;
    }
    finding *f = &l->v[l->n++];
    snprintf(f->source, sizeof f->source, "%s", src);
    snprintf(f->user, sizeof f->user, "%s", user ? user : "");
    snprintf(f->reason, sizeof f->reason, "%s", reason);
    snprintf(f->detail, sizeof f->detail, "%s", detail);
    f->count = 1;
}

// Run a command with --json; returns the parsed document (caller frees) or NULL.
static jm_node *run_json(capture_fn fn, const char *const *args)
{
    char *av[16];
    int ac = 0;
    for (; args[ac] && ac < 14; ac++) av[ac] = (char *)args[ac];
    av[ac++] = (char *)"--json";
    av[ac] = NULL;
    int rc = 1;
    char *text = capture_stdout(fn, ac, av, &rc);
    if (text == NULL) return NULL;
    jm_node *doc = jm_parse(text, strlen(text));
    free(text);
    return doc;
}

// Short description of a record: its first two meaningful text fields.
static void describe(const jm_node *r, char *out, size_t n)
{
    static const char *const keys[] = {
        "location", "name", "task", "check", "executable", "program", "list", "path", "command",
        "binary_path", "service_dll", "com_dll", "target", "value", "subject", "summary", "clsid",
        "user_server", "threat", "file", "item", "account", "source", "app", NULL
    };
    out[0] = 0;
    int used = 0;
    for (int i = 0; keys[i] && used < 3; i++) {
        const char *v = jm_gets(r, keys[i]);
        if (v == NULL || v[0] == 0 || strcmp(v, "-") == 0) continue;
        if (used && strstr(out, v)) continue;
        size_t L = strlen(out);
        snprintf(out + L, n - L, "%s%s", used ? "  " : "", v);
        used++;
    }
}

static int B(const jm_node *o, const char *k)
{
    const jm_node *v = jm_get(o, k);
    return v && v->type == JM_BOOL && v->boolean;
}

// Findings from one command's records.
enum { RULE_FLAGGED, RULE_POSTURE, RULE_ALL, RULE_WRITABLE };

static void collect(flist *l, const char *src, const char *user, const jm_node *doc, const char *list, int rule,
                    const char *fixed_reason)
{
    const jm_node *arr = list ? jm_get(doc, list) : doc;
    if (arr == NULL || arr->type != JM_ARR) return;
    for (const jm_node *r = arr->child; r; r = r->next) {
        if (r->type != JM_OBJ) continue;
        char d[1200];
        describe(r, d, sizeof d);
        const char *reason = NULL;
        switch (rule) {
        case RULE_FLAGGED:
            if (B(r, "suspicious")) reason = jm_gets(r, "reason");
            break;
        case RULE_POSTURE: {
            const char *st = jm_gets(r, "status");
            if (st && strcmp(st, "WARN") == 0) reason = jm_gets(r, "detail");
            break;
        }
        case RULE_ALL:
            reason = fixed_reason;
            break;
        case RULE_WRITABLE:
            if (B(r, "user_writable_dir")) reason = fixed_reason;
            break;
        }
        if (reason) fadd(l, src, user, reason[0] ? reason : "flagged", d);
    }
}

typedef struct {
    const char *name;
    capture_fn fn;
    const char *args[10];
    const char *list;
    int rule;
    const char *fixed;
} job;

int cmd_image(int argc, char **argv)
{
    int mode = 0;
    const char *root = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) mode = 1;
        else if (root == NULL) root = argv[a];
        else {
            fprintf(stderr, "image: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (root == NULL) {
        fputs("image: give the root folder of the Windows installation (e.g. E:\\)\n", stderr);
        return 1;
    }
    static img_paths ip;
    if (img_find(root, &ip) != 0) {
        fprintf(stderr, "image: no Windows\\System32\\config\\SYSTEM or SOFTWARE under '%s'\n", root);
        return 1;
    }
    const char *R = ip.root;
    const char *sys = ip.system, *sw = ip.software, *sam = ip.sam, *amc = ip.amcache;
    const char *pf = ip.prefetch, *tk = ip.tasks, *rb = ip.recycle;
    int has_sys = sys[0] != 0, has_sw = sw[0] != 0, has_sam = sam[0] != 0, has_amc = amc[0] != 0;
    int has_pf = pf[0] != 0, has_tk = tk[0] != 0, has_rb = rb[0] != 0;
    int nev = ip.nevtx, nu = ip.nusers;
    const img_user *users = ip.users;

    // ---- machine facts and accounts -------------------------------------------
    flist fl = { NULL, 0, 0 };
    jm_node *si = NULL, *acc = NULL;
    if (has_sw || has_sys) {
        const char *a[6] = { NULL };
        int k = 0;
        if (has_sw) { a[k++] = "--software"; a[k++] = sw; }
        if (has_sys) { a[k++] = "--system"; a[k++] = sys; }
        a[k] = NULL;
        si = run_json(cmd_sysinfo, a);
    }
    if (has_sam) {
        const char *a[] = { "--sam", sam, NULL };
        acc = run_json(cmd_users, a);
        if (acc) collect(&fl, "users", NULL, acc, "accounts", RULE_FLAGGED, NULL);
    }

    // ---- machine-wide checks ----------------------------------------------------
    job jobs[32];
    int nj = 0;
#define JOB(nm, f, lst, rl, fx, ...) do { job *j = &jobs[nj++]; memset(j, 0, sizeof *j); j->name = nm; j->fn = f; \
        j->list = lst; j->rule = rl; j->fixed = fx; const char *t_[] = { __VA_ARGS__, NULL }; \
        for (int i_ = 0; t_[i_] && i_ < 9; i_++) j->args[i_] = t_[i_]; } while (0)
    if (has_sw && has_sys) JOB("posture", cmd_posture, NULL, RULE_POSTURE, NULL, "--software", sw, "--system", sys);
    else if (has_sw)       JOB("posture", cmd_posture, NULL, RULE_POSTURE, NULL, "--software", sw);
    if (has_sw && has_sys) JOB("autoruns", cmd_autoruns, NULL, RULE_FLAGGED, NULL, "--software", sw, "--system", sys);
    else if (has_sw)       JOB("autoruns", cmd_autoruns, NULL, RULE_FLAGGED, NULL, "--software", sw);
    if (has_sw)            JOB("capability", cmd_capability, NULL, RULE_FLAGGED, NULL, "--software", sw);
    if (has_sys) {
        JOB("services", cmd_services, NULL, RULE_FLAGGED, NULL, "--hive", sys);
        JOB("shimcache", cmd_shimcache, NULL, RULE_WRITABLE, "seen in a user-writable dir (AppCompatCache)", "--hive", sys);
        JOB("bam", cmd_bam, NULL, RULE_WRITABLE, "ran from a user-writable dir (BAM)", "--hive", sys);
    }
    if (has_sw) {
        JOB("programs", cmd_programs, NULL, RULE_FLAGGED, NULL, "--software", sw);
        JOB("defender", cmd_defender, NULL, RULE_ALL, "Defender exclusion or protection setting", "--software", sw);
        JOB("certstore", cmd_certstore, NULL, RULE_FLAGGED, NULL, "--software", sw);
    }
    if (has_amc) JOB("amcache", cmd_amcache, NULL, RULE_FLAGGED, NULL, amc);
    if (has_pf)  JOB("prefetch", cmd_prefetch, NULL, RULE_FLAGGED, NULL, "--dir", pf);
    if (ip.pca[0]) JOB("pca", cmd_pca, NULL, RULE_FLAGGED, NULL, ip.pca);
    if (ip.srum[0]) JOB("srum", cmd_srum, NULL, RULE_FLAGGED, NULL, ip.srum, "--summary");
    if (has_tk)  JOB("tasks", cmd_tasks, NULL, RULE_FLAGGED, NULL, "--dir", tk);
    if (has_rb)  JOB("recyclebin", cmd_recyclebin, NULL, RULE_FLAGGED, NULL, rb);
    if (nev) {
        job *j = &jobs[nj++];
        memset(j, 0, sizeof *j);
        j->name = "events"; j->fn = cmd_events; j->rule = RULE_FLAGGED;
        int k = 0;
        for (int i = 0; i < nev && k < 8; i++) { j->args[k++] = "--evtx"; j->args[k++] = ip.evtx[i]; }
    }
    if (nev) {
        job *j = &jobs[nj++];
        memset(j, 0, sizeof *j);
        j->name = "logons"; j->fn = cmd_logons; j->rule = RULE_FLAGGED;
        int k = 0;
        for (int i = 0; i < nev && k < 8; i++) { j->args[k++] = "--evtx"; j->args[k++] = ip.evtx[i]; }
    }
    char werdir[MAX_PATH * 2];
    snprintf(werdir, sizeof werdir, "%s\\ProgramData\\Microsoft\\Windows\\WER", R);
    if (GetFileAttributesA(werdir) != INVALID_FILE_ATTRIBUTES) JOB("wer", cmd_wer, NULL, RULE_FLAGGED, NULL, werdir);
    char dhdir[MAX_PATH * 2];
    snprintf(dhdir, sizeof dhdir, "%s\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory", R);
    if (GetFileAttributesA(dhdir) != INVALID_FILE_ATTRIBUTES) JOB("detections", cmd_detections, NULL, RULE_FLAGGED, NULL, dhdir);
    for (int i = 0; i < nj; i++) {
        jm_node *doc = run_json(jobs[i].fn, jobs[i].args);
        if (doc) collect(&fl, jobs[i].name, NULL, doc, jobs[i].list, jobs[i].rule, jobs[i].fixed);
        jm_free(doc);
    }
    // ---- per user --------------------------------------------------------------
    for (int u = 0; u < nu; u++) {
        const img_user *p = &users[u];
        nj = 0;
        JOB("autoruns", cmd_autoruns, NULL, RULE_FLAGGED, NULL, "--ntuser", p->ntuser);
        JOB("userassist", cmd_userassist, NULL, RULE_FLAGGED, NULL, "--hive", p->ntuser);
        JOB("mru", cmd_mru, NULL, RULE_FLAGGED, NULL, "--hive", p->ntuser);
        JOB("office", cmd_office, NULL, RULE_FLAGGED, NULL, "--hive", p->ntuser);
        JOB("capability", cmd_capability, NULL, RULE_FLAGGED, NULL, "--ntuser", p->ntuser);
        if (p->usrclass[0] && has_sw)
            JOB("comhijack", cmd_comhijack, NULL, RULE_FLAGGED, NULL, "--usrclass", p->usrclass, "--software", sw);
        if (p->pshist[0]) JOB("pshistory", cmd_pshistory, NULL, RULE_FLAGGED, NULL, p->pshist);
        char home[MAX_PATH * 2];
        snprintf(home, sizeof home, "%s", p->ntuser);
        char *sl = strrchr(home, '\\');
        if (sl) *sl = 0;
        JOB("browser", cmd_browser, NULL, RULE_FLAGGED, NULL, "--home", home);
        JOB("activities", cmd_activities, NULL, RULE_FLAGGED, NULL, "--home", home);
        JOB("webcache", cmd_webcache, NULL, RULE_FLAGGED, NULL, "--home", home);
        char uwer[MAX_PATH * 2 + 48];
        snprintf(uwer, sizeof uwer, "%s\\AppData\\Local\\Microsoft\\Windows\\WER", home);
        if (GetFileAttributesA(uwer) != INVALID_FILE_ATTRIBUTES) JOB("wer", cmd_wer, NULL, RULE_FLAGGED, NULL, uwer);
        for (int i = 0; i < nj; i++) {
            jm_node *doc = run_json(jobs[i].fn, jobs[i].args);
            if (doc) collect(&fl, jobs[i].name, p->name, doc, jobs[i].list, jobs[i].rule, jobs[i].fixed);
            jm_free(doc);
        }
    }
#undef JOB

    // ---- report ----------------------------------------------------------------------
    const jm_node *comp = jm_get(si, "computer"), *win = jm_get(si, "windows");
    const char *cname = jm_gets(comp, "name"), *prod = jm_gets(win, "ProductName"), *build = jm_gets(win, "CurrentBuild");
    const char *inst = jm_gets(win, "install_date_utc"), *shut = jm_gets(comp, "last_shutdown_utc"), *tz = jm_gets(comp, "time_zone");
#define OR(x) ((x) && (x)[0] ? (x) : "-")
    if (mode == 0) {
        printf("image  %s\n\n", R);
        printf("  computer       %s\n  windows        %s (build %s)\n  installed      %s UTC\n"
               "  last shutdown  %s UTC\n  time zone      %s\n", OR(cname), OR(prod), OR(build), OR(inst), OR(shut), OR(tz));
        printf("  evidence       SYSTEM %s, SOFTWARE %s, SAM %s, Amcache %s, Prefetch %s, Tasks %s, Recycle Bin %s, %d event log(s), %d profile(s)\n",
               has_sys ? "yes" : "no", has_sw ? "yes" : "no", has_sam ? "yes" : "no", has_amc ? "yes" : "no",
               has_pf ? "yes" : "no", has_tk ? "yes" : "no", has_rb ? "yes" : "no", nev, nu);
        const jm_node *al = jm_get(acc, "accounts");
        if (al && al->type == JM_ARR) {
            puts("\n  local accounts (name, RID, state, last logon UTC)");
            for (const jm_node *a = al->child; a; a = a->next) {
                const jm_node *rid = jm_get(a, "rid");
                printf("    %-20s %6.0f  %-8s %s\n", OR(jm_gets(a, "name")), rid && rid->type == JM_NUM ? rid->num : 0.0,
                       B(a, "enabled") ? "enabled" : "disabled", OR(jm_gets(a, "last_logon")));
            }
        }
        // Grouped by source, user and reason; at most 5 examples per group.
        unsigned total = 0;
        for (size_t i = 0; i < fl.n; i++) total += fl.v[i].count;
        printf("\n  findings (%u)\n", total);
        static unsigned char done[1 << 16];
        memset(done, 0, sizeof done);
        for (size_t i = 0; i < fl.n && i < sizeof done; i++) {
            if (done[i]) continue;
            const finding *g = &fl.v[i];
            unsigned rows = 0, shown = 0;
            for (size_t j = i; j < fl.n && j < sizeof done; j++) {
                const finding *f = &fl.v[j];
                if (strcmp(f->source, g->source) || strcmp(f->user, g->user) || strcmp(f->reason, g->reason)) continue;
                rows += f->count;
            }
            printf("  [!] %-10s %s%s%s%s  (%u)\n", g->source, g->user[0] ? "(" : "", g->user, g->user[0] ? ") " : "",
                   g->reason, rows);
            for (size_t j = i; j < fl.n && j < sizeof done; j++) {
                const finding *f = &fl.v[j];
                if (strcmp(f->source, g->source) || strcmp(f->user, g->user) || strcmp(f->reason, g->reason)) continue;
                done[j] = 1;
                if (shown++ < 5) {
                    if (f->count > 1) printf("        %s  (x%u)\n", f->detail, f->count);
                    else printf("        %s\n", f->detail);
                }
            }
            if (shown > 5) printf("        ... %u more (all of them are in --json)\n", shown - 5);
        }
    } else {
        fputs("{\"root\":", stdout);
        json_str(R);
        fputs(",\"computer\":", stdout); json_str(OR(cname));
        fputs(",\"windows\":", stdout);  json_str(OR(prod));
        fputs(",\"build\":", stdout);    json_str(OR(build));
        fputs(",\"installed\":", stdout); json_str(OR(inst));
        fputs(",\"last_shutdown\":", stdout); json_str(OR(shut));
        printf(",\"evidence\":{\"system\":%s,\"software\":%s,\"sam\":%s,\"amcache\":%s,\"prefetch\":%s,"
               "\"tasks\":%s,\"recyclebin\":%s,\"event_logs\":%d,\"profiles\":[",
               has_sys ? "true" : "false", has_sw ? "true" : "false", has_sam ? "true" : "false",
               has_amc ? "true" : "false", has_pf ? "true" : "false", has_tk ? "true" : "false",
               has_rb ? "true" : "false", nev);
        for (int u = 0; u < nu; u++) { if (u) putchar(','); json_str(users[u].name); }
        fputs("]},\"findings\":[", stdout);
        for (size_t i = 0; i < fl.n; i++) {
            const finding *f = &fl.v[i];
            printf("%s{\"source\":", i ? "," : "");
            json_str(f->source);
            fputs(",\"user\":", stdout);   json_str(f->user);
            fputs(",\"detail\":", stdout); json_str(f->detail);
            fputs(",\"reason\":", stdout); json_str(f->reason);
            printf(",\"count\":%u}", f->count);
        }
        puts("]}");
    }
#undef OR
    jm_free(si);
    jm_free(acc);
    free(fl.v);
    return 0;
}
