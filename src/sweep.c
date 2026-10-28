// winspect sweep - all system-wide checks in one pass
//
// Each check already exists as its own command; sweep only orchestrates them,
// asking each for findings only, so the report stays short enough to read.
// The order goes from configuration (posture) through live state (processes,
// hidden objects) to persistence and history (autoruns ... events).
//
// JSON mode needs care: every command prints its own JSON to stdout, and a
// command that fails (say, the Security log without elevation) may print
// nothing. To keep the combined document valid, each check's stdout is
// redirected into a temporary file; if the check fails or prints nothing, its
// key gets null, otherwise the captured JSON is copied in.

#include "sweep.h"
#include "posture.h"
#include "hunt.h"
#include "hidden.h"
#include "net.h"
#include "autoruns.h"
#include "services.h"
#include "tasks.h"
#include "taskcache.h"
#include "firewall.h"
#include "defender.h"
#include "prefetch.h"
#include "wmi.h"
#include "events.h"
#include "bitsjobs.h"
#include "pshistory.h"
#include "recyclebin.h"
#include "comhijack.h"

#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cmd_fn)(int, char **);

typedef struct {
    const char *key;        // JSON key / section title
    const char *what;       // one-line description for the text report
    cmd_fn fn;
    const char *args[3];    // findings-only arguments (NULL-terminated)
} check;

static const check checks[] = {
    { "posture",   "hardening settings that need attention", cmd_posture,   { "--warn", NULL } },
    { "hunt",      "process lineage / masquerading",         cmd_hunt,      { NULL } },
    { "hidden",    "hidden processes and services",          cmd_hidden,    { NULL } },
    { "net",       "suspicious network endpoints",           cmd_net,       { "--flagged", NULL } },
    { "autoruns",  "suspicious auto-start entries",          cmd_autoruns,  { "--flagged", NULL } },
    { "services",  "suspicious service configuration",       cmd_services,  { "--flagged", NULL } },
    { "tasks",     "suspicious scheduled tasks",             cmd_tasks,     { "--flagged", NULL } },
    { "taskcache", "scheduled tasks hidden from tools",      cmd_taskcache, { "--flagged", NULL } },
    { "firewall",  "risky inbound allow rules",              cmd_firewall,  { "--flagged", NULL } },
    { "prefetch",  "programs that ran from user-writable dirs", cmd_prefetch, { "--flagged", NULL } },
    { "defender",  "Defender exclusions / disabled protection", cmd_defender, { NULL } },
    { "wmi",       "WMI permanent subscriptions",            cmd_wmi,       { NULL } },
    { "comhijack", "per-user COM classes replacing machine ones", cmd_comhijack, { "--flagged", NULL } },
    { "bits",      "BITS jobs with notify commands / risky downloads", cmd_bits, { "--flagged", NULL } },
    { "pshistory", "suspicious PowerShell history lines (all users)", cmd_pshistory, { "--all-users", "--flagged", NULL } },
    { "recyclebin","deleted programs and scripts",           cmd_recyclebin, { "--flagged", NULL } },
    { "events",    "high-signal events (latest 10 per channel)", cmd_events, { "--max", "10", NULL } },
};

// Build argv for a check: its findings-only args plus an optional extra.
static int build_args(const check *c, const char *extra, char **argv, int cap)
{
    int n = 0;
    for (int i = 0; i < 3 && c->args[i] != NULL && n < cap; i++) {
        argv[n++] = (char *)c->args[i];
    }
    if (extra != NULL && n < cap) {
        argv[n++] = (char *)extra;
    }
    return n;
}

// Runs fn with stdout redirected to a temp file; returns the captured text
// (malloc'd, may be empty) and the command's exit code via *rc.
static char *run_captured(cmd_fn fn, int argc, char **argv, int *rc)
{
    *rc = 1;
    FILE *tmp = tmpfile();
    if (tmp == NULL) return NULL;
    fflush(stdout);
    int saved = _dup(_fileno(stdout));
    // _dup2 returns 0 on success, not a new descriptor (GCC's -fanalyzer models
    // it as dup2 and reports a bogus fd leak here).
    if (saved < 0 || _dup2(_fileno(tmp), _fileno(stdout)) != 0) {
        if (saved >= 0) _close(saved);
        fclose(tmp);
        return NULL;
    }
    *rc = fn(argc, argv);
    fflush(stdout);
    _dup2(saved, _fileno(stdout));
    _close(saved);

    long len = 0;
    char *text = NULL;
    if (fseek(tmp, 0, SEEK_END) == 0 && (len = ftell(tmp)) >= 0 &&
            fseek(tmp, 0, SEEK_SET) == 0) {
        text = (char *)malloc((size_t)len + 1);
        if (text != NULL) {
            size_t got = fread(text, 1, (size_t)len, tmp);
            text[got] = '\0';
        }
    }
    fclose(tmp);
    return text;
}

int cmd_sweep(int argc, char **argv)
{
    int json = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) json = 1;
        else {
            fprintf(stderr, "sweep: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    size_t n = sizeof checks / sizeof checks[0];
    if (!json) {
        puts("sweep  (all system-wide checks, findings only)");
        puts("       tip: run elevated - several checks need administrator rights\n");
        for (size_t i = 0; i < n; i++) {
            printf("==== %s - %s\n", checks[i].key, checks[i].what);
            fflush(stdout);
            char *av[4];
            int ac = build_args(&checks[i], NULL, av, 4);
            int rc = checks[i].fn(ac, av);
            fflush(stdout);
            if (rc != 0) {
                printf("  (check could not complete - see the message above)\n");
            }
            putchar('\n');
        }
        return 0;
    }

    putchar('{');
    for (size_t i = 0; i < n; i++) {
        char *av[4];
        int ac = build_args(&checks[i], "--json", av, 4);
        int rc = 1;
        char *text = run_captured(checks[i].fn, ac, av, &rc);
        // Trim trailing whitespace so the captured document nests cleanly.
        size_t L = text ? strlen(text) : 0;
        while (L > 0 && (text[L - 1] == '\n' || text[L - 1] == '\r' || text[L - 1] == ' ')) {
            text[--L] = '\0';
        }
        printf("%s\"%s\":", i ? "," : "", checks[i].key);
        if (text != NULL && L > 0 && (text[0] == '[' || text[0] == '{')) {
            fputs(text, stdout);
        } else {
            fputs("null", stdout);
        }
        free(text);
    }
    puts("}");
    return 0;
}
