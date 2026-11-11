// Report.wer parsing (see werparse.h). Portable C.

#include "werparse.h"
#include "ioc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int key_is(const char *line, const char *key, const char **value)
{
    size_t n = strlen(key);
    if (strncmp(line, key, n) != 0 || line[n] != '=') return 0;
    *value = line + n + 1;
    return 1;
}

// "Sig[12].Name" -> 12 and a pointer to ".Name..." ; -1 when not that shape.
static int indexed(const char *line, const char *prefix, const char **rest)
{
    size_t n = strlen(prefix);
    if (strncmp(line, prefix, n) != 0 || line[n] != '[') return -1;
    char *end;
    long v = strtol(line + n + 1, &end, 10);
    if (end == line + n + 1 || *end != ']' || v < 0 || v > 4096) return -1;
    *rest = end + 1;
    return (int)v;
}

static void copy(char *dst, size_t n, const char *src)
{
    snprintf(dst, n, "%s", src);
}

int wer_parse(char *text, wer_report *r)
{
    memset(r, 0, sizeof *r);
    // Sig[i].Name arrives before Sig[i].Value; remember which slot means what.
    enum { SIG_NONE, SIG_APP, SIG_MODULE, SIG_CODE };
    int sig_kind[64];
    memset(sig_kind, 0, sizeof sig_kind);
    char ui2[520] = "", module0[520] = "", ns_app[160] = "", app_name[160] = "";
    int known = 0;

    char *p = text;
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) p += 3;
    while (*p) {
        char *e = strchr(p, '\n');
        if (e) *e = '\0';
        size_t L = strlen(p);
        if (L && p[L - 1] == '\r') p[L - 1] = '\0';
        const char *v, *rest;
        int i;
        if (key_is(p, "EventType", &v)) { copy(r->event_type, sizeof r->event_type, v); known++; }
        else if (key_is(p, "EventTime", &v)) { r->event_time = strtoull(v, NULL, 10); known++; }
        else if (key_is(p, "AppPath", &v)) { copy(r->app_path, sizeof r->app_path, v); known++; }
        else if (key_is(p, "NsAppName", &v)) copy(ns_app, sizeof ns_app, v);
        else if (key_is(p, "AppName", &v)) copy(app_name, sizeof app_name, v);
        else if (key_is(p, "ReportIdentifier", &v)) copy(r->report_id, sizeof r->report_id, v);
        else if ((i = indexed(p, "Sig", &rest)) >= 0 && i < 64) {
            if (key_is(rest, ".Name", &v)) {
                sig_kind[i] = strcmp(v, "Application Name") == 0 ? SIG_APP
                            : strcmp(v, "Fault Module Name") == 0 ? SIG_MODULE
                            : strcmp(v, "Exception Code") == 0 ? SIG_CODE : SIG_NONE;
            } else if (key_is(rest, ".Value", &v)) {
                if (sig_kind[i] == SIG_APP) copy(r->app_name, sizeof r->app_name, v);
                else if (sig_kind[i] == SIG_MODULE) copy(r->fault_module, sizeof r->fault_module, v);
                else if (sig_kind[i] == SIG_CODE) copy(r->exc_code, sizeof r->exc_code, v);
            }
            known++;
        }
        else if ((i = indexed(p, "LoadedModule", &rest)) >= 0 && rest[0] == '=') {
            r->modules++;
            if (i == 0) copy(module0, sizeof module0, rest + 1);
            if (ioc_user_writable(rest + 1)) {
                if (r->modules_writable++ == 0) copy(r->first_writable_module, sizeof r->first_writable_module, rest + 1);
            }
            known++;
        }
        else if ((i = indexed(p, "UI", &rest)) == 2 && rest[0] == '=') copy(ui2, sizeof ui2, rest + 1);
        if (!e) break;
        p = e + 1;
    }
    if (known == 0) return -1;
    // Program path: the explicit key, else the first loaded module (always the
    // .exe itself), else the path shown in the crash dialog.
    if (r->app_path[0] == '\0') {
        const char *alt = module0[0] ? module0 : (strchr(ui2, '\\') ? ui2 : "");
        copy(r->app_path, sizeof r->app_path, alt);
    }
    if (r->app_name[0] == '\0') {
        if (ns_app[0]) copy(r->app_name, sizeof r->app_name, ns_app);
        else if (r->app_path[0]) {
            const char *b = strrchr(r->app_path, '\\');
            copy(r->app_name, sizeof r->app_name, b ? b + 1 : r->app_path);
        } else copy(r->app_name, sizeof r->app_name, app_name);
    }
    return 0;
}

const char *wer_reason(const wer_report *r)
{
    if (r->app_path[0] && ioc_user_writable(r->app_path)) return "crashed program ran from a user-writable dir";
    return NULL;
}
