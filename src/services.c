// winspect services - what the Service Control Manager is running
//
// Services are a prime place for both legitimate background work and persistence,
// so "what services exist, where do their binaries live, and as whom do they
// run?" is a standard triage question (the core of `sc query` / AccessChk -c).
// We ask the SCM with query-only rights: EnumServicesStatusEx lists the services
// and their live state + PID, then QueryServiceConfig gives each one's start
// type, image path and logon account. Read-only; we never start/stop/change a
// service.
//
// Audit hints (each printed with its reason; --flagged shows only these):
//   * unquoted path  - an unquoted ImagePath with spaces before ".exe" makes
//                      Windows try C:\Program.exe, C:\Program Files\My.exe...
//                      first; a classic misconfiguration (logic in artparse.c)
//   * user-writable  - the binary or ServiceDll lives in Temp/AppData/...
//   * masquerading   - a core Windows binary name (svchost.exe, lsass.exe ...)
//                      outside System32 (rule shared with autoruns / hunt)
// --hive reads the Services key of an offline SYSTEM hive instead of asking
// the SCM: same configuration fields; state and PID are then unknown ("-").
// For shared svchost services the real code is the ServiceDll under
// Services\<name>\Parameters, so we show that too.

#include "services.h"
#include "jsonutil.h"
#include "artparse.h"
#include "ioc.h"
#include "sign.h"
#include "regsrc.h"

#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void w2u(const WCHAR *w, char *out, size_t n)
{
    out[0] = '\0';
    if (w != NULL) {
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)n, NULL, NULL);
    }
}

static const char *state_name(DWORD s)
{
    switch (s) {
    case SERVICE_STOPPED:          return "stopped";
    case SERVICE_START_PENDING:    return "start-pending";
    case SERVICE_STOP_PENDING:     return "stop-pending";
    case SERVICE_RUNNING:          return "running";
    case SERVICE_CONTINUE_PENDING: return "continue-pending";
    case SERVICE_PAUSE_PENDING:    return "pause-pending";
    case SERVICE_PAUSED:           return "paused";
    default:                       return "?";
    }
}

static const char *start_name(DWORD t)
{
    switch (t) {
    case SERVICE_BOOT_START:   return "boot";
    case SERVICE_SYSTEM_START: return "system";
    case SERVICE_AUTO_START:   return "auto";
    case SERVICE_DEMAND_START: return "manual";
    case SERVICE_DISABLED:     return "disabled";
    default:                   return "?";
    }
}

struct svc_ctx { int mode; int first; int only_flagged; int sig; unsigned shown, flagged; };
#define SVC_TEXT 0
#define SVC_JSON 1
#define SVC_CSV  2

static void emit(struct svc_ctx *c, const char *name, const char *disp,
                 const char *state, DWORD pid, const char *start,
                 const char *path, const char *account, const char *dll,
                 const char *reason, const char *sigtxt)
{
    if (c->only_flagged && reason == NULL) {
        return;
    }
    c->shown++;
    if (reason) { c->flagged++; }
    if (c->mode == SVC_TEXT) {
        printf("  %s%-28s %-14s %-9s %-7lu %-9s %s\n", reason ? "[!] " : "    ",
               name, state, start, (unsigned long)pid,
               account[0] ? account : "-", path[0] ? path : "-");
        if (dll[0]) {
            printf("        ServiceDll: %s\n", dll);
        }
        if (sigtxt[0]) {
            printf("        signature: %s\n", sigtxt);
        }
        if (reason) {
            printf("        <- %s\n", reason);
        }
        (void)disp;
    } else if (c->mode == SVC_CSV) {
        csv_str(name);    putchar(',');
        csv_str(disp);    putchar(',');
        csv_str(state);   putchar(',');
        printf("%lu,", (unsigned long)pid);
        csv_str(start);   putchar(',');
        csv_str(account); putchar(',');
        csv_str(path);    putchar(',');
        csv_str(dll);     putchar(',');
        csv_str(reason ? reason : ""); putchar(',');
        csv_str(sigtxt);  putchar('\n');
    } else {
        printf("%s{\"name\":", c->first ? "" : ",");
        json_str(name);
        fputs(",\"display_name\":", stdout); json_str(disp);
        fputs(",\"state\":", stdout);        json_str(state);
        printf(",\"pid\":%lu", (unsigned long)pid);
        fputs(",\"start_type\":", stdout);   json_str(start);
        fputs(",\"account\":", stdout);      json_str(account);
        fputs(",\"binary_path\":", stdout);  json_str(path);
        fputs(",\"service_dll\":", stdout);  json_str(dll);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        fputs(",\"signature\":", stdout);
        json_str(sigtxt);
        putchar('}');
        c->first = 0;
    }
}

// svchost-hosted services keep their real code in Parameters\ServiceDll.
static void service_dll(const WCHAR *name, char *out, size_t n)
{
    out[0] = '\0';
    WCHAR key[512], val[1024];
    _snwprintf(key, 512, L"SYSTEM\\CurrentControlSet\\Services\\%ls\\Parameters", name);
    key[511] = 0;
    DWORD sz = sizeof val;
    // RRF_RT_REG_SZ also accepts REG_EXPAND_SZ and expands %SystemRoot% for us.
    if (RegGetValueW(HKEY_LOCAL_MACHINE, key, L"ServiceDll", RRF_RT_REG_SZ, NULL, val, &sz)
            == ERROR_SUCCESS) {
        w2u(val, out, n);
    }
}

// Reads one service's config (start type, image path, account). Best-effort:
// leaves the strings empty when the service can't be opened for query.
static void query_config(SC_HANDLE scm, const WCHAR *name,
                         char *start, size_t startn,
                         char *path, size_t pathn,
                         char *account, size_t acctn)
{
    start[0] = path[0] = account[0] = '\0';
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG);
    if (svc == NULL) {
        return;
    }
    DWORD need = 0;
    QueryServiceConfigW(svc, NULL, 0, &need);
    if (need > 0) {
        QUERY_SERVICE_CONFIGW *cfg = (QUERY_SERVICE_CONFIGW *)malloc(need);
        if (cfg != NULL && QueryServiceConfigW(svc, cfg, need, &need)) {
            snprintf(start, startn, "%s", start_name(cfg->dwStartType));
            w2u(cfg->lpBinaryPathName, path, pathn);
            w2u(cfg->lpServiceStartName, account, acctn);
        }
        free(cfg);
    }
    CloseServiceHandle(svc);
}

static const char *classify(int is_win32, const char *path, const char *dll)
{
    char image[1024];
    if (is_win32 && svc_unquoted_path(path))           return "unquoted path with spaces";
    if (ioc_user_writable(path))                       return "binary in user-writable dir";
    if (dll[0] && ioc_user_writable(dll))              return "ServiceDll in user-writable dir";
    if (ioc_command_image(path, image, sizeof image) && asep_masquerade(image))
        return "Windows system binary name outside System32 (masquerading)";
    return NULL;
}

// --hive: the same fields straight from <ControlSet>\Services in a SYSTEM
// hive file. A subkey is a service when it has a Type value; Win32 services
// have type bits 0x10/0x20 (own / shared process), drivers 0x1/0x2.
typedef struct { char n[2048][128]; int count; } svcnames;
static void svc_name_cb(const char *name, void *vctx)
{
    svcnames *l = (svcnames *)vctx;
    if (l->count < 2048) snprintf(l->n[l->count++], sizeof l->n[0], "%s", name);
}

static int offline_services(const char *hive, struct svc_ctx *c, int drivers)
{
    regsrc src;
    char err[512];
    if (regsrc_open_hive(&src, hive, err, sizeof err) != 0) {
        fprintf(stderr, "services: %s\n", err);
        return 1;
    }
    if (regsrc_dirty(&src)) fputs("services: note: hive is dirty (transaction logs not replayed)\n", stderr);
    char cs[32], base[96];
    regsrc_control_set(&src, cs, sizeof cs);
    snprintf(base, sizeof base, "%s\\Services", cs);
    rkey k;
    if (rk_open(&src, base, &k) != 0) {
        fprintf(stderr, "services: no %s key in %s\n", base, hive);
        regsrc_close(&src);
        return 1;
    }
    static svcnames names;
    names.count = 0;
    rk_subkeys(&src, &k, svc_name_cb, &names);
    rk_close(&k);
    unsigned total = 0;
    for (int i = 0; i < names.count; i++) {
        char p[300];
        snprintf(p, sizeof p, "%s\\%s", base, names.n[i]);
        if (rk_open(&src, p, &k) != 0) continue;
        unsigned char d[4];
        uint32_t vt = 0;
        uint32_t type = 0, startv = 99;
        if (rk_get(&src, &k, "Type", &vt, d, 4) != 4 || vt != REG_DWORD) { rk_close(&k); continue; }
        type = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
        if (rk_get(&src, &k, "Start", &vt, d, 4) == 4 && vt == REG_DWORD)
            startv = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
        int is_win32 = (type & 0x30) != 0, is_driver = (type & 0x3) != 0;
        if (!(is_win32 || (drivers && is_driver))) { rk_close(&k); continue; }
        char path[1024] = "", disp[512] = "", account[256] = "", dll[1024] = "";
        rk_get_str(&src, &k, "ImagePath", path, sizeof path);
        rk_get_str(&src, &k, "DisplayName", disp, sizeof disp);
        rk_get_str(&src, &k, "ObjectName", account, sizeof account);
        rk_close(&k);
        char pp[340];
        snprintf(pp, sizeof pp, "%s\\Parameters", p);
        if (rk_open(&src, pp, &k) == 0) {
            rk_get_str(&src, &k, "ServiceDll", dll, sizeof dll);
            rk_close(&k);
        }
        total++;
        emit(c, names.n[i], disp, "-", 0, startv <= 4 ? start_name(startv) : "?", path, account, dll,
             classify(is_win32, path, dll), "");
    }
    regsrc_close(&src);
    if (c->mode == SVC_TEXT) {
        printf("\n%u service(s) in %s, %u flagged%s\n", total, hive, c->flagged,
               c->only_flagged ? " (only flagged shown)" : "");
    } else if (c->mode == SVC_JSON) {
        puts("]");
    }
    return 0;
}

int cmd_services(int argc, char **argv)
{
    int mode = SVC_TEXT, drivers = 0, only_flagged = 0, sig = 0;
    const char *hive = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--hive") == 0 && a + 1 < argc) { hive = argv[++a]; continue; }
        if (strcmp(argv[a], "--json") == 0)        mode = SVC_JSON;
        else if (strcmp(argv[a], "--csv") == 0)    mode = SVC_CSV;
        else if (strcmp(argv[a], "--drivers") == 0) drivers = 1;
        else if (strcmp(argv[a], "--flagged") == 0) only_flagged = 1;
        else if (strcmp(argv[a], "--sig") == 0)     sig = 1;
        else {
            fprintf(stderr, "services: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    if (hive != NULL) {
        if (sig) {
            fputs("services: --sig is not available with --hive (the files are on another machine)\n", stderr);
            return 1;
        }
        struct svc_ctx oc;
        memset(&oc, 0, sizeof oc);
        oc.mode = mode; oc.first = 1; oc.only_flagged = only_flagged;
        if (mode == SVC_TEXT) {
            printf("      %-28s %-14s %-9s %-7s %-9s %s\n", "name", "state", "start", "pid", "account", "binary path");
        } else if (mode == SVC_CSV) {
            puts("name,display_name,state,pid,start_type,account,binary_path,service_dll,reason,signature");
        } else {
            putchar('[');
        }
        return offline_services(hive, &oc, drivers);
    }

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == NULL) {
        fprintf(stderr, "services: OpenSCManager failed (error %lu)\n",
                (unsigned long)GetLastError());
        return 1;
    }

    DWORD type = SERVICE_WIN32 | (drivers ? SERVICE_DRIVER : 0);
    DWORD bytes = 0, count = 0, resume = 0;
    // First call sizes the buffer.
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, type, SERVICE_STATE_ALL,
                          NULL, 0, &bytes, &count, &resume, NULL);
    if (bytes == 0) {
        fprintf(stderr, "services: nothing to enumerate (error %lu)\n",
                (unsigned long)GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    BYTE *buf = (BYTE *)malloc(bytes);
    if (buf == NULL) {
        CloseServiceHandle(scm);
        return 1;
    }
    DWORD got = 0;
    resume = 0;
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, type, SERVICE_STATE_ALL,
                               buf, bytes, &got, &count, &resume, NULL)) {
        fprintf(stderr, "services: EnumServicesStatusEx failed (error %lu)\n",
                (unsigned long)GetLastError());
        free(buf);
        CloseServiceHandle(scm);
        return 1;
    }

    struct svc_ctx c;
    c.mode = mode; c.first = 1; c.only_flagged = only_flagged; c.sig = sig; c.shown = 0; c.flagged = 0;
    if (mode == SVC_TEXT) {
        printf("      %-28s %-14s %-9s %-7s %-9s %s\n",
               "name", "state", "start", "pid", "account", "binary path");
    } else if (mode == SVC_CSV) {
        puts("name,display_name,state,pid,start_type,account,binary_path,service_dll,reason,signature");
    } else {
        putchar('[');
    }

    ENUM_SERVICE_STATUS_PROCESSW *svc = (ENUM_SERVICE_STATUS_PROCESSW *)buf;
    for (DWORD i = 0; i < count; i++) {
        char name[256], disp[512], path[1024], account[256], start[16];
        w2u(svc[i].lpServiceName, name, sizeof name);
        w2u(svc[i].lpDisplayName, disp, sizeof disp);
        query_config(scm, svc[i].lpServiceName, start, sizeof start,
                     path, sizeof path, account, sizeof account);
        char dll[1024] = "";
        int is_win32 = (svc[i].ServiceStatusProcess.dwServiceType & SERVICE_WIN32) != 0;
        if (is_win32 && ioc_contains_ci(path, "svchost.exe")) {
            service_dll(svc[i].lpServiceName, dll, sizeof dll);
        }
        const char *reason = classify(is_win32, path, dll);
        // --sig: verify the code that really runs (the ServiceDll for shared
        // svchost services, the binary otherwise).
        char sigtxt[32] = "";
        if (c.sig) {
            char image[1024];
            const char *src = "none";
            int t = sign_command_trust(dll[0] ? dll : path, image, sizeof image, &src);
            snprintf(sigtxt, sizeof sigtxt, "%s", t == 1 ? src : (t == 0 ? "untrusted" : "unresolved"));
            if (t == 0 && reason == NULL) {
                reason = dll[0] ? "ServiceDll not signed / not trusted" : "binary not signed / not trusted";
            }
        }
        emit(&c, name, disp,
             state_name(svc[i].ServiceStatusProcess.dwCurrentState),
             svc[i].ServiceStatusProcess.dwProcessId,
             start[0] ? start : "?", path, account, dll, reason, sigtxt);
    }

    free(buf);
    CloseServiceHandle(scm);

    if (mode == SVC_TEXT) {
        printf("\n%lu service(s), %u flagged%s\n", (unsigned long)count, c.flagged,
               only_flagged ? " (only flagged shown)" : "");
    } else if (mode == SVC_JSON) {
        puts("]");
    }
    return 0;
}
