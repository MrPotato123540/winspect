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
// For shared svchost services the real code is the ServiceDll under
// Services\<name>\Parameters, so we show that too.

#include "services.h"
#include "jsonutil.h"
#include "artparse.h"
#include "ioc.h"
#include "sign.h"

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

int cmd_services(int argc, char **argv)
{
    int mode = SVC_TEXT, drivers = 0, only_flagged = 0, sig = 0;
    for (int a = 0; a < argc; a++) {
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
        const char *reason = NULL;
        if (is_win32 && svc_unquoted_path(path))           reason = "unquoted path with spaces";
        else if (ioc_user_writable(path))                  reason = "binary in user-writable dir";
        else if (dll[0] && ioc_user_writable(dll))         reason = "ServiceDll in user-writable dir";
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
