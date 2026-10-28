// winspect wmi - permanent WMI event subscriptions (fileless persistence)
//
// WMI can run an action whenever an event matches a query, and keep doing so
// across reboots. Three objects in the root\subscription namespace make up
// such a "permanent subscription":
//   __EventFilter              - the trigger: a WQL event query
//                                ("... WITHIN 60 WHERE TargetInstance ISA
//                                'Win32_PerfFormattedData_PerfOS_System'")
//   __EventConsumer subclasses - the action. Two of the standard ones run code:
//       CommandLineEventConsumer  (CommandLineTemplate / ExecutablePath)
//       ActiveScriptEventConsumer (VBScript/JScript text or file)
//   __FilterToConsumerBinding  - links one filter to one consumer
// Nothing touches the disk outside the WMI repository, which is why this is a
// favourite of intruders (MITRE T1546.003) and why Autoruns has a WMI tab.
//
// We connect with COM, run three read-only WQL SELECT queries and print what
// comes back. Code-running consumers are flagged; Windows itself ships an
// "SCM Event Log Consumer" (NTEventLogEventConsumer) that is benign and is
// listed without a flag. Nothing is created, changed or deleted.

#define COBJMACROS
#include "wmi.h"
#include "jsonutil.h"

#include <windows.h>
#include <objbase.h>
#include <wbemcli.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int mode;
    int first;      // JSON comma state within the current array
    unsigned rows, flagged;
} wmi_ctx;

// Read a property as UTF-8 text ("" if absent / not a string).
static void prop(IWbemClassObject *o, const WCHAR *name, char *out, size_t n)
{
    out[0] = '\0';
    VARIANT v;
    VariantInit(&v);
    if (SUCCEEDED(IWbemClassObject_Get(o, name, 0, &v, NULL, NULL)) &&
            V_VT(&v) == VT_BSTR && V_BSTR(&v) != NULL) {
        WideCharToMultiByte(CP_UTF8, 0, V_BSTR(&v), -1, out, (int)n, NULL, NULL);
        out[n - 1] = '\0';
    }
    VariantClear(&v);
}

static void row(wmi_ctx *c, const char *kind, const char *name, const char *cls,
                const char *detail, const char *reason)
{
    c->rows++;
    if (reason) { c->flagged++; }
    if (c->mode == 0) {
        printf("  %s%-20s %s\n", reason ? "[!] " : "    ", cls, name);
        if (detail[0]) {
            printf("        %s\n", detail);
        }
        if (reason) {
            printf("        <- %s\n", reason);
        }
    } else if (c->mode == 2) {
        csv_str(kind);   putchar(',');
        csv_str(name);   putchar(',');
        csv_str(cls);    putchar(',');
        csv_str(detail); putchar(',');
        csv_str(reason ? reason : ""); putchar('\n');
    } else {
        printf("%s{\"name\":", c->first ? "" : ",");
        json_str(name);
        fputs(",\"class\":", stdout);  json_str(cls);
        fputs(",\"detail\":", stdout); json_str(detail);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

// Run one query and report each object via the per-kind formatter below.
static void query(IWbemServices *svc, wmi_ctx *c, const WCHAR *wql, const char *kind)
{
    BSTR lang = SysAllocString(L"WQL");
    BSTR q = SysAllocString(wql);
    IEnumWbemClassObject *en = NULL;
    HRESULT hr = IWbemServices_ExecQuery(svc, lang, q,
                                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                         NULL, &en);
    SysFreeString(lang);
    SysFreeString(q);
    if (FAILED(hr) || en == NULL) {
        if (c->mode == 0) {
            printf("  (query failed: 0x%08lX)\n", (unsigned long)hr);
        }
        return;
    }
    for (;;) {
        IWbemClassObject *o = NULL;
        ULONG got = 0;
        // 10 s per object is generous; a hung provider must not hang us.
        hr = IEnumWbemClassObject_Next(en, 10000, 1, &o, &got);
        if (hr != WBEM_S_NO_ERROR || got == 0 || o == NULL) {
            break;
        }
        char name[512], cls[128], detail[2048];
        prop(o, L"Name", name, sizeof name);
        prop(o, L"__CLASS", cls, sizeof cls);
        detail[0] = '\0';
        const char *reason = NULL;

        if (strcmp(kind, "filter") == 0) {
            char ql[1024], ns[256];
            prop(o, L"Query", ql, sizeof ql);
            prop(o, L"EventNamespace", ns, sizeof ns);
            snprintf(detail, sizeof detail, "query: %s%s%s", ql, ns[0] ? "   ns: " : "", ns);
        } else if (strcmp(kind, "consumer") == 0) {
            if (_stricmp(cls, "CommandLineEventConsumer") == 0) {
                char cmd[1024], exe[512];
                prop(o, L"CommandLineTemplate", cmd, sizeof cmd);
                prop(o, L"ExecutablePath", exe, sizeof exe);
                snprintf(detail, sizeof detail, "runs: %s%s%s", exe, exe[0] ? " " : "", cmd);
                reason = "consumer runs a command line";
            } else if (_stricmp(cls, "ActiveScriptEventConsumer") == 0) {
                char eng[64], file[512], text[512];
                prop(o, L"ScriptingEngine", eng, sizeof eng);
                prop(o, L"ScriptFileName", file, sizeof file);
                prop(o, L"ScriptText", text, sizeof text);
                // Script text can be long; show the start, one line.
                for (char *p = text; *p; p++) {
                    if (*p == '\r' || *p == '\n') *p = ' ';
                }
                snprintf(detail, sizeof detail, "%s script: %s%s", eng, file[0] ? file : text,
                         (!file[0] && strlen(text) >= sizeof text - 1) ? "..." : "");
                reason = "consumer runs a script";
            }
        } else {
            // Bindings have no Name; show which filter feeds which consumer.
            char f[512], k[512];
            prop(o, L"Filter", f, sizeof f);
            prop(o, L"Consumer", k, sizeof k);
            snprintf(name, sizeof name, "%s", k);
            snprintf(detail, sizeof detail, "filter: %s", f);
        }
        row(c, kind, name, cls, detail, reason);
        IWbemClassObject_Release(o);
    }
    IEnumWbemClassObject_Release(en);
}

int cmd_wmi(int argc, char **argv)
{
    wmi_ctx c = { 0, 1, 0, 0 };
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else {
            fprintf(stderr, "wmi: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        fprintf(stderr, "wmi: CoInitializeEx failed (0x%08lX)\n", (unsigned long)hr);
        return 1;
    }
    // Process-wide COM security; RPC_E_TOO_LATE just means it was already set.
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    IWbemLocator *loc = NULL;
    IWbemServices *svc = NULL;
    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (void **)&loc);
    if (SUCCEEDED(hr)) {
        BSTR ns = SysAllocString(L"ROOT\\subscription");
        hr = IWbemLocator_ConnectServer(loc, ns, NULL, NULL, NULL, 0, NULL, NULL, &svc);
        SysFreeString(ns);
    }
    if (FAILED(hr) || svc == NULL) {
        fprintf(stderr, "wmi: cannot connect to ROOT\\subscription (0x%08lX)\n", (unsigned long)hr);
        if (loc) IWbemLocator_Release(loc);
        CoUninitialize();
        return 1;
    }
    CoSetProxyBlanket((IUnknown *)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    if (c.mode == 2) {
        puts("kind,name,class,detail,reason");
    }
    static const struct { const char *kind, *title; const WCHAR *wql; } parts[] = {
        { "filter",   "filters",  L"SELECT * FROM __EventFilter" },
        { "consumer", "consumers", L"SELECT * FROM __EventConsumer" },
        { "binding",  "bindings", L"SELECT * FROM __FilterToConsumerBinding" },
    };
    if (c.mode == 1) putchar('{');
    for (size_t i = 0; i < sizeof parts / sizeof parts[0]; i++) {
        if (c.mode == 0) {
            printf("%s%s (root\\subscription)\n", i ? "\n" : "", parts[i].title);
        } else if (c.mode == 1) {
            printf("%s\"%s\":[", i ? "," : "", parts[i].title);
            c.first = 1;
        }
        query(svc, &c, parts[i].wql, parts[i].kind);
        if (c.mode == 1) putchar(']');
    }
    if (c.mode == 1) {
        puts("}");
    } else if (c.mode == 0) {
        printf("\n%u object(s), %u consumer(s) that run code\n", c.rows, c.flagged);
    }

    IWbemServices_Release(svc);
    IWbemLocator_Release(loc);
    CoUninitialize();
    return 0;
}
