// winspect bits - BITS job listing (file named bitsjobs.c so its header does
// not shadow the SDK's <bits.h>)
//
// BITS (qmgr) queues downloads/uploads that continue across logons and
// reboots; Windows Update, Store and many updaters use it. Its job object can
// carry a "notify command line" that BITS starts when the job completes or
// fails - a documented way to keep code running (T1197) that leaves no Run key,
// service or task behind. The jobs are read through the public COM interface
// (IBackgroundCopyManager::EnumJobs, IBackgroundCopyJob[2] getters) only; no
// job is created, resumed, completed or cancelled. Judging is done by the
// portable, unit-tested bits_reason (artparse.c).

#define COBJMACROS
#include "bitsjobs.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <bits.h>
#include <bits1_5.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int mode, first, only_flagged;
    unsigned jobs, flagged;
} bctx;

static void w2u(const WCHAR *w, char *out, size_t n)
{
    out[0] = 0;
    if (w) WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)n, NULL, NULL);
}

static const char *state_name(BG_JOB_STATE s)
{
    static const char *const names[] = {
        "queued", "connecting", "transferring", "suspended", "error",
        "transient error", "transferred", "acknowledged", "cancelled",
    };
    return (unsigned)s < sizeof names / sizeof names[0] ? names[s] : "?";
}

static const char *type_name(BG_JOB_TYPE t)
{
    return t == BG_JOB_TYPE_DOWNLOAD ? "download" : t == BG_JOB_TYPE_UPLOAD ? "upload" :
           t == BG_JOB_TYPE_UPLOAD_REPLY ? "upload-reply" : "?";
}

static void ft_utc(const FILETIME *f, char *out, size_t n)
{
    filetime_utc_str(((uint64_t)f->dwHighDateTime << 32) | f->dwLowDateTime, out, n);
}

// Owner SID string -> DOMAIN\user (or the SID when it cannot be resolved).
static void owner_name(const WCHAR *sidw, char *out, size_t n)
{
    w2u(sidw, out, n);
    PSID sid = NULL;
    if (sidw == NULL || !ConvertStringSidToSidW(sidw, &sid)) return;
    char name[128], dom[128];
    DWORD nl = sizeof name, dl = sizeof dom;
    SID_NAME_USE use;
    if (LookupAccountSidA(NULL, sid, name, &nl, dom, &dl, &use))
        snprintf(out, n, "%s%s%s", dom, dom[0] ? "\\" : "", name);
    LocalFree(sid);
}

#define MAX_FILES 32

typedef struct { char remote[1024], local[1024]; } bfile;

static void one_job(bctx *c, IBackgroundCopyJob *job)
{
    char name[512] = "", owner[300] = "", guid[64] = "", notify[2048] = "";
    char created[32], modified[32], done[32];
    WCHAR *w = NULL;
    if (SUCCEEDED(IBackgroundCopyJob_GetDisplayName(job, &w))) { w2u(w, name, sizeof name); CoTaskMemFree(w); }
    w = NULL;
    if (SUCCEEDED(IBackgroundCopyJob_GetOwner(job, &w))) { owner_name(w, owner, sizeof owner); CoTaskMemFree(w); }
    GUID id;
    if (SUCCEEDED(IBackgroundCopyJob_GetId(job, &id))) {
        WCHAR gw[64];
        if (StringFromGUID2(&id, gw, 64)) w2u(gw, guid, sizeof guid);
    }
    BG_JOB_STATE st = BG_JOB_STATE_QUEUED;
    BG_JOB_TYPE ty = BG_JOB_TYPE_DOWNLOAD;
    IBackgroundCopyJob_GetState(job, &st);
    IBackgroundCopyJob_GetType(job, &ty);
    BG_JOB_TIMES t;
    memset(&t, 0, sizeof t);
    IBackgroundCopyJob_GetTimes(job, &t);
    ft_utc(&t.CreationTime, created, sizeof created);
    ft_utc(&t.ModificationTime, modified, sizeof modified);
    ft_utc(&t.TransferCompletionTime, done, sizeof done);

    // Notify command line lives on the BITS 1.5 interface.
    IBackgroundCopyJob2 *j2 = NULL;
    if (SUCCEEDED(IBackgroundCopyJob_QueryInterface(job, &IID_IBackgroundCopyJob2, (void **)&j2)) && j2) {
        WCHAR *prog = NULL, *params = NULL;
        if (SUCCEEDED(IBackgroundCopyJob2_GetNotifyCmdLine(j2, &prog, &params))) {
            char p8[1024] = "", a8[1024] = "";
            w2u(prog, p8, sizeof p8);
            w2u(params, a8, sizeof a8);
            // By convention the parameters repeat the program as argv[0]
            // (possibly quoted); show it once.
            const char *q = a8[0] == '"' ? a8 + 1 : a8;
            if (a8[0] == 0)                                 snprintf(notify, sizeof notify, "%s", p8);
            else if (p8[0] == 0 || _strnicmp(q, p8, strlen(p8)) == 0) snprintf(notify, sizeof notify, "%s", a8);
            else                                            snprintf(notify, sizeof notify, "%s %s", p8, a8);
            if (prog) CoTaskMemFree(prog);
            if (params) CoTaskMemFree(params);
        }
        IBackgroundCopyJob2_Release(j2);
    }

    static bfile files[MAX_FILES];
    size_t nf = 0;
    IEnumBackgroundCopyFiles *ef = NULL;
    if (SUCCEEDED(IBackgroundCopyJob_EnumFiles(job, &ef)) && ef) {
        IBackgroundCopyFile *f = NULL;
        ULONG got = 0;
        while (nf < MAX_FILES && IEnumBackgroundCopyFiles_Next(ef, 1, &f, &got) == S_OK && got == 1) {
            WCHAR *r = NULL, *l = NULL;
            files[nf].remote[0] = files[nf].local[0] = 0;
            if (SUCCEEDED(IBackgroundCopyFile_GetRemoteName(f, &r))) { w2u(r, files[nf].remote, sizeof files[nf].remote); CoTaskMemFree(r); }
            if (SUCCEEDED(IBackgroundCopyFile_GetLocalName(f, &l)))  { w2u(l, files[nf].local, sizeof files[nf].local); CoTaskMemFree(l); }
            IBackgroundCopyFile_Release(f);
            nf++;
        }
        IEnumBackgroundCopyFiles_Release(ef);
    }

    // First reason wins: the notify command, else the first file that has one.
    const char *reason = bits_reason(notify, NULL, NULL);
    for (size_t i = 0; reason == NULL && i < nf; i++) reason = bits_reason(NULL, files[i].remote, files[i].local);
    c->jobs++;
    if (reason) c->flagged++;
    if (c->only_flagged && reason == NULL) return;
    if (owner[0] == 0) snprintf(owner, sizeof owner, "-");

    if (c->mode == 0) {
        printf("\n%s %s  %s\n", reason ? "[!]" : "   ", name[0] ? name : "(no name)", guid);
        printf("    owner %s, %s, %s; created %s, modified %s, completed %s (UTC)\n", owner, type_name(ty),
               state_name(st), created, modified, done);
        for (size_t i = 0; i < nf; i++) printf("    %s\n      -> %s\n", files[i].remote, files[i].local);
        if (notify[0]) printf("    notify command: %s\n", notify);
        if (reason) printf("    <- %s\n", reason);
    } else if (c->mode == 2) {
        // One row per file (a job without files still gets one row).
        for (size_t i = 0; i < (nf ? nf : 1); i++) {
            csv_str(name); putchar(',');
            csv_str(guid); putchar(',');
            csv_str(owner);
            printf(",%s,%s,%s,%s,%s,", type_name(ty), state_name(st), created, modified, done);
            csv_str(nf ? files[i].remote : ""); putchar(',');
            csv_str(nf ? files[i].local : ""); putchar(',');
            csv_str(notify); putchar(',');
            csv_str(reason ? reason : ""); putchar('\n');
        }
    } else {
        printf("%s{\"name\":", c->first ? "" : ",");
        json_str(name);
        fputs(",\"id\":", stdout);      json_str(guid);
        fputs(",\"owner\":", stdout);   json_str(owner);
        printf(",\"type\":\"%s\",\"state\":\"%s\",\"created\":", type_name(ty), state_name(st));
        json_str(created);
        fputs(",\"modified\":", stdout);  json_str(modified);
        fputs(",\"completed\":", stdout); json_str(done);
        fputs(",\"files\":[", stdout);
        for (size_t i = 0; i < nf; i++) {
            printf("%s{\"remote\":", i ? "," : "");
            json_str(files[i].remote);
            fputs(",\"local\":", stdout);
            json_str(files[i].local);
            putchar('}');
        }
        fputs("],\"notify\":", stdout); json_str(notify);
        printf(",\"suspicious\":%s,\"reason\":", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

int cmd_bits(int argc, char **argv)
{
    bctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)          c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)      c.mode = 2;
        else if (strcmp(argv[a], "--flagged") == 0)  c.only_flagged = 1;
        else {
            fprintf(stderr, "bits: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        fprintf(stderr, "bits: CoInitializeEx failed (0x%08lX)\n", (unsigned long)hr);
        return 1;
    }
    IBackgroundCopyManager *mgr = NULL;
    hr = CoCreateInstance(&CLSID_BackgroundCopyManager, NULL, CLSCTX_LOCAL_SERVER,
                          &IID_IBackgroundCopyManager, (void **)&mgr);
    if (FAILED(hr) || mgr == NULL) {
        fprintf(stderr, "bits: cannot reach the BITS service (0x%08lX)\n", (unsigned long)hr);
        CoUninitialize();
        return 1;
    }
    // All users needs admin; fall back to the caller's own jobs and say so.
    int all = 1;
    IEnumBackgroundCopyJobs *ej = NULL;
    hr = IBackgroundCopyManager_EnumJobs(mgr, BG_JOB_ENUM_ALL_USERS, &ej);
    if (FAILED(hr)) {
        all = 0;
        hr = IBackgroundCopyManager_EnumJobs(mgr, 0, &ej);
    }
    if (FAILED(hr) || ej == NULL) {
        fprintf(stderr, "bits: cannot list jobs (0x%08lX)\n", (unsigned long)hr);
        IBackgroundCopyManager_Release(mgr);
        CoUninitialize();
        return 1;
    }
    if (c.mode == 0) {
        printf("bits  (%s)\n", all ? "jobs of all users" : "own jobs only - run as administrator for all users");
    } else if (c.mode == 2) {
        puts("name,id,owner,type,state,created,modified,completed,remote,local,notify,reason");
    } else {
        putchar('[');
    }
    IBackgroundCopyJob *job = NULL;
    ULONG got = 0;
    while (IEnumBackgroundCopyJobs_Next(ej, 1, &job, &got) == S_OK && got == 1) {
        one_job(&c, job);
        IBackgroundCopyJob_Release(job);
    }
    IEnumBackgroundCopyJobs_Release(ej);
    IBackgroundCopyManager_Release(mgr);
    CoUninitialize();
    if (c.mode == 1) {
        puts("]");
    } else if (c.mode == 0) {
        printf("\n%u job(s), %u flagged\n", c.jobs, c.flagged);
    }
    return 0;
}
