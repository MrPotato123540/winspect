// winspect detections - Defender Detection History
//
// One binary file per detection, named by the detection GUID, in numbered
// sub-folders. defhist.c (portable, unit-tested against real files) decodes
// them; this file finds the files and prints, newest first.

#include "detections.h"
#include "defhist.h"
#include "artparse.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DH_MAX_FILE (4u * 1024u * 1024u)    // real files are a few KiB

typedef struct {
    dh_record r;
    char file[MAX_PATH * 2];
} drow;

typedef struct {
    drow *v;
    size_t n, cap;
    unsigned seen, denied;
} dlist;

static void one_file(dlist *l, const char *path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_ACCESS_DENIED) l->denied++;
        return;
    }
    LARGE_INTEGER sz;
    unsigned char *d = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart >= 64 && sz.QuadPart <= (LONGLONG)DH_MAX_FILE &&
            (d = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL) {
        if (!ReadFile(h, d, (DWORD)sz.QuadPart, &got, NULL)) got = 0;
    }
    CloseHandle(h);
    if (d == NULL) return;
    l->seen++;
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 32;
        drow *nv = (drow *)realloc(l->v, nc * sizeof *nv);
        if (nv != NULL) { l->v = nv; l->cap = nc; }
    }
    if (l->n < l->cap && dh_parse(d, got, &l->v[l->n].r) == 0) {
        snprintf(l->v[l->n].file, sizeof l->v[l->n].file, "%s", path);
        l->n++;
    }
    free(d);
}

static void scan(dlist *l, const char *dir, int depth)
{
    char pat[MAX_PATH * 2];
    if (snprintf(pat, sizeof pat, "%s\\*", dir) >= (int)sizeof pat) return;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_ACCESS_DENIED) l->denied++;
        return;
    }
    do {
        if (fd.cFileName[0] == '.') continue;
        char full[MAX_PATH * 2];
        if (snprintf(full, sizeof full, "%s\\%s", dir, fd.cFileName) >= (int)sizeof full) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (depth > 0 && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) scan(l, full, depth - 1);
        } else {
            one_file(l, full);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static int newest_first(const void *a, const void *b)
{
    uint64_t x = ((const drow *)a)->r.detect_time, y = ((const drow *)b)->r.detect_time;
    return x < y ? 1 : x > y ? -1 : 0;
}

static void ft(uint64_t t, char *out, size_t n)
{
    out[0] = '\0';
    if (t == 0) return;
    char iso[40];
    filetime_utc_str(t, iso, sizeof iso);
    snprintf(out, n, "%.19s", iso);
}

int cmd_detections(int argc, char **argv)
{
    int mode = 0;
    const char *target = NULL, *find = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc) find = argv[++a];
        else if (target == NULL && argv[a][0] != '-') target = argv[a];
        else {
            fprintf(stderr, "detections: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    char def[MAX_PATH * 2];
    int is_default = target == NULL;
    if (target == NULL) {
        char base[MAX_PATH];
        if (GetEnvironmentVariableA("ProgramData", base, MAX_PATH) == 0) snprintf(base, sizeof base, "C:\\ProgramData");
        snprintf(def, sizeof def, "%s\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory", base);
        target = def;
    }
    dlist l;
    memset(&l, 0, sizeof l);
    DWORD at = GetFileAttributesA(target);
    DWORD at_err = GetLastError();
    if (at == INVALID_FILE_ATTRIBUTES) {
        if (mode == 1) puts("[]");
        else if (mode == 2) puts("detected,threat,threat_id,file,resource_type,sha256,container,url,user,process,remediated,remediated_by,status_changed,detection_id,history_file,reason");
        if (is_default && at_err != ERROR_ACCESS_DENIED) {
            // No folder at all: Defender never recorded a detection here (or is not installed).
            if (mode == 0) puts("detections  (Defender Detection History)\n\n0 detection(s): no Detection History folder on this machine");
            return 0;
        }
        fprintf(stderr, "detections: cannot open '%s' (%s)\n", target, at_err == ERROR_ACCESS_DENIED ? "access denied - run elevated" : "not found");
        return 1;
    }
    if (at & FILE_ATTRIBUTE_DIRECTORY) scan(&l, target, 3);
    else one_file(&l, target);
    if (l.n > 1) qsort(l.v, l.n, sizeof *l.v, newest_first);

    if (mode == 0) {
        printf("detections  (Defender Detection History: %s; UTC, newest first)\n\n", target);
    } else if (mode == 2) {
        puts("detected,threat,threat_id,file,resource_type,sha256,container,url,user,process,remediated,remediated_by,status_changed,detection_id,history_file,reason");
    } else {
        putchar('[');
    }
    unsigned shown = 0, open_count = 0;
    for (size_t i = 0; i < l.n; i++) {
        const dh_record *r = &l.v[i].r;
        const dh_resource *p = dh_primary(r);
        const char *loc = p ? p->location : "", *rtype = p ? p->type : "", *sha = p ? p->sha256 : "";
        char url[1024] = "";
        const char *container = "";
        for (int k = 0; k < r->nres; k++) {
            if (strcmp(r->res[k].type, "webfile") == 0 && url[0] == '\0') dh_web_url(r->res[k].location, url, sizeof url);
            else if (strcmp(r->res[k].type, "containerfile") == 0 && container[0] == '\0') container = r->res[k].location;
            if (sha[0] == '\0' && r->res[k].sha256[0]) sha = r->res[k].sha256;
        }
        if (find && !ioc_contains_ci(r->threat, find) && !ioc_contains_ci(loc, find) && !ioc_contains_ci(url, find) &&
                !ioc_contains_ci(r->user, find) && !ioc_contains_ci(r->process, find) && !ioc_contains_ci(sha, find)) continue;
        char t_det[24], t_rem[24], t_st[24];
        ft(r->detect_time, t_det, sizeof t_det);
        ft(r->remediation_time, t_rem, sizeof t_rem);
        ft(r->status_time, t_st, sizeof t_st);
        const char *reason = r->remediation_time ? "detected by Defender (remediated)" : "detected by Defender, no remediation recorded";
        shown++;
        if (r->remediation_time == 0) open_count++;
        if (mode == 0) {
            printf("[!] %-19s  %s\n", t_det[0] ? t_det : "-", r->threat);
            printf("        %-11s %s\n", rtype[0] ? rtype : "resource", loc);
            if (container[0]) printf("        %-11s %s\n", "inside", container);
            if (url[0])       printf("        %-11s %s\n", "from", url);
            if (sha[0])       printf("        %-11s %s\n", "sha256", sha);
            printf("        %-11s %s%s%s\n", "user", r->user[0] ? r->user : "-", r->process[0] ? "   process " : "", r->process);
            if (t_rem[0]) printf("        %-11s %s by %s\n", "remediated", t_rem, r->remediation_user[0] ? r->remediation_user : "-");
            else          printf("        %-11s %s\n", "remediated", "no remediation recorded");
        } else if (mode == 2) {
            printf("%s,", t_det);
            csv_str(r->threat);
            printf(",%llu,", (unsigned long long)r->threat_id);
            csv_str(loc); putchar(',');
            csv_str(rtype); putchar(',');
            csv_str(sha); putchar(',');
            csv_str(container); putchar(',');
            csv_str(url); putchar(',');
            csv_str(r->user); putchar(',');
            csv_str(r->process);
            printf(",%s,", t_rem);
            csv_str(r->remediation_user);
            printf(",%s,%s,", t_st, r->guid);
            csv_str(l.v[i].file); putchar(',');
            csv_str(reason); putchar('\n');
        } else {
            printf("%s{\"detected\":\"%s\",\"threat\":", shown > 1 ? "," : "", t_det);
            json_str(r->threat);
            printf(",\"threat_id\":%llu,\"file\":", (unsigned long long)r->threat_id);
            json_str(loc);
            fputs(",\"resource_type\":", stdout); json_str(rtype);
            fputs(",\"sha256\":", stdout);        json_str(sha);
            fputs(",\"container\":", stdout);     json_str(container);
            fputs(",\"url\":", stdout);           json_str(url);
            fputs(",\"user\":", stdout);          json_str(r->user);
            fputs(",\"process\":", stdout);       json_str(r->process);
            printf(",\"remediated\":\"%s\",\"remediated_by\":", t_rem);
            json_str(r->remediation_user);
            printf(",\"status_changed\":\"%s\",\"detection_id\":\"%s\",\"history_file\":", t_st, r->guid);
            json_str(l.v[i].file);
            fputs(",\"resources\":[", stdout);
            for (int k = 0; k < r->nres; k++) {
                printf("%s{\"type\":", k ? "," : "");
                json_str(r->res[k].type);
                fputs(",\"location\":", stdout); json_str(r->res[k].location);
                putchar('}');
            }
            fputs("],\"suspicious\":true,\"reason\":", stdout);
            json_str(reason);
            putchar('}');
        }
    }
    if (mode == 1) puts("]");
    else if (mode == 0) {
        printf("%s%u detection(s), %u without a recorded remediation", shown ? "\n" : "", shown, open_count);
        if (l.seen > l.n) printf("; %u file(s) not recognised", l.seen - (unsigned)l.n);
        putchar('\n');
    }
    if (l.denied) fprintf(stderr, "detections: %u folder(s) / file(s) could not be opened (access denied - run elevated)\n", l.denied);
    free(l.v);
    return 0;
}
