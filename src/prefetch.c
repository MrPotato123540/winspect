// winspect prefetch - Windows Prefetch files as evidence of execution
//
// To speed up launches, Windows records each program's start-up file accesses
// in %SystemRoot%\Prefetch\<EXE>-<HASH>.pf. As a side effect every .pf file
// says "this executable ran, N times, most recently at T" - one of the most
// used execution artifacts in DFIR (PECmd and WinPrefetchView read the same).
//
// Windows 10+ compresses the files: a "MAM" header, then XPRESS Huffman data.
// ntdll exports the matching decompressor (RtlDecompressBufferEx), so we use the
// OS's own code instead of writing one. The decompressed SCCA structure is
// parsed by the portable pfparse.c, which is unit-tested on Linux.
//
// Read-only: files are opened for reading only. The Prefetch folder's ACL
// normally admits only Administrators/SYSTEM, so access denied is reported
// clearly. Note that prefetching can be disabled (common on servers and some
// SSD setups), in which case the folder is empty - absence is not proof.

#include "prefetch.h"
#include "pfparse.h"
#include "jsonutil.h"
#include "ioc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PF_MAX_FILE  (16u * 1024 * 1024)   // sanity cap for on-disk and decompressed size
#define WS_COMPRESSION_FORMAT_XPRESS_HUFF 4

typedef LONG (NTAPI *RtlGetCompressionWorkSpaceSize_t)(USHORT, PULONG, PULONG);
typedef LONG (NTAPI *RtlDecompressBufferEx_t)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG,
                                              PULONG, PVOID);

typedef struct {
    pf_info info;
    char    file[MAX_PATH];
    char    path[520];          // full path of the exe, from the referenced files
    const char *reason;         // why it is flagged, or NULL
} pf_entry;

// Like PECmd, look up where the program actually ran from (its own entry in
// the referenced-file list) and flag runs from user-writable directories -
// Temp, Downloads, AppData, Public: where dropped tools usually start.
static void annotate(pf_entry *e, const unsigned char *buf, size_t len)
{
    e->reason = NULL;
    if (pf_exe_path(buf, len, e->info.exe, e->path, sizeof e->path) &&
            ioc_user_writable(e->path)) {
        e->reason = "ran from a user-writable dir";
    }
}

// Read a whole file; returns malloc'd buffer or NULL (sets *err to GetLastError).
static unsigned char *slurp(const char *path, size_t *len, DWORD *err)
{
    *err = 0;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE |
                           FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        *err = GetLastError();
        return NULL;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > PF_MAX_FILE) {
        CloseHandle(h);
        return NULL;
    }
    unsigned char *buf = (unsigned char *)malloc((size_t)sz.QuadPart);
    DWORD got = 0;
    if (buf == NULL || !ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL) ||
            got != (DWORD)sz.QuadPart) {
        free(buf);
        CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    *len = got;
    return buf;
}

// If buf is MAM-compressed, replace it with the decompressed bytes.
// Returns 0 on success (compressed or not), -1 on failure.
static int maybe_decompress(unsigned char **buf, size_t *len)
{
    unsigned fmt;
    uint32_t usize;
    size_t off;
    if (!pf_mam_header(*buf, *len, &fmt, &usize, &off)) {
        return 0;   // plain SCCA (Windows 8.1 and older)
    }
    if (fmt != WS_COMPRESSION_FORMAT_XPRESS_HUFF || usize == 0 || usize > PF_MAX_FILE) {
        return -1;
    }
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    RtlGetCompressionWorkSpaceSize_t GetWs = ntdll ? (RtlGetCompressionWorkSpaceSize_t)
        (void(*)(void))GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize") : NULL;
    RtlDecompressBufferEx_t Decomp = ntdll ? (RtlDecompressBufferEx_t)
        (void(*)(void))GetProcAddress(ntdll, "RtlDecompressBufferEx") : NULL;
    if (GetWs == NULL || Decomp == NULL) {
        return -1;
    }
    ULONG wssize = 0, fragsize = 0;
    if (GetWs(WS_COMPRESSION_FORMAT_XPRESS_HUFF, &wssize, &fragsize) < 0) {
        return -1;
    }
    void *ws = malloc(wssize ? wssize : 1);
    unsigned char *out = (unsigned char *)malloc(usize);
    ULONG final_size = 0;
    LONG st = -1;
    if (ws != NULL && out != NULL) {
        st = Decomp(WS_COMPRESSION_FORMAT_XPRESS_HUFF, out, usize, *buf + off,
                    (ULONG)(*len - off), &final_size, ws);
    }
    free(ws);
    if (st < 0 || final_size == 0) {
        free(out);
        return -1;
    }
    free(*buf);
    *buf = out;
    *len = final_size;
    return 0;
}

// Load and parse one .pf file. Returns 0 ok, otherwise prints why to stderr
// when verbose is set. If keep is non-NULL the decompressed buffer is handed
// back (caller frees) so the file/volume lists can be walked afterwards.
static int load_pf(const char *path, pf_info *info, int verbose,
                   unsigned char **keep, size_t *keeplen)
{
    size_t len = 0;
    DWORD err = 0;
    unsigned char *buf = slurp(path, &len, &err);
    if (buf == NULL) {
        if (verbose) {
            fprintf(stderr, "prefetch: cannot read '%s'%s\n", path,
                    err == ERROR_ACCESS_DENIED ? " (access denied - run elevated)" : "");
        }
        return -1;
    }
    if (maybe_decompress(&buf, &len) != 0) {
        if (verbose) fprintf(stderr, "prefetch: cannot decompress '%s'\n", path);
        free(buf);
        return -1;
    }
    int rc = pf_parse(buf, len, info);
    if (rc == 0 && keep != NULL) {
        *keep = buf;
        *keeplen = len;
    } else {
        free(buf);
    }
    if (rc != 0 && verbose) {
        fprintf(stderr, "prefetch: '%s' is %s\n", path,
                rc == -1 ? "not a prefetch (SCCA) file" : "an unsupported prefetch version");
    }
    return rc;
}

static void ft_str(uint64_t t, char *out, size_t n)
{
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = (DWORD)t;
    ft.dwHighDateTime = (DWORD)(t >> 32);
    if (t == 0 || !FileTimeToSystemTime(&ft, &st)) {
        snprintf(out, n, "-");
        return;
    }
    snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

typedef struct {
    int mode;
    int first;
    unsigned flagged;
} list_ctx;

static void on_volume(const char *dev, uint32_t serial, uint64_t created, void *vctx)
{
    list_ctx *c = (list_ctx *)vctx;
    char ts[32];
    ft_str(created, ts, sizeof ts);
    if (c->mode == 0) {
        printf("  %-48s serial %08lX  created %s\n", dev, (unsigned long)serial, ts);
    } else if (c->mode == 1) {
        printf("%s{\"device\":", c->first ? "" : ",");
        json_str(dev);
        printf(",\"serial\":\"%08lX\",\"created\":", (unsigned long)serial);
        json_str(ts);
        putchar('}');
        c->first = 0;
    }
}

static void on_file(const char *name, void *vctx)
{
    list_ctx *c = (list_ctx *)vctx;
    int hint = ioc_user_writable(name);
    c->flagged += (unsigned)hint;
    if (c->mode == 0) {
        printf("  %s%s\n", name, hint ? "   [user-writable dir]" : "");
    } else if (c->mode == 2) {
        csv_str(name);
        fputs(hint ? ",true\n" : ",false\n", stdout);
    } else {
        printf("%s{\"path\":", c->first ? "" : ",");
        json_str(name);
        printf(",\"user_writable_dir\":%s}", hint ? "true" : "false");
        c->first = 0;
    }
}

// --files: the volumes and every file the program touched in its first
// seconds (DLLs, configs, data). Shows WHAT it loaded, not just that it ran.
static void print_files(const pf_entry *e, const unsigned char *buf, size_t len, int mode)
{
    list_ctx c = { mode, 1, 0 };
    if (mode == 2) {
        puts("referenced_file,user_writable_dir");
        pf_filenames(buf, len, on_file, &c);
        return;
    }
    if (mode == 1) {
        printf("{\"executable\":");
        json_str(e->info.exe);
        printf(",\"run_count\":%lu,\"volumes\":[", (unsigned long)e->info.run_count);
        pf_volumes(buf, len, on_volume, &c);
        fputs("],\"files\":[", stdout);
        c.first = 1;
        pf_filenames(buf, len, on_file, &c);
        puts("]}");
        return;
    }
    puts("\nvolumes");
    if (pf_volumes(buf, len, on_volume, &c) < 0) {
        puts("  (volume table unreadable)");
    }
    puts("\nreferenced files");
    int nf = pf_filenames(buf, len, on_file, &c);
    if (nf < 0) {
        puts("  (file-name table unreadable)");
    } else {
        printf("\n%d file(s), %u in user-writable dirs\n", nf, c.flagged);
    }
}

static int by_last_run_desc(const void *a, const void *b)
{
    uint64_t ta = ((const pf_entry *)a)->info.ntimes ? ((const pf_entry *)a)->info.times[0] : 0;
    uint64_t tb = ((const pf_entry *)b)->info.ntimes ? ((const pf_entry *)b)->info.times[0] : 0;
    return (ta < tb) - (ta > tb);
}

static void print_entries(const pf_entry *e, size_t n, int mode, int only_flagged)
{
    if (mode == 0) {
        printf("    %-26s %6s  %-19s  %s\n", "executable", "runs", "last run (UTC)", "file");
    } else if (mode == 2) {
        puts("executable,run_count,last_run,hash,version,file,path,reason");
    } else {
        putchar('[');
    }
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        const pf_info *p = &e[i].info;
        if (only_flagged && e[i].reason == NULL) {
            continue;
        }
        char last[32];
        ft_str(p->ntimes ? p->times[0] : 0, last, sizeof last);
        if (mode == 0) {
            printf("%s%-26s %6lu  %-19s  %s\n", e[i].reason ? "[!] " : "    ", p->exe,
                   (unsigned long)p->run_count, last, e[i].file);
            // Show the older run times compactly (v26+ keeps up to 8).
            for (int t = 1; t < p->ntimes; t++) {
                char older[32];
                ft_str(p->times[t], older, sizeof older);
                printf("    %-26s %6s  %-19s\n", "", "", older);
            }
            if (e[i].reason) {
                printf("        %s\n        <- %s\n", e[i].path, e[i].reason);
            }
        } else if (mode == 2) {
            csv_str(p->exe);
            printf(",%lu,", (unsigned long)p->run_count);
            csv_str(last);
            printf(",%08lX,%lu,", (unsigned long)p->hash, (unsigned long)p->version);
            csv_str(e[i].file);   putchar(',');
            csv_str(e[i].path);   putchar(',');
            csv_str(e[i].reason ? e[i].reason : "");
            putchar('\n');
        } else {
            printf("%s{\"executable\":", first ? "" : ",");
            json_str(p->exe);
            printf(",\"run_count\":%lu,\"hash\":\"%08lX\",\"version\":%lu,\"run_times\":[",
                   (unsigned long)p->run_count, (unsigned long)p->hash,
                   (unsigned long)p->version);
            for (int t = 0; t < p->ntimes; t++) {
                char ts[32];
                ft_str(p->times[t], ts, sizeof ts);
                if (t) putchar(',');
                json_str(ts);
            }
            fputs("],\"file\":", stdout);
            json_str(e[i].file);
            fputs(",\"path\":", stdout);
            json_str(e[i].path);
            printf(",\"suspicious\":%s,\"reason\":", e[i].reason ? "true" : "false");
            json_str(e[i].reason ? e[i].reason : "");
            putchar('}');
        }
        first = 0;
    }
    if (mode == 1) {
        puts("]");
    }
}

int cmd_prefetch(int argc, char **argv)
{
    int mode = 0;
    const char *single = NULL;
    const char *dir = NULL;
    int files = 0, only_flagged = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--flagged") == 0) only_flagged = 1;
        else if (strcmp(argv[a], "--files") == 0) files = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else if (strcmp(argv[a], "--dir") == 0) {
            if (a + 1 >= argc) { fputs("prefetch: --dir needs a path\n", stderr); return 1; }
            dir = argv[++a];
        }
        else if (single == NULL)                 single = argv[a];
        else {
            fprintf(stderr, "prefetch: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    // One file given explicitly: parse just that.
    if (single != NULL) {
        pf_entry e;
        memset(&e, 0, sizeof e);
        snprintf(e.file, sizeof e.file, "%s", single);
        unsigned char *buf = NULL;
        size_t len = 0;
        if (load_pf(single, &e.info, 1, &buf, &len) != 0) {
            return 1;
        }
        annotate(&e, buf, len);
        if (files) {
            if (mode == 0) {
                print_entries(&e, 1, mode, 0);
            }
            print_files(&e, buf, len, mode);
        } else {
            print_entries(&e, 1, mode, 0);
        }
        free(buf);
        return 0;
    }
    if (files) {
        fputs("prefetch: --files needs a single .pf file argument\n", stderr);
        return 1;
    }

    char folder[MAX_PATH];
    if (dir != NULL) {
        snprintf(folder, sizeof folder, "%s", dir);
    } else {
        UINT wl = GetSystemWindowsDirectoryA(folder, MAX_PATH);
        if (wl == 0 || wl >= MAX_PATH - 10) {
            fputs("prefetch: cannot resolve the Windows directory\n", stderr);
            return 1;
        }
        snprintf(folder + wl, sizeof folder - wl, "\\Prefetch");
    }

    char pattern[MAX_PATH + 8];
    snprintf(pattern, sizeof pattern, "%s\\*.pf", folder);
    WIN32_FIND_DATAA fd;
    HANDLE fh = FindFirstFileA(pattern, &fd);
    if (fh == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) {
            // Folder exists but holds no .pf files (prefetch may be disabled).
            if (mode == 1)      puts("[]");
            else if (mode == 2) puts("executable,run_count,last_run,hash,version,file,path,reason");
            else                printf("prefetch: no .pf files in %s (prefetching may be disabled)\n", folder);
            return 0;
        }
        fprintf(stderr, "prefetch: cannot list %s%s\n", folder,
                err == ERROR_ACCESS_DENIED ? " (access denied - run elevated)" : "");
        return 1;
    }

    size_t cap = 256, n = 0;
    unsigned failed = 0;
    pf_entry *list = (pf_entry *)malloc(cap * sizeof *list);
    if (list == NULL) {
        FindClose(fh);
        return 1;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        if (n == cap) {
            pf_entry *grown = (pf_entry *)realloc(list, cap * 2 * sizeof *list);
            if (grown == NULL) {
                break;
            }
            list = grown;
            cap *= 2;
        }
        char path[MAX_PATH * 2];
        snprintf(path, sizeof path, "%s\\%s", folder, fd.cFileName);
        unsigned char *buf = NULL;
        size_t len = 0;
        if (load_pf(path, &list[n].info, 0, &buf, &len) == 0) {
            snprintf(list[n].file, sizeof list[n].file, "%s", fd.cFileName);
            annotate(&list[n], buf, len);
            free(buf);
            n++;
        } else {
            failed++;
        }
    } while (FindNextFileA(fh, &fd));
    FindClose(fh);

    qsort(list, n, sizeof *list, by_last_run_desc);
    if (mode == 0) {
        printf("prefetch  %s\n\n", folder);
    }
    print_entries(list, n, mode, only_flagged);
    if (mode == 0) {
        unsigned nflag = 0;
        for (size_t i = 0; i < n; i++) nflag += list[i].reason != NULL;
        printf("\n%lu file(s) parsed, %u flagged", (unsigned long)n, nflag);
        if (failed) {
            printf(", %u unreadable (access denied? run elevated)", failed);
        }
        putchar('\n');
    }
    free(list);
    return 0;
}
