// winspect hash - the three digests everyone asks a file for
//
// MD5, SHA1 and SHA256 are how a file is named in threat intel and sample
// databases. We compute all three with the modern CNG (BCrypt) hashing API:
// the file is streamed once through all three algorithms (no size limit, no
// whole-file buffer). A folder is hashed file by file; --match looks each
// result up in a list of known hashes (hashlist.c, portable and unit-tested).
// Read-only; the file is never modified.

#include "hash.h"
#include "hashlist.h"
#include "jsonutil.h"
#include "textfile.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

#define HASH_CHUNK (1u << 20)

// One running hash (algorithm provider + hash object).
typedef struct {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE h;
    DWORD len;
} hstate;

static int hs_begin(hstate *s, const wchar_t *algo)
{
    memset(s, 0, sizeof *s);
    DWORD cb = 0;
    if (BCryptOpenAlgorithmProvider(&s->alg, algo, NULL, 0) != STATUS_SUCCESS) return 0;
    if (BCryptGetProperty(s->alg, BCRYPT_HASH_LENGTH, (PUCHAR)&s->len, sizeof s->len, &cb, 0) != STATUS_SUCCESS ||
            s->len == 0 || s->len > 64 || BCryptCreateHash(s->alg, &s->h, NULL, 0, NULL, 0, 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(s->alg, 0);
        s->alg = NULL;
        return 0;
    }
    return 1;
}

// Finishes the hash into lowercase hex ("" on failure) and releases it.
static void hs_end(hstate *s, int ok, char *out)
{
    out[0] = '\0';
    if (s->alg == NULL) return;
    unsigned char dig[64];
    if (ok && BCryptFinishHash(s->h, dig, s->len, 0) == STATUS_SUCCESS) {
        static const char hx[] = "0123456789abcdef";
        for (DWORD i = 0; i < s->len; i++) {
            out[i * 2]     = hx[dig[i] >> 4];
            out[i * 2 + 1] = hx[dig[i] & 0xF];
        }
        out[s->len * 2] = '\0';
    }
    BCryptDestroyHash(s->h);
    BCryptCloseAlgorithmProvider(s->alg, 0);
}

typedef struct {
    char md5[33], sha1[41], sha256[65];
    uint64_t size;
} digests;

// Streams the file once through all three algorithms. 0 if it cannot be read.
static int hash_file(const char *path, unsigned char *chunk, digests *d)
{
    memset(d, 0, sizeof *d);
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    hstate h[3];
    int have[3];
    have[0] = hs_begin(&h[0], BCRYPT_MD5_ALGORITHM);
    have[1] = hs_begin(&h[1], BCRYPT_SHA1_ALGORITHM);
    have[2] = hs_begin(&h[2], BCRYPT_SHA256_ALGORITHM);
    int ok = 1;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(f, chunk, HASH_CHUNK, &got, NULL)) { ok = 0; break; }
        if (got == 0) break;
        d->size += got;
        for (int i = 0; i < 3; i++) {
            if (have[i] && BCryptHashData(h[i].h, chunk, got, 0) != STATUS_SUCCESS) ok = 0;
        }
    }
    CloseHandle(f);
    hs_end(&h[0], ok && have[0], d->md5);
    hs_end(&h[1], ok && have[1], d->sha1);
    hs_end(&h[2], ok && have[2], d->sha256);
    return ok;
}

typedef struct {
    int mode, first, recurse;
    const hashlist *list;       // NULL without --match
    unsigned files, matched, unreadable;
    unsigned char *chunk;
} hctx;

static void one(hctx *c, const char *path)
{
    digests d;
    if (!hash_file(path, c->chunk, &d)) { c->unreadable++; return; }
    c->files++;
    const hl_entry *m = NULL;
    if (c->list) {
        m = hashlist_find(c->list, d.sha256);
        if (m == NULL) m = hashlist_find(c->list, d.sha1);
        if (m == NULL) m = hashlist_find(c->list, d.md5);
        if (m == NULL) return;                       // --match reports only hits
        c->matched++;
    }
    if (c->mode == 0) {
        printf("%s %s  %s  %s  %12llu  %s\n", m ? "[!]" : "   ", d.md5, d.sha1, d.sha256, (unsigned long long)d.size, path);
        if (m) printf("        <- on the hash list%s%s\n", m->label[0] ? ": " : "", m->label);
    } else if (c->mode == 2) {
        csv_str(path);
        printf(",%llu,%s,%s,%s,", (unsigned long long)d.size, d.md5, d.sha1, d.sha256);
        csv_str(m ? (m->label[0] ? m->label : "listed") : ""); putchar('\n');
    } else {
        printf("%s{\"file\":", c->first ? "" : ",");
        json_str(path);
        printf(",\"size\":%llu,\"md5\":\"%s\",\"sha1\":\"%s\",\"sha256\":\"%s\",\"matched\":%s,\"label\":",
               (unsigned long long)d.size, d.md5, d.sha1, d.sha256, m ? "true" : "false");
        json_str(m ? m->label : "");
        putchar('}');
        c->first = 0;
    }
}

static void walk(hctx *c, const char *dir, int depth)
{
    char pat[MAX_PATH * 2];
    if (snprintf(pat, sizeof pat, "%s\\*", dir) >= (int)sizeof pat) return;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char full[MAX_PATH * 2];
        if (snprintf(full, sizeof full, "%s\\%s", dir, fd.cFileName) >= (int)sizeof full) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (c->recurse && depth < 64 && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) walk(c, full, depth + 1);
            continue;
        }
        one(c, full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int cmd_hash(int argc, char **argv)
{
    hctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *path = NULL, *match = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "-r") == 0 || strcmp(argv[a], "--recursive") == 0) c.recurse = 1;
        else if (strcmp(argv[a], "--match") == 0 && a + 1 < argc) match = argv[++a];
        else if (path == NULL && argv[a][0] != '-') path = argv[a];
        else {
            fprintf(stderr, "hash: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (path == NULL) {
        fputs("usage: winspect hash <file | folder> [-r] [--match <hash list>] [--json | --csv]\n", stderr);
        return 1;
    }
    DWORD at = GetFileAttributesA(path);
    int is_dir = at != INVALID_FILE_ATTRIBUTES && (at & FILE_ATTRIBUTE_DIRECTORY);

    hashlist list = { NULL, 0 };
    if (match != NULL) {
        char *t = read_text_file(match);
        long n = t ? hashlist_parse(t, &list) : -1;
        free(t);
        if (n <= 0) {
            fprintf(stderr, n == 0 ? "hash: '%s' holds no MD5 / SHA-1 / SHA-256 hashes\n" : "hash: cannot read the hash list '%s'\n", match);
            return 1;
        }
        c.list = &list;
    }
    c.chunk = (unsigned char *)malloc(HASH_CHUNK);
    if (c.chunk == NULL) { fputs("hash: out of memory\n", stderr); hashlist_free(&list); return 1; }

    // One plain file without --match / --csv keeps its original report shape.
    if (!is_dir && match == NULL && c.mode != 2) {
        digests d;
        if (!hash_file(path, c.chunk, &d)) {
            fprintf(stderr, "hash: cannot read '%s'\n", path);
            free(c.chunk);
            return 1;
        }
        if (c.mode == 1) {
            fputs("{\"file\":", stdout); json_str(path);
            printf(",\"size\":%llu", (unsigned long long)d.size);
            fputs(",\"md5\":", stdout);    json_str(d.md5);
            fputs(",\"sha1\":", stdout);   json_str(d.sha1);
            fputs(",\"sha256\":", stdout); json_str(d.sha256);
            puts("}");
        } else {
            printf("file    %s  (%llu bytes)\n", path, (unsigned long long)d.size);
            printf("  MD5     %s\n", d.md5[0] ? d.md5 : "(failed)");
            printf("  SHA1    %s\n", d.sha1[0] ? d.sha1 : "(failed)");
            printf("  SHA256  %s\n", d.sha256[0] ? d.sha256 : "(failed)");
        }
        free(c.chunk);
        return 0;
    }

    if (at == INVALID_FILE_ATTRIBUTES) {
        if (c.mode == 1) puts("[]");
        fprintf(stderr, "hash: cannot find '%s'\n", path);
        free(c.chunk);
        hashlist_free(&list);
        return 1;
    }
    if (c.mode == 0) printf("    %-32s  %-40s  %-64s  %12s  %s\n", "md5", "sha1", "sha256", "size", "path");
    else if (c.mode == 2) puts("path,size,md5,sha1,sha256,match");
    else putchar('[');
    if (is_dir) {
        char dir[MAX_PATH * 2];
        snprintf(dir, sizeof dir, "%s", path);
        size_t L = strlen(dir);
        while (L > 3 && (dir[L - 1] == '\\' || dir[L - 1] == '/')) dir[--L] = '\0';
        walk(&c, dir, 0);
    } else {
        one(&c, path);
        if (c.files == 0 && c.unreadable) fprintf(stderr, "hash: cannot read '%s'\n", path);
    }
    if (c.mode == 1) puts("]");
    else if (c.mode == 0) {
        printf("\n%u file(s) hashed", c.files);
        if (c.list) printf(", %u on the list (%lu hash(es) loaded)", c.matched, (unsigned long)list.n);
        if (c.unreadable) printf(", %u could not be read", c.unreadable);
        putchar('\n');
    }
    free(c.chunk);
    hashlist_free(&list);
    return (!is_dir && c.files == 0) ? 1 : 0;
}
