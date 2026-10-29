// winspect hash - the three digests everyone asks a file for
//
// MD5, SHA1 and SHA256 are how a file is named in threat intel and sample
// databases. We compute all three with the modern CNG (BCrypt) hashing API:
// read the file, feed its bytes to each algorithm, and print the hex digest.
// Read-only; the file is never modified.

#include "hash.h"
#include "jsonutil.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

#define HASH_MAX_FILE (1024u * 1024u * 1024u)   // 1 GB ceiling

static int load_file(const char *path, unsigned char **buf, size_t *size)
{
    *buf = NULL; *size = 0;
    HANDLE f = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        return 0;
    }
    LARGE_INTEGER sz;
    int ok = 0;
    if (GetFileSizeEx(f, &sz) && sz.QuadPart >= 0 && sz.QuadPart <= (LONGLONG)HASH_MAX_FILE) {
        size_t n = (size_t)sz.QuadPart;
        unsigned char *p = (n > 0) ? (unsigned char *)malloc(n) : (unsigned char *)malloc(1);
        if (p != NULL) {
            DWORD got = 0;
            if (n == 0 || (ReadFile(f, p, (DWORD)n, &got, NULL) && got == n)) {
                *buf = p; *size = n; ok = 1;
            } else {
                free(p);
            }
        }
    }
    CloseHandle(f);
    return ok;
}

// Hashes the buffer with one CNG algorithm and hex-encodes the digest into out.
// Returns 1 on success.
static int hash_buf(const wchar_t *algo, const unsigned char *data, size_t len,
                    char *out, size_t outcap)
{
    out[0] = '\0';
    BCRYPT_ALG_HANDLE alg = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, algo, NULL, 0) != STATUS_SUCCESS) {
        return 0;
    }
    DWORD hashlen = 0, cb = 0;
    int ok = 0;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashlen, sizeof hashlen, &cb, 0) == STATUS_SUCCESS &&
        hashlen > 0 && (size_t)hashlen * 2 + 1 <= outcap) {
        BCRYPT_HASH_HANDLE hh = NULL;
        if (BCryptCreateHash(alg, &hh, NULL, 0, NULL, 0, 0) == STATUS_SUCCESS) {
            // BCryptHashData takes a DWORD length; feed large files in chunks.
            NTSTATUS st = STATUS_SUCCESS;
            size_t off = 0;
            while (off < len && st == STATUS_SUCCESS) {
                size_t chunk = len - off;
                if (chunk > (1u << 30)) { chunk = (1u << 30); }
                st = BCryptHashData(hh, (PUCHAR)(data + off), (ULONG)chunk, 0);
                off += chunk;
            }
            unsigned char dig[64];
            if (st == STATUS_SUCCESS && hashlen <= sizeof dig &&
                BCryptFinishHash(hh, dig, hashlen, 0) == STATUS_SUCCESS) {
                static const char hx[] = "0123456789abcdef";
                for (DWORD i = 0; i < hashlen; i++) {
                    out[i * 2]     = hx[dig[i] >> 4];
                    out[i * 2 + 1] = hx[dig[i] & 0xF];
                }
                out[hashlen * 2] = '\0';
                ok = 1;
            }
            BCryptDestroyHash(hh);
        }
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

int cmd_hash(int argc, char **argv)
{
    const char *path = NULL;
    int json = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) json = 1;
        else if (path == NULL)              path = argv[a];
        else {
            fprintf(stderr, "hash: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (path == NULL) {
        fputs("usage: winspect hash <path> [--json]\n", stderr);
        return 1;
    }

    unsigned char *d = NULL;
    size_t n = 0;
    if (!load_file(path, &d, &n)) {
        fprintf(stderr, "hash: cannot read '%s'\n", path);
        return 1;
    }

    char md5[33] = "", sha1[41] = "", sha256[65] = "";
    hash_buf(BCRYPT_MD5_ALGORITHM, d, n, md5, sizeof md5);
    hash_buf(BCRYPT_SHA1_ALGORITHM, d, n, sha1, sizeof sha1);
    hash_buf(BCRYPT_SHA256_ALGORITHM, d, n, sha256, sizeof sha256);
    free(d);

    if (json) {
        fputs("{\"file\":", stdout); json_str(path);
        printf(",\"size\":%zu", n);
        fputs(",\"md5\":", stdout);    json_str(md5);
        fputs(",\"sha1\":", stdout);   json_str(sha1);
        fputs(",\"sha256\":", stdout); json_str(sha256);
        puts("}");
    } else {
        printf("file    %s  (%zu bytes)\n", path, n);
        printf("  MD5     %s\n", md5[0] ? md5 : "(failed)");
        printf("  SHA1    %s\n", sha1[0] ? sha1 : "(failed)");
        printf("  SHA256  %s\n", sha256[0] ? sha256 : "(failed)");
    }
    return 0;
}
