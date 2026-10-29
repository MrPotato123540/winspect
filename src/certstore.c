// winspect certstore - what certificates the machine trusts
//
// Windows trusts a signature or a TLS server because its certificate chains up
// to a certificate in a system store - above all the Root store. Planting a root
// there is a powerful, quiet attack: the attacker's own signatures and sites then
// verify cleanly. So "what is in the Root store, and is any of it unexpected?" is
// a real baseline question. We open the store read-only and list each certificate
// (subject, issuer, SHA-1 thumbprint, validity), marking the self-signed roots.
// We only read; we never add, remove or trust anything.
//
// Flags (each with a reason), from well-known incidents:
//   * a certificate in Root whose PRIVATE KEY is on this machine: a root
//     generated locally - the shape of TLS-interception software (the
//     Superfish / eDellRoot cases); anyone with that key can impersonate any
//     site to this machine
//   * a certificate in Root that is not self-signed: roots sign themselves,
//     so this one does not belong there
//   * the stored SHA-1 (a cached property, or offline the registry key name)
//     differs from the SHA-1 of the certificate itself: the entry was edited
//     by hand. The thumbprint shown is always computed from the certificate.
// Self-signed is decided by comparing the encoded subject and issuer names
// (CertCompareCertificateName), not the display strings.
//
// Offline (--software / --ntuser): the registry-backed stores of a copied
// hive - SystemCertificates\<store>\Certificates\<SHA-1>\Blob, also the Group
// Policy copy under Policies\Microsoft\SystemCertificates. Each blob's
// properties are walked by certblob_prop (artparse.c, unit-tested) and only
// the DER certificate (property 32) is handed to CryptoAPI for decoding.

#include "certstore.h"
#include "artparse.h"
#include "regsrc.h"
#include "jsonutil.h"

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void filetime_str(const FILETIME *ft, char *out, size_t n)
{
    SYSTEMTIME st;
    out[0] = '\0';
    if (FileTimeToSystemTime(ft, &st)) {
        snprintf(out, n, "%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    }
}

static void hex(const BYTE *b, DWORD n, char *out, size_t on)
{
    size_t p = 0;
    out[0] = '\0';
    for (DWORD i = 0; i < n && p + 2 < on; i++) p += (size_t)snprintf(out + p, on - p, "%02x", b[i]);
}

typedef struct {
    int mode, first, is_root;
    unsigned count, flagged;
    FILETIME now;
} cctx;

// One certificate. stored: the SHA-1 the store claims for it (hex, "" if none);
// where: the registry location (offline) or "" (live).
static void one_cert(cctx *c, PCCERT_CONTEXT ctx, const char *stored, const char *where, int has_key)
{
    // Names through the W API, then UTF-8: the A variant returns the ANSI code
    // page, which broke the JSON for roots such as "TÜRKTRUST".
    char subject[512], issuer[512], thumb[48] = "", nb[16], na[16];
    WCHAR w[256];
    CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, w, 256);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, subject, sizeof subject, NULL, NULL);
    CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, w, 256);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, issuer, sizeof issuer, NULL, NULL);
    BYTE hash[20];
    DWORD hn = sizeof hash;
    if (CryptHashCertificate(0, CALG_SHA1, 0, ctx->pbCertEncoded, ctx->cbCertEncoded, hash, &hn))
        hex(hash, hn, thumb, sizeof thumb);
    filetime_str(&ctx->pCertInfo->NotBefore, nb, sizeof nb);
    filetime_str(&ctx->pCertInfo->NotAfter,  na, sizeof na);
    int self_signed = CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                 &ctx->pCertInfo->Subject,
                                                 &ctx->pCertInfo->Issuer) != 0;
    int expired = CompareFileTime(&ctx->pCertInfo->NotAfter, &c->now) < 0;
    const char *reason = NULL;
    if (stored[0] && thumb[0] && _stricmp(stored, thumb) != 0)
        reason = "stored SHA-1 does not match the certificate (entry edited by hand?)";
    else if (c->is_root && has_key)
        reason = "private key for this root is on this machine (locally generated - TLS interception?)";
    else if (c->is_root && !self_signed)
        reason = "not self-signed but stored as a trusted root";
    if (reason) c->flagged++;
    c->count++;
    if (c->mode == 0) {
        char shortsub[41];
        snprintf(shortsub, sizeof shortsub, "%s", subject);
        size_t L = strlen(shortsub);                    // do not end inside a UTF-8 sequence
        while (L > 0 && ((unsigned char)shortsub[L - 1] & 0xC0) == 0x80) L--;
        if (L > 0 && ((unsigned char)shortsub[L - 1] & 0xC0) == 0xC0) L--;
        if (strlen(subject) > sizeof shortsub - 1) shortsub[L] = '\0';
        printf("  %s%-40s %-10s %-12.12s %s%s%s%s%s\n", reason ? "[!] " : "    ",
               shortsub, na, thumb, self_signed ? "self-signed" : "",
               expired ? " expired" : "", has_key ? " private-key" : "",
               where[0] ? "  " : "", where);
        if (reason) printf("        <- %s\n", reason);
    } else if (c->mode == 2) {
        csv_str(subject); putchar(',');
        csv_str(issuer);  putchar(',');
        csv_str(nb);      putchar(',');
        csv_str(na);      putchar(',');
        csv_str(thumb);
        printf(",%d,%d,%d,", self_signed ? 1 : 0, expired ? 1 : 0, has_key ? 1 : 0);
        csv_str(reason ? reason : ""); putchar(',');
        csv_str(where); putchar('\n');
    } else {
        printf("%s{\"subject\":", c->first ? "" : ",");
        json_str(subject);
        fputs(",\"issuer\":", stdout);       json_str(issuer);
        fputs(",\"not_before\":", stdout);   json_str(nb);
        fputs(",\"not_after\":", stdout);    json_str(na);
        fputs(",\"thumbprint\":", stdout);   json_str(thumb);
        fputs(",\"stored_sha1\":", stdout);  json_str(stored);
        fputs(",\"location\":", stdout);     json_str(where);
        printf(",\"self_signed\":%s,\"expired\":%s,\"private_key\":%s,\"suspicious\":%s,\"reason\":",
               self_signed ? "true" : "false", expired ? "true" : "false",
               has_key ? "true" : "false", reason ? "true" : "false");
        json_str(reason ? reason : "");
        putchar('}');
        c->first = 0;
    }
}

typedef struct { cctx *c; regsrc *s; const char *base; } octx;

static void offline_cert(const char *keyname, void *vctx)
{
    octx *o = (octx *)vctx;
    char path[600];
    rkey k;
    snprintf(path, sizeof path, "%s\\%s", o->base, keyname);
    if (rk_open(o->s, path, &k) != 0) return;
    static unsigned char blob[256 * 1024];
    uint32_t type = 0;
    long n = rk_get(o->s, &k, "Blob", &type, blob, sizeof blob);
    rk_close(&k);
    size_t off = 0, len = 0;
    if (n <= 0 || (size_t)n > sizeof blob || !certblob_prop(blob, (size_t)n, CERTBLOB_DER, &off, &len)) return;
    PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, blob + off, (DWORD)len);
    if (ctx == NULL) return;
    one_cert(o->c, ctx, keyname, path, 0);
    CertFreeCertificateContext(ctx);
}

static int offline(cctx *c, const char *hive, int user, const char *store)
{
    static regsrc s;
    char err[256];
    if (regsrc_open_hive(&s, hive, err, sizeof err) != 0) {
        fprintf(stderr, "certstore: %s\n", err);
        return 1;
    }
    // The registry-backed physical stores of this system store.
    const char *roots[2];
    roots[0] = user ? "Software\\Microsoft\\SystemCertificates" : "Microsoft\\SystemCertificates";
    roots[1] = user ? "Software\\Policies\\Microsoft\\SystemCertificates" : "Policies\\Microsoft\\SystemCertificates";
    for (int i = 0; i < 2; i++) {
        char base[300];
        rkey k;
        snprintf(base, sizeof base, "%s\\%s\\Certificates", roots[i], store);
        if (rk_open(&s, base, &k) != 0) continue;
        octx o = { c, &s, base };
        rk_subkeys(&s, &k, offline_cert, &o);
        rk_close(&k);
    }
    regsrc_close(&s);
    return 0;
}

int cmd_certstore(int argc, char **argv)
{
    int user = 0;          // current user vs local machine
    const char *store = "ROOT", *software = NULL, *ntuser = NULL;
    cctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)       c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)   c.mode = 2;
        else if (strcmp(argv[a], "--user") == 0)  user = 1;
        else if (strcmp(argv[a], "--software") == 0 && a + 1 < argc) software = argv[++a];
        else if (strcmp(argv[a], "--ntuser") == 0 && a + 1 < argc)   ntuser = argv[++a];
        else if (strcmp(argv[a], "--store") == 0) {
            if (a + 1 >= argc) { fputs("certstore: --store needs a name\n", stderr); return 1; }
            store = argv[++a];
        }
        else {
            fprintf(stderr, "certstore: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (software && ntuser) {
        fputs("certstore: give either --software or --ntuser\n", stderr);
        return 1;
    }
    const char *hive = software ? software : ntuser;
    if (ntuser) user = 1;

    HCERTSTORE hs = NULL;
    if (hive == NULL) {
        DWORD flags = (user ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE) |
                      CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG;
        hs = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, flags, store);
        if (hs == NULL) {
            fprintf(stderr, "certstore: cannot open %s store '%s' (error %lu)\n",
                    user ? "user" : "machine", store, (unsigned long)GetLastError());
            return 1;
        }
    }

    if (c.mode == 0) {
        printf("certstore  %s\\%s%s%s\n\n", user ? "CurrentUser" : "LocalMachine", store,
               hive ? "  from " : "", hive ? hive : "");
        printf("      %-40s %-10s %-12s %s\n", "subject", "expires", "thumbprint", "flags");
    } else if (c.mode == 2) {
        puts("subject,issuer,not_before,not_after,thumbprint,self_signed,expired,private_key,reason,location");
    } else {
        putchar('[');
    }

    c.is_root = _stricmp(store, "ROOT") == 0 || _stricmp(store, "AuthRoot") == 0;
    GetSystemTimeAsFileTime(&c.now);
    int rc = 0;
    if (hive) {
        rc = offline(&c, hive, user, store);
    } else {
        PCCERT_CONTEXT ctx = NULL;
        while ((ctx = CertEnumCertificatesInStore(hs, ctx)) != NULL) {
            // The SHA-1 the store keeps for the certificate (a cached property
            // for registry stores) - compared with the computed one.
            BYTE h[20];
            DWORD hn = sizeof h;
            char stored[48] = "";
            if (CertGetCertificateContextProperty(ctx, CERT_SHA1_HASH_PROP_ID, h, &hn)) hex(h, hn, stored, sizeof stored);
            DWORD kpl = 0;
            int has_key = CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &kpl) != 0;
            one_cert(&c, ctx, stored, "", has_key);
        }
        CertCloseStore(hs, 0);
    }

    if (c.mode == 0) {
        printf("\n%u certificate(s), %u flagged\n", c.count, c.flagged);
    } else if (c.mode == 1) {
        puts("]");
    }
    return rc;
}
