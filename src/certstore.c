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
// Self-signed is decided by comparing the encoded subject and issuer names
// (CertCompareCertificateName), not the display strings.

#include "certstore.h"
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

int cmd_certstore(int argc, char **argv)
{
    int mode = 0;          // 0 text, 1 json, 2 csv
    int user = 0;          // current user vs local machine
    const char *store = "ROOT";
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)       mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)   mode = 2;
        else if (strcmp(argv[a], "--user") == 0)  user = 1;
        else if (strcmp(argv[a], "--store") == 0) {
            if (a + 1 >= argc) { fputs("certstore: --store needs a name\n", stderr); return 1; }
            store = argv[++a];
        }
        else {
            fprintf(stderr, "certstore: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    DWORD flags = (user ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE) |
                  CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG;
    HCERTSTORE hs = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, flags, store);
    if (hs == NULL) {
        fprintf(stderr, "certstore: cannot open %s store '%s' (error %lu)\n",
                user ? "user" : "machine", store, (unsigned long)GetLastError());
        return 1;
    }

    if (mode == 0) {
        printf("certstore  %s\\%s\n\n", user ? "CurrentUser" : "LocalMachine", store);
        printf("      %-40s %-10s %-12s %s\n", "subject", "expires", "thumbprint", "flags");
    } else if (mode == 2) {
        puts("subject,issuer,not_before,not_after,thumbprint,self_signed,expired,private_key,reason");
    } else {
        putchar('[');
    }

    unsigned count = 0, flagged = 0;
    int first = 1;
    int is_root = _stricmp(store, "ROOT") == 0 || _stricmp(store, "AuthRoot") == 0;
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    PCCERT_CONTEXT ctx = NULL;
    while ((ctx = CertEnumCertificatesInStore(hs, ctx)) != NULL) {
        char subject[256], issuer[256], thumb[48] = "", nb[16], na[16];
        CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, sizeof subject);
        CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL,
                           issuer, sizeof issuer);
        BYTE hash[20];
        DWORD hn = sizeof hash;
        if (CertGetCertificateContextProperty(ctx, CERT_SHA1_HASH_PROP_ID, hash, &hn)) {
            size_t p = 0;
            for (DWORD i = 0; i < hn && p + 2 < sizeof thumb; i++) {
                p += (size_t)snprintf(thumb + p, sizeof thumb - p, "%02x", hash[i]);
            }
        }
        filetime_str(&ctx->pCertInfo->NotBefore, nb, sizeof nb);
        filetime_str(&ctx->pCertInfo->NotAfter,  na, sizeof na);
        int self_signed = CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                     &ctx->pCertInfo->Subject,
                                                     &ctx->pCertInfo->Issuer) != 0;
        int expired = CompareFileTime(&ctx->pCertInfo->NotAfter, &now) < 0;
        DWORD kpl = 0;
        int has_key = CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &kpl) != 0;
        const char *reason = NULL;
        if (is_root && has_key)
            reason = "private key for this root is on this machine (locally generated - TLS interception?)";
        else if (is_root && !self_signed)
            reason = "not self-signed but stored as a trusted root";
        if (reason) flagged++;

        count++;
        if (mode == 0) {
            char shortsub[41];
            snprintf(shortsub, sizeof shortsub, "%s", subject);
            printf("  %s%-40s %-10s %-12.12s %s%s%s\n", reason ? "[!] " : "    ",
                   shortsub, na, thumb, self_signed ? "self-signed" : "",
                   expired ? " expired" : "", has_key ? " private-key" : "");
            if (reason) {
                printf("        <- %s\n", reason);
            }
        } else if (mode == 2) {
            csv_str(subject); putchar(',');
            csv_str(issuer);  putchar(',');
            csv_str(nb);      putchar(',');
            csv_str(na);      putchar(',');
            csv_str(thumb);
            printf(",%d,%d,%d,", self_signed ? 1 : 0, expired ? 1 : 0, has_key ? 1 : 0);
            csv_str(reason ? reason : ""); putchar('\n');
        } else {
            printf("%s{\"subject\":", first ? "" : ",");
            json_str(subject);
            fputs(",\"issuer\":", stdout);       json_str(issuer);
            fputs(",\"not_before\":", stdout);   json_str(nb);
            fputs(",\"not_after\":", stdout);    json_str(na);
            fputs(",\"thumbprint\":", stdout);   json_str(thumb);
            printf(",\"self_signed\":%s,\"expired\":%s,\"private_key\":%s,\"suspicious\":%s,\"reason\":",
                   self_signed ? "true" : "false", expired ? "true" : "false",
                   has_key ? "true" : "false", reason ? "true" : "false");
            json_str(reason ? reason : "");
            putchar('}');
            first = 0;
        }
    }
    CertCloseStore(hs, 0);

    if (mode == 0) {
        printf("\n%u certificate(s), %u flagged\n", count, flagged);
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
