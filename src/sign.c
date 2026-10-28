// winspect sign - Authenticode signature check
//
// Two different questions, often confused:
//   "Is it signed?"   -> there are signature bytes in the file.
//   "Is it trusted?"  -> that signature is cryptographically valid AND its
//                        certificate chains up to a root this machine trusts.
// A file can be signed but not trusted (self-signed, expired, revoked, tampered
// after signing). So we ask WinVerifyTrust for the trust verdict, and separately
// read the signer's name out of the embedded certificate.
//
// APIs used:
//   WinVerifyTrust (wintrust)  - the trust verdict
//   CryptQueryObject / CryptMsgGetParam / CertGetNameString (crypt32) - signer

#include "sign.h"
#include "ioc.h"
#include "artparse.h"
#include "jsonutil.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>    // WINTRUST_ACTION_GENERIC_VERIFY_V2
#include <wincrypt.h>
#include <mscat.h>      // CryptCATAdmin* (catalog-signed files)
#include <stdio.h>
#include <stdlib.h>     // malloc, free  (without this MSVC assumes malloc returns
                        // int and truncates the pointer to 32 bits -> crash on x64)
#include <string.h>     // strcmp

// Converts the (ANSI) path argument to the wide string the crypto APIs want.
// Returns 1 on success.
static int to_wide(const char *path, WCHAR *wbuf, int wcap)
{
    return MultiByteToWideChar(CP_ACP, 0, path, -1, wbuf, wcap) != 0;
}

// Turns WinVerifyTrust's LONG result into a short human verdict.
static const char *trust_verdict(LONG st)
{
    switch ((DWORD)st) {
    case ERROR_SUCCESS:              return "TRUSTED (valid signature, trusted chain)";
    case TRUST_E_NOSIGNATURE:        return "NOT SIGNED (or signature unreadable)";
    case TRUST_E_EXPLICIT_DISTRUST:  return "DISTRUSTED (explicitly blocked)";
    case TRUST_E_SUBJECT_NOT_TRUSTED:return "SIGNED but NOT trusted";
    case CERT_E_UNTRUSTEDROOT:       return "SIGNED but root is not trusted";
    case CERT_E_EXPIRED:             return "SIGNED but certificate expired";
    case TRUST_E_BAD_DIGEST:         return "TAMPERED (digest mismatch - file changed after signing)";
    case CRYPT_E_SECURITY_SETTINGS:  return "signature present but blocked by policy";
    default:                         return "untrusted / error";
    }
}

// Best-effort extraction of the signer's display name from the embedded PKCS#7
// signature. Writes "" on failure (not every file is signed). The flow:
//   CryptQueryObject -> opens the file's embedded signature as a cert store + msg
//   CryptMsgGetParam(CMSG_SIGNER_CERT_INFO_PARAM) -> which cert signed it
//   CertFindCertificateInStore -> that cert in the store
//   CertGetNameString -> its subject display name
static void signer_name(const WCHAR *wpath, char *out, size_t outsz)
{
    out[0] = '\0';

    HCERTSTORE store = NULL;
    HCRYPTMSG  msg = NULL;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          NULL, NULL, NULL, &store, &msg, NULL)) {
        return;   // no embedded signature
    }

    // How big is the signer CERT_INFO? Ask, allocate, fetch.
    DWORD len = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &len) && len > 0) {
        CERT_INFO *ci = (CERT_INFO *)malloc(len);
        if (ci != NULL &&
            CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, ci, &len)) {
            // Find that exact certificate in the store opened above.
            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, ci, NULL);
            if (cert != NULL) {
                CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                                   out, (DWORD)outsz);
                CertFreeCertificateContext(cert);
            }
        }
        free(ci);
    }

    if (msg != NULL)   CryptMsgClose(msg);
    if (store != NULL) CertCloseStore(store, 0);
}

// Many Windows binaries carry no embedded signature; their Authenticode hash is
// instead listed in a system security catalog (a signed .cat file). This is why
// a bare WinVerifyTrust on, say, kernel32.dll comes back "not signed" even though
// the file is perfectly trusted. The catalog path is:
//   1. CryptCATAdminCalcHashFromFileHandle - the file's Authenticode hash
//   2. CryptCATAdminEnumCatalogFromHash     - which catalog, if any, lists it
//   3. WinVerifyTrust with WINTRUST_CATALOG_INFO - verify via that catalog
//
// On success *found is set, the catalog file path is written (UTF-8), and the
// trust LONG is returned. On any failure the result is TRUST_E_NOSIGNATURE so the
// caller treats it exactly like "no embedded signature either".
static LONG verify_via_catalog(const WCHAR *wpath, char *catpath, size_t catsz, int *found)
{
    *found = 0;
    if (catsz > 0) {
        catpath[0] = '\0';
    }

    HANDLE hFile = CreateFileW(wpath, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return TRUST_E_NOSIGNATURE;
    }

    HCATADMIN hAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hAdmin, NULL, 0)) {
        CloseHandle(hFile);
        return TRUST_E_NOSIGNATURE;
    }

    // Two-step hash: probe the length, allocate, compute.
    DWORD hashLen = 0;
    CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, NULL, 0);
    LONG st = TRUST_E_NOSIGNATURE;
    BYTE *hash = (hashLen > 0) ? (BYTE *)malloc(hashLen) : NULL;
    if (hash != NULL &&
        CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash, 0)) {

        HCATINFO hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash, hashLen, 0, NULL);
        if (hCat != NULL) {
            *found = 1;

            CATALOG_INFO ci;
            ZeroMemory(&ci, sizeof ci);
            ci.cbStruct = sizeof ci;
            if (CryptCATCatalogInfoFromContext(hCat, &ci, 0) && catsz > 0) {
                WideCharToMultiByte(CP_UTF8, 0, ci.wszCatalogFile, -1,
                                    catpath, (int)catsz, NULL, NULL);
            }

            // The member tag WinVerifyTrust matches against the catalog is the
            // file hash rendered as an uppercase hex string.
            WCHAR tag[2 * 64 + 1];     // room for up to a 64-byte hash
            DWORD tagn = (hashLen > 64) ? 64 : hashLen;
            for (DWORD i = 0; i < tagn; i++) {
                static const WCHAR hexd[] = L"0123456789ABCDEF";
                tag[i * 2]     = hexd[(hash[i] >> 4) & 0xF];
                tag[i * 2 + 1] = hexd[hash[i] & 0xF];
            }
            tag[tagn * 2] = L'\0';

            WINTRUST_CATALOG_INFO wci;
            ZeroMemory(&wci, sizeof wci);
            wci.cbStruct               = sizeof wci;
            wci.pcwszCatalogFilePath   = ci.wszCatalogFile;
            wci.pcwszMemberFilePath    = wpath;
            wci.pcwszMemberTag         = tag;
            wci.hMemberFile            = hFile;
            wci.pbCalculatedFileHash   = hash;
            wci.cbCalculatedFileHash   = hashLen;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA wd;
            ZeroMemory(&wd, sizeof wd);
            wd.cbStruct            = sizeof wd;
            wd.dwUIChoice          = WTD_UI_NONE;
            wd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wd.dwUnionChoice       = WTD_CHOICE_CATALOG;
            wd.pCatalog            = &wci;
            wd.dwStateAction       = WTD_STATEACTION_VERIFY;

            st = WinVerifyTrust(NULL, &action, &wd);

            wd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &action, &wd);

            CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
        }
    }

    free(hash);
    CryptCATAdminReleaseContext(hAdmin, 0);
    CloseHandle(hFile);
    return st;
}

// ---- Rich signature detail extraction (signify-style, via crypt32) ----------
// Beyond the trust verdict and signer name, a thorough view answers: which hash
// algorithm signed it (SHA1 is an age/trust signal), WHEN it was signed (a
// countersignature keeps a signature valid past cert expiry), the full issuer
// chain, whether that chain roots in a Microsoft root (i.e. an OS component),
// and the file's Authenticode hash. All of this is read-only extraction from the
// PKCS#7 blob + the chain engine; it does not redo the trust decision.

#ifndef szOID_RSA_counterSign
#define szOID_RSA_counterSign "1.2.840.113549.1.9.6"
#endif
#ifndef szOID_RSA_signingTime
#define szOID_RSA_signingTime "1.2.840.113549.1.9.5"
#endif
#ifndef SPC_SP_OPUS_INFO_OBJID
#define SPC_SP_OPUS_INFO_OBJID "1.3.6.1.4.1.311.2.1.12"
#endif
#ifndef szOID_NESTED_SIGNATURE
#define szOID_NESTED_SIGNATURE "1.3.6.1.4.1.311.2.4.1"
#endif
#ifndef BCRYPT_SHA256_ALGORITHM
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#endif

struct cert_row {
    char subject[256];
    char issuer[256];
    char serial[80];
    char not_before[40];
    char not_after[40];
    char thumb[48];      // SHA1 thumbprint, hex
};

struct sig_details {
    int  have;
    char digest_algo[24];
    int  signed_at_present;
    char signed_at[40];
    char authentihash[65];   // SHA256 hex (Authenticode hash), or ""
    const char *authentihash_algo;
    int  nsignatures;
    int  ms_root, ms_root_known;
    char program_name[256];
    struct cert_row chain[16];
    int  nchain;
};

static void filetime_to_str(const FILETIME *ft, char *out, size_t n)
{
    SYSTEMTIME st;
    out[0] = '\0';
    if (FileTimeToSystemTime(ft, &st)) {
        snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02uZ",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }
}

// OID of a hash algorithm -> friendly short name.
static const char *hash_oid_name(const char *oid)
{
    if (oid == NULL)                            return "unknown";
    if (strcmp(oid, szOID_OIWSEC_sha1) == 0)    return "SHA1";
    if (strcmp(oid, szOID_NIST_sha256) == 0)    return "SHA256";
    if (strcmp(oid, szOID_NIST_sha384) == 0)    return "SHA384";
    if (strcmp(oid, szOID_NIST_sha512) == 0)    return "SHA512";
    if (strcmp(oid, szOID_RSA_MD5) == 0)        return "MD5";
    return oid;
}

static void wide_to_utf8(const WCHAR *w, char *out, size_t n)
{
    out[0] = '\0';
    if (w != NULL) {
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)n, NULL, NULL);
    }
}

// Fills one chain row from a certificate context.
static void fill_cert_row(PCCERT_CONTEXT c, struct cert_row *r)
{
    WCHAR tmp[256];
    CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, tmp, 256);
    wide_to_utf8(tmp, r->subject, sizeof r->subject);
    CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, tmp, 256);
    wide_to_utf8(tmp, r->issuer, sizeof r->issuer);

    // Serial number is stored little-endian; print most-significant first.
    DWORD sn = c->pCertInfo->SerialNumber.cbData;
    size_t pos = 0;
    r->serial[0] = '\0';
    for (DWORD i = 0; i < sn && pos + 2 < sizeof r->serial; i++) {
        unsigned char b = c->pCertInfo->SerialNumber.pbData[sn - 1 - i];
        pos += (size_t)snprintf(r->serial + pos, sizeof r->serial - pos, "%02x", b);
    }

    filetime_to_str(&c->pCertInfo->NotBefore, r->not_before, sizeof r->not_before);
    filetime_to_str(&c->pCertInfo->NotAfter,  r->not_after,  sizeof r->not_after);

    BYTE hash[20];
    DWORD hlen = sizeof hash;
    r->thumb[0] = '\0';
    if (CertGetCertificateContextProperty(c, CERT_SHA1_HASH_PROP_ID, hash, &hlen)) {
        size_t p = 0;
        for (DWORD i = 0; i < hlen && p + 2 < sizeof r->thumb; i++) {
            p += (size_t)snprintf(r->thumb + p, sizeof r->thumb - p, "%02x", hash[i]);
        }
    }
}

// Pulls the legacy PKCS#9 counter-signature time (szOID_RSA_signingTime) out of
// the signer's unauthenticated attributes. Best-effort: leaves signed_at empty
// if the signature uses only an RFC3161 token we don't decode.
static void extract_signing_time(const CMSG_SIGNER_INFO *si, struct sig_details *d)
{
    for (DWORD i = 0; i < si->UnauthAttrs.cAttr; i++) {
        CRYPT_ATTRIBUTE *a = &si->UnauthAttrs.rgAttr[i];
        if (a->pszObjId == NULL || strcmp(a->pszObjId, szOID_RSA_counterSign) != 0 ||
            a->cValue == 0) {
            continue;
        }
        // The countersignature is itself a signer-info; decode it, then look for
        // szOID_RSA_signingTime in its authenticated attributes.
        DWORD len = 0;
        if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS7_SIGNER_INFO,
                               a->rgValue[0].pbData, a->rgValue[0].cbData, 0, NULL, &len) ||
            len == 0) {
            continue;
        }
        CMSG_SIGNER_INFO *cs = (CMSG_SIGNER_INFO *)malloc(len);
        if (cs == NULL) {
            continue;
        }
        if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS7_SIGNER_INFO,
                              a->rgValue[0].pbData, a->rgValue[0].cbData, 0, cs, &len)) {
            for (DWORD j = 0; j < cs->AuthAttrs.cAttr; j++) {
                CRYPT_ATTRIBUTE *ta = &cs->AuthAttrs.rgAttr[j];
                if (ta->pszObjId != NULL && strcmp(ta->pszObjId, szOID_RSA_signingTime) == 0 &&
                    ta->cValue > 0) {
                    FILETIME ft;
                    DWORD flen = sizeof ft;
                    if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                          szOID_RSA_signingTime,
                                          ta->rgValue[0].pbData, ta->rgValue[0].cbData,
                                          0, &ft, &flen)) {
                        filetime_to_str(&ft, d->signed_at, sizeof d->signed_at);
                        d->signed_at_present = d->signed_at[0] != '\0';
                    }
                    break;
                }
            }
        }
        free(cs);
        if (d->signed_at_present) {
            break;
        }
    }
}

// Extracts signer info, program name, signing time and the full certificate
// chain from an embedded PKCS#7 signature in the file at wpath.
static void sig_extract(const WCHAR *wpath, struct sig_details *d)
{
    memset(d, 0, sizeof *d);
    d->authentihash_algo = "";

    HCERTSTORE store = NULL;
    HCRYPTMSG  msg = NULL;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          NULL, NULL, NULL, &store, &msg, NULL)) {
        return;   // no embedded signature (maybe catalog-signed; caller decides)
    }

    DWORD si_len = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &si_len) && si_len > 0) {
        CMSG_SIGNER_INFO *si = (CMSG_SIGNER_INFO *)malloc(si_len);
        if (si != NULL && CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, si, &si_len)) {
            d->have = 1;
            snprintf(d->digest_algo, sizeof d->digest_algo, "%s",
                     hash_oid_name(si->HashAlgorithm.pszObjId));

            // Program name from SpcSpOpusInfo (authenticated attribute).
            for (DWORD i = 0; i < si->AuthAttrs.cAttr; i++) {
                CRYPT_ATTRIBUTE *a = &si->AuthAttrs.rgAttr[i];
                if (a->pszObjId != NULL && strcmp(a->pszObjId, SPC_SP_OPUS_INFO_OBJID) == 0 &&
                    a->cValue > 0) {
                    DWORD olen = 0;
                    if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                          SPC_SP_OPUS_INFO_OBJID,
                                          a->rgValue[0].pbData, a->rgValue[0].cbData,
                                          0, NULL, &olen) && olen > 0) {
                        SPC_SP_OPUS_INFO *opus = (SPC_SP_OPUS_INFO *)malloc(olen);
                        if (opus != NULL &&
                            CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              SPC_SP_OPUS_INFO_OBJID,
                                              a->rgValue[0].pbData, a->rgValue[0].cbData,
                                              0, opus, &olen)) {
                            wide_to_utf8(opus->pwszProgramName, d->program_name,
                                         sizeof d->program_name);
                        }
                        free(opus);
                    }
                    break;
                }
            }

            extract_signing_time(si, d);

            // Count signatures: primary + any nested (dual-signing).
            d->nsignatures = 1;
            for (DWORD i = 0; i < si->UnauthAttrs.cAttr; i++) {
                if (si->UnauthAttrs.rgAttr[i].pszObjId != NULL &&
                    strcmp(si->UnauthAttrs.rgAttr[i].pszObjId, szOID_NESTED_SIGNATURE) == 0) {
                    d->nsignatures += (int)si->UnauthAttrs.rgAttr[i].cValue;
                }
            }

            // Certificate chain: locate the signer cert in the message store, then
            // let the chain engine resolve intermediates up to the root.
            CERT_INFO find;
            memset(&find, 0, sizeof find);
            find.Issuer = si->Issuer;
            find.SerialNumber = si->SerialNumber;
            PCCERT_CONTEXT signer = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, &find, NULL);
            if (signer != NULL) {
                CERT_CHAIN_PARA cp;
                memset(&cp, 0, sizeof cp);
                cp.cbSize = sizeof cp;
                PCCERT_CHAIN_CONTEXT chain = NULL;
                if (CertGetCertificateChain(NULL, signer, NULL, store, &cp, 0, NULL, &chain) &&
                    chain != NULL && chain->cChain > 0) {
                    PCERT_SIMPLE_CHAIN sc = chain->rgpChain[0];
                    for (DWORD i = 0; i < sc->cElement && d->nchain < 16; i++) {
                        fill_cert_row(sc->rgpElement[i]->pCertContext, &d->chain[d->nchain]);
                        d->nchain++;
                    }
                    // Does the chain terminate in a Microsoft root?
                    CERT_CHAIN_POLICY_PARA pp;
                    CERT_CHAIN_POLICY_STATUS ps;
                    memset(&pp, 0, sizeof pp); pp.cbSize = sizeof pp;
                    memset(&ps, 0, sizeof ps); ps.cbSize = sizeof ps;
                    if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT,
                                                         chain, &pp, &ps)) {
                        d->ms_root_known = 1;
                        d->ms_root = (ps.dwError == 0);
                    }
                    CertFreeCertificateChain(chain);
                }
                CertFreeCertificateContext(signer);
            }
        }
        free(si);
    }

    if (msg != NULL)   { CryptMsgClose(msg); }
    if (store != NULL) { CertCloseStore(store, 0); }
}

// Computes the file's Authenticode hash (SHA256 where available, else SHA1),
// which omits the checksum and certificate table. Uses the catalog-admin helper
// so we do not reimplement the PE omit-range logic.
static void compute_authentihash(const WCHAR *wpath, struct sig_details *d)
{
    HANDLE hFile = CreateFileW(wpath, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }
    BYTE hash[64];
    DWORD hlen = sizeof hash;
    int got = 0;
    const char *algo = "";

    HCATADMIN admin = NULL;

    // The SHA256 path uses the Win8+ "2" APIs. We resolve them dynamically from
    // wintrust.dll so the binary still links on toolchains whose import library
    // predates them (e.g. some MinGW builds); if they are missing at runtime we
    // fall back to the SHA1 authenticode hash.
    typedef BOOL (WINAPI *acquire2_t)(HCATADMIN *, const GUID *, PCWSTR,
                                      PCCERT_STRONG_SIGN_PARA, DWORD);
    typedef BOOL (WINAPI *calc2_t)(HCATADMIN, HANDLE, DWORD *, BYTE *, DWORD);
    HMODULE wt = GetModuleHandleA("wintrust.dll");
    if (wt == NULL) { wt = LoadLibraryA("wintrust.dll"); }
    acquire2_t acquire2 = NULL;
    calc2_t    calc2    = NULL;
    if (wt != NULL) {
        acquire2 = (acquire2_t)(void (*)(void))GetProcAddress(wt, "CryptCATAdminAcquireContext2");
        calc2    = (calc2_t)(void (*)(void))GetProcAddress(wt, "CryptCATAdminCalcHashFromFileHandle2");
    }
    if (acquire2 != NULL && calc2 != NULL &&
        acquire2(&admin, NULL, BCRYPT_SHA256_ALGORITHM, NULL, 0)) {
        if (calc2(admin, hFile, &hlen, hash, 0)) {
            got = 1; algo = "SHA256";
        }
        CryptCATAdminReleaseContext(admin, 0);
    }
    if (!got) {
        // Fall back to the SHA1 authenticode hash via the v1 API.
        hlen = sizeof hash;
        if (CryptCATAdminAcquireContext(&admin, NULL, 0)) {
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hlen, hash, 0)) {
                got = 1; algo = "SHA1";
            }
            CryptCATAdminReleaseContext(admin, 0);
        }
    }
    if (got) {
        size_t p = 0;
        for (DWORD i = 0; i < hlen && p + 2 < sizeof d->authentihash; i++) {
            p += (size_t)snprintf(d->authentihash + p, sizeof d->authentihash - p,
                                  "%02x", hash[i]);
        }
        d->authentihash_algo = algo;
    }
    CloseHandle(hFile);
}

// ---- Directory scan (sigcheck -u -e -s) --------------------------------------
// "Which executables under this folder are not trusted?" is the single most
// useful bulk query sigcheck answers. We recurse a directory, treat anything
// that starts with an MZ as an executable (header, not extension, like -e), and
// report its trust. By default only the untrusted/unsigned ones are listed; an
// --all flag lists every executable with its verdict.

// Compact trust check used by the scan and by "modules --sig" (no chain/detail
// extraction needed). Exported through sign.h.
int sign_file_trust(const wchar_t *wpath, const char **source)
{
    *source = "none";
    WINTRUST_FILE_INFO fi;
    ZeroMemory(&fi, sizeof fi);
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = wpath;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd;
    ZeroMemory(&wd, sizeof wd);
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    LONG st = WinVerifyTrust(NULL, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wd);
    if (st == ERROR_SUCCESS) {
        *source = "embedded";
        return 1;
    }
    if (st == (LONG)TRUST_E_NOSIGNATURE) {
        char cat[1024];
        int found = 0;
        LONG cst = verify_via_catalog(wpath, cat, sizeof cat, &found);
        if (found && cst == ERROR_SUCCESS) {
            *source = "catalog";
            return 1;
        }
    }
    return 0;
}

// True if the file begins with an "MZ" (so it is worth a signature check).
static int looks_like_pe(const char *path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    unsigned char mz[2] = { 0, 0 };
    DWORD got = 0;
    int ok = ReadFile(h, mz, 2, &got, NULL) && got == 2 && mz[0] == 'M' && mz[1] == 'Z';
    CloseHandle(h);
    return ok;
}

struct scanctx { int mode; int all; int first; unsigned total; unsigned flagged; };
#define SIGN_TEXT 0
#define SIGN_JSON 1
#define SIGN_CSV  2

static void scan_emit(struct scanctx *c, const char *path, int trusted, const char *source)
{
    c->total++;
    if (!trusted) {
        c->flagged++;
    }
    if (trusted && !c->all) {
        return;   // default view: only the files worth a second look
    }
    if (c->mode == SIGN_TEXT) {
        printf("  %-10s %-9s %s\n", trusted ? "trusted" : "UNTRUSTED", source, path);
    } else if (c->mode == SIGN_CSV) {
        csv_str(path);
        printf(",%d,", trusted ? 1 : 0);
        csv_str(source);
        putchar('\n');
    } else {
        printf("%s{\"path\":", c->first ? "" : ",");
        json_str(path);
        printf(",\"trusted\":%s,\"source\":", trusted ? "true" : "false");
        json_str(source);
        putchar('}');
        c->first = 0;
    }
}

static void scan_dir(const char *dir, struct scanctx *c)
{
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof pattern, "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
            continue;
        }
        char full[MAX_PATH];
        snprintf(full, sizeof full, "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_dir(full, c);                 // recurse, like sigcheck -s
        } else if (looks_like_pe(full)) {
            WCHAR w[1024];
            if (to_wide(full, w, (int)(sizeof w / sizeof w[0]))) {
                const char *src = "none";
                int tr = sign_file_trust(w, &src);
                scan_emit(c, full, tr, src);
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static int cmd_sign_scan(const char *dir, int mode, int all)
{
    struct scanctx c;
    c.mode = mode;
    c.all = all;
    c.first = 1;
    c.total = 0;
    c.flagged = 0;

    if (mode == SIGN_TEXT) {
        printf("scan  %s%s\n\n", dir, all ? "" : "  (showing untrusted only; --all for every file)");
        printf("  %-10s %-9s %s\n", "trust", "source", "path");
    } else if (mode == SIGN_CSV) {
        puts("path,trusted,source");
    } else {
        putchar('[');
    }

    scan_dir(dir, &c);

    if (mode == SIGN_TEXT) {
        printf("\n%u executable(s) scanned, %u untrusted\n", c.total, c.flagged);
    } else if (mode == SIGN_JSON) {
        puts("]");
    }
    // Non-zero exit when anything untrusted was found, so CI/scripts can gate.
    return c.flagged > 0 ? 1 : 0;
}

int cmd_sign(int argc, char **argv)
{
    // Args: <path> [--json], or --scan <dir> [--all] [--json|--csv].
    const char *path = NULL;
    int json = 0;
    int scan = 0, all = 0, csv = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) {
            json = 1;
        } else if (strcmp(argv[a], "--csv") == 0) {
            csv = 1;
        } else if (strcmp(argv[a], "--scan") == 0) {
            scan = 1;
        } else if (strcmp(argv[a], "--all") == 0) {
            all = 1;
        } else if (path == NULL) {
            path = argv[a];
        } else {
            fprintf(stderr, "sign: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (path == NULL) {
        fputs("usage: winspect sign <path> [--json]\n"
              "       winspect sign --scan <dir> [--all] [--json | --csv]\n", stderr);
        return 1;
    }

    if (scan) {
        int mode = csv ? SIGN_CSV : (json ? SIGN_JSON : SIGN_TEXT);
        return cmd_sign_scan(path, mode, all);
    }

    WCHAR wpath[1024];
    if (!to_wide(path, wpath, (int)(sizeof wpath / sizeof wpath[0]))) {
        fprintf(stderr, "sign: cannot convert path '%s'\n", path);
        return 1;
    }

    // --- Trust verdict via WinVerifyTrust ---
    WINTRUST_FILE_INFO fi;
    ZeroMemory(&fi, sizeof fi);
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = wpath;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd;
    ZeroMemory(&wd, sizeof wd);
    wd.cbStruct       = sizeof wd;
    wd.dwUIChoice     = WTD_UI_NONE;          // never pop a dialog
    wd.fdwRevocationChecks = WTD_REVOKE_NONE; // don't go online for CRLs here
    wd.dwUnionChoice  = WTD_CHOICE_FILE;
    wd.pFile          = &fi;
    wd.dwStateAction  = WTD_STATEACTION_VERIFY;

    LONG st = WinVerifyTrust(NULL, &action, &wd);

    // Always release the state the VERIFY action allocated.
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wd);

    // --- Signer name (independent of trust) ---
    char signer[512];
    signer_name(wpath, signer, sizeof signer);

    // Where the signature came from: an embedded Authenticode blob, a system
    // catalog, or nowhere. Start by assuming embedded (that is what the check
    // above looked at).
    const char *source = (st == ERROR_SUCCESS) ? "embedded" : "none";
    char catalog[1024] = "";

    // If there was no embedded signature, the file may still be catalog-signed
    // (the common case for shipped Windows binaries). Fall back to that.
    if (st == (LONG)TRUST_E_NOSIGNATURE) {
        int found = 0;
        LONG cst = verify_via_catalog(wpath, catalog, sizeof catalog, &found);
        if (found) {
            st = cst;
            source = "catalog";
            // The signer of a catalog-signed file is the catalog's signer, so
            // read the name from the .cat when we didn't get one from the file.
            if (signer[0] == '\0' && catalog[0] != '\0') {
                WCHAR wcat[1024];
                if (to_wide(catalog, wcat, (int)(sizeof wcat / sizeof wcat[0]))) {
                    signer_name(wcat, signer, sizeof signer);
                }
            }
        }
    }

    // --- Rich details: digest algo, timestamp, chain, MS-root, program name.
    // The PKCS#7 lives in the file itself for an embedded signature, or in the
    // .cat for a catalog-signed file; the file's own Authenticode hash we always
    // compute from the file.
    struct sig_details det;
    memset(&det, 0, sizeof det);
    det.authentihash_algo = "";
    if (strcmp(source, "embedded") == 0) {
        sig_extract(wpath, &det);
    } else if (strcmp(source, "catalog") == 0 && catalog[0] != '\0') {
        WCHAR wcat[1024];
        if (to_wide(catalog, wcat, (int)(sizeof wcat / sizeof wcat[0]))) {
            sig_extract(wcat, &det);
        }
    }
    compute_authentihash(wpath, &det);

    if (json) {
        fputs("{\"file\":", stdout);          json_str(path);
        printf(",\"trusted\":%s", st == ERROR_SUCCESS ? "true" : "false");
        printf(",\"status\":\"0x%08lX\"", (unsigned long)st);
        fputs(",\"verdict\":", stdout);        json_str(trust_verdict(st));
        fputs(",\"source\":", stdout);         json_str(source);
        fputs(",\"catalog\":", stdout);
        if (catalog[0]) { json_str(catalog); } else { fputs("null", stdout); }
        fputs(",\"signer\":", stdout);         json_str(signer[0] ? signer : "");
        fputs(",\"digest_algo\":", stdout);
        if (det.digest_algo[0]) { json_str(det.digest_algo); } else { fputs("null", stdout); }
        fputs(",\"signed_at\":", stdout);
        if (det.signed_at_present) { json_str(det.signed_at); } else { fputs("null", stdout); }
        fputs(",\"authentihash\":", stdout);
        if (det.authentihash[0]) { json_str(det.authentihash); } else { fputs("null", stdout); }
        fputs(",\"authentihash_algo\":", stdout);
        if (det.authentihash[0]) { json_str(det.authentihash_algo); } else { fputs("null", stdout); }
        printf(",\"signatures\":%d", det.have ? det.nsignatures : 0);
        fputs(",\"microsoft_root\":", stdout);
        if (det.ms_root_known) { fputs(det.ms_root ? "true" : "false", stdout); }
        else                   { fputs("null", stdout); }
        fputs(",\"program_name\":", stdout);
        if (det.program_name[0]) { json_str(det.program_name); } else { fputs("null", stdout); }
        fputs(",\"chain\":[", stdout);
        for (int i = 0; i < det.nchain; i++) {
            fputs(i ? ",{\"subject\":" : "{\"subject\":", stdout);
            json_str(det.chain[i].subject);
            fputs(",\"issuer\":", stdout);     json_str(det.chain[i].issuer);
            fputs(",\"serial\":", stdout);     json_str(det.chain[i].serial);
            fputs(",\"not_before\":", stdout); json_str(det.chain[i].not_before);
            fputs(",\"not_after\":", stdout);  json_str(det.chain[i].not_after);
            fputs(",\"sha1_thumbprint\":", stdout); json_str(det.chain[i].thumb);
            putchar('}');
        }
        fputs("]}", stdout);
        putchar('\n');
    } else {
        printf("file    %s\n", path);
        printf("  trust   %s  (0x%08lX)\n", trust_verdict(st), (unsigned long)st);
        printf("  source  %s\n", source);
        if (catalog[0]) {
            printf("  catalog %s\n", catalog);
        }
        printf("  signer  %s\n", signer[0] ? signer : "(none / unsigned)");
        if (det.program_name[0]) { printf("  program %s\n", det.program_name); }
        if (det.digest_algo[0])  { printf("  digest  %s%s\n", det.digest_algo,
                                          det.nsignatures > 1 ? " (dual-signed)" : ""); }
        if (det.signed_at_present) { printf("  signed  %s\n", det.signed_at); }
        if (det.authentihash[0]) { printf("  %-7s %s\n", det.authentihash_algo, det.authentihash); }
        if (det.ms_root_known)   { printf("  MS root %s\n", det.ms_root ? "yes (OS component)" : "no (third-party)"); }
        for (int i = 0; i < det.nchain; i++) {
            printf("  cert[%d] %s\n", i, det.chain[i].subject);
            printf("          issuer %s\n", det.chain[i].issuer);
            printf("          valid  %s .. %s\n", det.chain[i].not_before, det.chain[i].not_after);
            printf("          sha1   %s\n", det.chain[i].thumb);
        }
    }

    // Exit non-zero when the file is not trusted, so scripts and CI can gate on it.
    return (st == ERROR_SUCCESS) ? 0 : 1;
}

// ---- command line -> image -> trust (used by autoruns/services --sig) --------

int sign_command_trust(const char *cmdline, char *image, size_t n, const char **source)
{
    *source = "none";
    image[0] = '\0';
    char raw[1024];
    if (!ioc_command_image(cmdline, raw, sizeof raw)) {
        return -1;
    }
    // Kernel-style paths used by driver services (\SystemRoot\..., \??\C:\...,
    // system32\drivers\x.sys) become Win32 paths first.
    char windir[MAX_PATH] = "C:\\Windows";
    GetWindowsDirectoryA(windir, MAX_PATH);
    char norm[1024];
    drv_path_normalize(raw, windir, norm, sizeof norm);

    WCHAR w[1024], expanded[1024], found[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, norm, -1, w, 1024) == 0) return -1;
    DWORD el = ExpandEnvironmentStringsW(w, expanded, 1024);
    if (el == 0 || el > 1024) return -1;
    const WCHAR *path = expanded;
    if (wcschr(expanded, L'\\') == NULL && wcschr(expanded, L'/') == NULL) {
        // Bare name ("notepad", "rundll32.exe"): resolve like CreateProcess would.
        // Extension-less names in DLL lists (LSA packages: "scecli") are DLLs.
        DWORD fl = SearchPathW(NULL, expanded, L".exe", 1024, found, NULL);
        if (fl == 0 || fl >= 1024) {
            fl = SearchPathW(NULL, expanded, L".dll", 1024, found, NULL);
        }
        if (fl == 0 || fl >= 1024) return -1;
        path = found;
    }
    WideCharToMultiByte(CP_UTF8, 0, path, -1, image, (int)n, NULL, NULL);
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return -1;
    return sign_file_trust(path, source) ? 1 : 0;
}
