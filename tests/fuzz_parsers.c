// Sanitizer fuzz for the portable parsers (no Windows needed).
//
// Each parser that reads attacker-controllable bytes (prefetch, ShimCache,
// .lnk, event XML, Mark-of-the-Web, firewall rules, IOC classifier, command
// lines) is fed thousands of inputs derived from valid seeds by random
// mutation: byte flips, truncation, insertion, and integer-boundary values in
// header fields. Built with AddressSanitizer + UndefinedBehaviorSanitizer, so
// a single out-of-bounds read or overflow aborts the run with a report.
//
// Build (one line): cc -std=c11 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all
//          -I inc src/ioc.c src/pfparse.c src/artparse.c src/lnkparse.c src/rights.c
//          src/capa.c src/cfb.c src/destlist.c src/regf.c src/shellitem.c tests/fuzz_parsers.c -o fuzz_parsers
// Run:   ./fuzz_parsers [iterations]      (exit 0 = no sanitizer findings)

#include "pfparse.h"
#include "artparse.h"
#include "jsonmini.h"
#include "usn.h"
#include "lnkparse.h"
#include "destlist.h"
#include "regf.h"
#include "shellitem.h"
#include "ioc.h"
#include "logonparse.h"
#include "bootparse.h"
#include "werparse.h"
#include "hashlist.h"
#include "magicparse.h"
#include "officeparse.h"
#include "patchdec.h"
#include "rights.h"
#include "capa.h"
#include "cfb.h"
#include "cfb_seed.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rng = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (uint32_t)rng;
}

// Mutate src (len n) into dst; returns the new length (<= cap).
static size_t mutate(const unsigned char *src, size_t n, unsigned char *dst, size_t cap)
{
    size_t m = n < cap ? n : cap;
    memcpy(dst, src, m);
    int ops = 1 + (int)(rnd() % 8);
    for (int i = 0; i < ops && m > 0; i++) {
        switch (rnd() % 6) {
        case 0: dst[rnd() % m] = (unsigned char)rnd(); break;              // flip a byte
        case 1: m = rnd() % (m + 1); break;                                // truncate
        case 2: {                                                          // boundary u32
            static const uint32_t b[] = { 0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0xFFFF,
                                          0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu };
            if (m >= 4) {
                size_t at = rnd() % (m - 3);
                uint32_t v = b[rnd() % (sizeof b / sizeof b[0])];
                memcpy(dst + at, &v, 4);
            }
            break;
        }
        case 3: if (m < cap) { size_t at = rnd() % (m + 1);               // insert a byte
                    memmove(dst + at + 1, dst + at, m - at); dst[at] = (unsigned char)rnd(); m++; }
                break;
        case 4: if (m > 1) { size_t at = rnd() % m;                       // delete a byte
                    memmove(dst + at, dst + at + 1, m - at - 1); m--; }
                break;
        default: { size_t a = rnd() % m, b2 = rnd() % m;                   // duplicate a run
                   size_t len = rnd() % 16; if (a + len > m) len = m - a;
                   if (b2 + len <= cap) { memmove(dst + b2, dst + a, len); if (b2 + len > m) m = b2 + len; } }
                break;
        }
    }
    return m;
}

static void nop_name(const char *s, void *c) { (void)s; (void)c; }
static void nop_vol(const char *d, uint32_t s, uint64_t t, void *c) { (void)d; (void)s; (void)t; (void)c; }
static void nop_shim(const char *p, uint64_t t, int x, void *c) { (void)p; (void)t; (void)x; (void)c; }
static void nop_stream(const char *nm, const unsigned char *d, size_t n, void *c)
{
    // Touch every byte so ASan sees any out-of-bounds stream buffer.
    volatile unsigned char x = 0;
    for (size_t i = 0; i < n; i++) x ^= d[i];
    (void)nm; (void)c; (void)x;
}

// ---- seeds ------------------------------------------------------------------
static size_t seed_pf(unsigned char *d)
{
    memset(d, 0, 1024);
    d[0] = 30; memcpy(d + 4, "SCCA", 4);
    const char *nm = "CMD.EXE"; for (int i = 0; nm[i]; i++) d[16 + 2 * i] = (unsigned char)nm[i];
    d[84] = 0x30; d[85] = 1; d[128] = 1; d[208] = 5;
    d[100] = 0x90; d[101] = 1; d[104] = 20;                 // names @400, 20 bytes
    for (int i = 0; i < 8; i++) d[400 + 2 * i] = (unsigned char)"A.DLL\0B\0"[i];
    d[108] = 0xBC; d[109] = 2; d[112] = 1; d[116] = 120;    // volumes @700
    d[700] = 96; d[704] = 2; d[796] = 'C'; d[798] = ':';
    return 1024;
}
static size_t seed_mam(unsigned char *d)
{
    memcpy(d, "MAM\x84", 4); d[4] = 0; d[5] = 0x10; memset(d + 8, 0xAB, 32); return 40;
}
static size_t seed_shim(unsigned char *d)
{
    memset(d, 0, 0x34 + 72); d[0] = 0x34;
    for (int k = 0; k < 2; k++) {
        unsigned char *e = d + 0x34 + k * 36;
        memcpy(e, "10ts", 4); e[8] = 24; e[12] = 6; e[14] = 'X'; e[16] = '.'; e[18] = 'E'; e[28] = 4;
    }
    return 0x34 + 72;
}
static size_t seed_lnk(unsigned char *d)
{
    // Header + IDList + LinkInfo (VolumeID with Unicode label, network link,
    // local path) + NAME/ARGS + ExtraData (environment block, tracker block).
    static const unsigned char clsid[16] = { 1, 0x14, 2, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 };
    memset(d, 0, 2048);
    d[0] = 0x4C; memcpy(d + 4, clsid, 16); d[0x14] = 0x01 | 0x02 | 0x04 | 0x20 | 0x80;
    size_t p = 0x4C;
    d[p] = 4; p += 2 + 4;                                   // IDList of 4 bytes
    size_t li = p;
    d[li] = 0x90; d[li + 4] = 0x24; d[li + 8] = 3; d[li + 16] = 0x24; d[li + 24] = 0x3F;
    d[li + 0x1C] = 0x30; d[li + 0x20] = 0x3E;
    memcpy(d + li + 0x24, "C:\\x\\y.exe", 10);
    d[li + 12] = 0x40;                                      // VolumeID @+0x40
    d[li + 0x40] = 0x1C; d[li + 0x44] = 3; d[li + 0x4C] = 0x14; d[li + 0x50] = 0x18;
    d[li + 0x58] = 'L';
    d[li + 20] = 0x60;                                      // network link @+0x60
    d[li + 0x60] = 0x28; d[li + 0x68] = 0x1C; d[li + 0x74] = 0x20;
    memcpy(d + li + 0x7C, "\\\\s\\h", 6);
    p = li + 0x90;
    d[p] = 2; d[p + 2] = 'h'; d[p + 4] = 'i'; p += 6;       // NAME
    d[p] = 2; d[p + 2] = '/'; d[p + 4] = 'c'; p += 6;       // ARGS
    d[p] = 0x14; d[p + 1] = 0x03; d[p + 4] = 0x01; d[p + 7] = 0xA0;   // env block (0x314)
    memcpy(d + p + 8, "%x%", 3); d[p + 268] = '%'; p += 0x314;
    d[p] = 0x60; d[p + 4] = 0x03; d[p + 7] = 0xA0;                    // tracker block
    memcpy(d + p + 16, "host", 4); d[p + 48 + 7] = 0x10; p += 0x60;
    return p + 4;                                           // + terminal block
}

static size_t seed_destlist(unsigned char *d)
{
    // Version-3 header + two entries ("C:\\a", pinned; "x") with v1 droids.
    memset(d, 0, 600);
    d[0] = 3; d[4] = 2; d[8] = 1; d[16] = 2;
    size_t p = 32;
    for (int k = 0; k < 2; k++) {
        unsigned char *e = d + p;
        e[24 + 7] = 0x11; e[72] = 'h'; e[88] = (unsigned char)(k + 1);
        e[100] = 0x40; e[107] = 0x01;
        if (k) { e[108] = 0xFF; e[109] = 0xFF; e[110] = 0xFF; e[111] = 0xFF; }
        e[116] = 3;
        const char *path = k ? "x" : "C:\\a";
        size_t L = strlen(path);
        e[128] = (unsigned char)L;
        for (size_t i = 0; i < L; i++) e[130 + 2 * i] = (unsigned char)path[i];
        p += 130 + 2 * L + 4;
    }
    return p;
}
static void nop_dl(const dl_entry *e, void *ctx) { (void)e; (void)ctx; }

// Minimal hive: base block + one bin holding a root key (compressed name)
// with one subkey (lf list) and two values: an inline DWORD and a 16400-byte
// "big data" value (db record, two segments).
static void put32(unsigned char *p, uint32_t v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24); }
static size_t seed_regf(unsigned char *d)
{
    memset(d, 0, 4096 + 20480);
    memcpy(d, "regf", 4); put32(d + 4, 1); put32(d + 8, 1); put32(d + 20, 1); put32(d + 24, 5);
    put32(d + 36, 0x20); put32(d + 40, 20480);
    unsigned char *b = d + 4096;
    memcpy(b, "hbin", 4); put32(b + 8, 20480);
    // root nk @0x20 (size 88)
    unsigned char *c = b + 0x20; put32(c, (uint32_t)-88);
    memcpy(c + 4, "nk", 2); c[6] = 0x2C; put32(c + 4 + 20, 1); put32(c + 4 + 28, 0x78);
    put32(c + 4 + 36, 2); put32(c + 4 + 40, 0xE0); c[4 + 72] = 4; memcpy(c + 4 + 76, "ROOT", 4);
    // lf @0x78 (size 16) -> child @0x88
    c = b + 0x78; put32(c, (uint32_t)-16); memcpy(c + 4, "lf", 2); c[6] = 1; put32(c + 8, 0x88);
    // child nk @0x88 (size 88), name "Sub"
    c = b + 0x88; put32(c, (uint32_t)-88); memcpy(c + 4, "nk", 2); c[6] = 0x20;
    c[4 + 72] = 3; memcpy(c + 4 + 76, "Sub", 3);
    // value list @0xE0 (size 16): vk @0xF0, vk @0x110
    c = b + 0xE0; put32(c, (uint32_t)-16); put32(c + 4, 0xF0); put32(c + 8, 0x110);
    c = b + 0xF0; put32(c, (uint32_t)-32); memcpy(c + 4, "vk", 2); c[6] = 1;
    put32(c + 8, 0x80000004u); put32(c + 12, 7); put32(c + 16, 4); c[20] = 1; c[24] = 'a';
    c = b + 0x110; put32(c, (uint32_t)-32); memcpy(c + 4, "vk", 2); c[6] = 3;
    put32(c + 8, 16400); put32(c + 12, 0x130); put32(c + 16, 3); c[20] = 1; memcpy(c + 24, "big", 3);
    // db @0x130 -> segment list @0x140 -> data cells @0x150, @0x190
    c = b + 0x130; put32(c, (uint32_t)-16); memcpy(c + 4, "db", 2); c[6] = 2; put32(c + 8, 0x140);
    c = b + 0x140; put32(c, (uint32_t)-16); put32(c + 4, 0x150); put32(c + 8, 0x190);
    c = b + 0x150; put32(c, (uint32_t)-16352);         // first segment: 16344 bytes
    c = b + 0x150 + 16352; put32(c, (uint32_t)-64);    // second: the remaining 56
    put32(b + 0x140 + 8, 0x150 + 16352);
    return 4096 + 20480;
}
static size_t seed_shellitem(unsigned char *d)
{
    // directory entry + BEEF0004 v9 with a long name, followed by a CFSF
    // delegate item and a property-store item (see test_util.c)
    memset(d, 0, 512);
    d[2] = 0x31; d[8] = 0x10; d[9] = 0x53; memcpy(d + 14, "tmp", 3);
    unsigned char *b = d + 18;
    b[0] = 0x44; b[2] = 9; b[4] = 0x04; b[6] = 0xEF; b[7] = 0xBE; b[0x2E] = 'x';
    d[0] = 18 + 0x44;
    unsigned char *e = d + 128;
    e[0] = 0x60; e[2] = 0x74; memcpy(e + 6, "CFSF", 4); e[10] = 0x16; e[12] = 0x31; memcpy(e + 24, "abc", 3);
    unsigned char *pv = d + 256;
    pv[0] = 0x60; memcpy(pv + 12, "1SPS", 4); pv[8] = 0x50;
    return 512;
}
static void nop_key(uint32_t k, void *ctx) { (void)k; (void)ctx; }
static void nop_val(const regf_value *v, void *ctx) { (void)v; (void)ctx; }

// Recycle Bin: a $I v2 record followed by an INFO2 with two records; the
// mutator decides which one the parsers see (both are tried on every input).
static size_t seed_rb(unsigned char *s)
{
    memset(s, 0, 20 + 2 * 800);
    s[0] = 5; s[12] = 0x20; s[13] = 0x03;
    for (int r = 0; r < 2; r++) {
        unsigned char *p = s + 20 + r * 800;
        memcpy(p, "C:\\x\\a.exe", 10);
        p[260] = (unsigned char)(r + 1); p[264] = 2; p[275] = 0x01;
        for (int k = 0; k < 10; k++) p[280 + 2 * k] = (unsigned char)"C:\\x\\a.exe"[k];
    }
    return 20 + 2 * 800;
}

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    static unsigned char seed[32768], buf[65536];
    char text[8192];
    pf_info pi;
    lnk_info li;
    motw_info mi;
    unsigned fmt; uint32_t us; size_t off;
    const char *xml_seed =
        "<Event><System><EventID Qualifiers='16384'>7045</EventID>"
        "<TimeCreated SystemTime='2024-05-01T12:34:56.1Z'/></System><EventData>"
        "<Data Name='ServiceName'>a &amp; b</Data><Data Name=\"ImagePath\">C:\\x.exe</Data>"
        "</EventData></Event>";
    const char *texts[] = {
        xml_seed,
        "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://x/y.exe\r\nReferrerUrl=https://x/\r\n",
        "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|App=C:\\a.exe|Name=x|",
        "\"C:\\Program Files\\A B\\a.exe\" -x rundll32.exe C:\\x.dll,Run",
        "powershell -enc SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG9mIGJhc2U2NA==",
        "MSSE-1234-server", "192.168.1.1", "autocheck autochk *",
        "<Task><Settings><Hidden>true</Hidden><Enabled>false</Enabled></Settings><Actions><Exec>"
        "<Command>C:\\a.exe</Command><Arguments>&quot;x&amp;</Arguments></Exec><ComHandler><ClassId>{A}"
        "</ClassId></ComHandler></Actions><Triggers><BootTrigger/><LogonTrigger></LogonTrigger></Triggers></Task>",
        "\"%ProgramFiles(x86)%\\A B\\srv.exe\" -Embedding",
        "<Event><System><EventID>4624</EventID><TimeCreated SystemTime='2024-05-01T12:34:56.1Z'/><Channel>Security</Channel></System>"
        "<EventData><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x1a2b</Data>"
        "<Data Name='LogonType'>10</Data><Data Name='IpAddress'>::ffff:8.8.4.4</Data><Data Name='LmPackageName'>NTLM V1</Data>"
        "<Data Name='LogonProcessName'>seclogo </Data></EventData><UserData><EventXML><User>A\\b</User><Address>LOCAL</Address></EventXML></UserData></Event>",
        "EventType=APPCRASH\r\nEventTime=133500000000000000\r\nSig[0].Name=Application Name\r\nSig[0].Value=upd.exe\r\n"
        "Sig[3].Name=Fault Module Name\r\nSig[3].Value=x.dll\r\nUI[2]=C:\\Temp\\upd.exe\r\nLoadedModule[0]=C:\\Users\\b\\AppData\\upd.exe\r\nAppPath=C:\\x\r\n",
        "# list\nD41D8CD98F00B204E9800998ECF8427E\nda39a3ee5e6b4b0d3255bfef95601890afd80709  empty.bin\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,Empty File,high\n",
        "<Event><System><Provider Name='User32' Guid='{x}'/><EventID>1074</EventID><TimeCreated SystemTime='2024-05-01T12:34:56.5Z'/></System>"
        "<EventData><Data>C:\\w\\winlogon.exe (H)</Data><Data>H</Data><Data>r &amp; r</Data><Data>0x5</Data><Data>restart</Data><Data/><Data>H\\A</Data></EventData></Event>",
        "<Event><System><Provider Name=\"Microsoft-Windows-Kernel-General\"/><EventID>1</EventID></System><EventData>"
        "<Data Name='NewTime'>2015-08-08T09:12:25.85Z</Data><Data Name='OldTime'>2015-08-08T18:12:24.32Z</Data></EventData></Event>",
        "invoice.pdf            .exe", "ann\xE2\x80\xAE" "fdp.exe", "%USERPROFILE%/Downloads/a.b.docm",
    };
    for (long it = 0; it < iters; it++) {
        size_t n;
        if (it % 7 == 6) {                       // compound file (jump lists)
            n = mutate(cfb_seed, sizeof cfb_seed, buf, sizeof buf);
            cfb_file cf;
            if (cfb_open(&cf, buf, n) == 0) {
                cfb_streams(&cf, nop_stream, NULL);
                cfb_close(&cf);
            }
            continue;
        }
        switch (it % 5) {
        case 0: n = seed_pf(seed); n = mutate(seed, n, buf, sizeof buf);
                pf_parse(buf, n, &pi); pf_filenames(buf, n, nop_name, NULL);
                pf_volumes(buf, n, nop_vol, NULL); break;
        case 1: n = seed_mam(seed); n = mutate(seed, n, buf, sizeof buf);
                pf_mam_header(buf, n, &fmt, &us, &off);
                {   // change journal: v2 + v3 records behind zeros
                    memset(seed, 0, 256);
                    seed[64] = 88; seed[68] = 2; seed[64 + 56] = 10; seed[64 + 58] = 60;
                    seed[152] = 96; seed[156] = 3; seed[152 + 72] = 6; seed[152 + 74] = 76;
                    size_t m = mutate(seed, 256, buf, sizeof buf), uo = 0;
                    usn_rec ur;
                    char rs[256];
                    for (int k = 0; k < 64 && usn_next(buf, m, &uo, &ur); k++) usn_reason_str(ur.reason, rs, sizeof rs);
                }
                {
                    rb_entry re;
                    char ts[32];
                    n = seed_rb(seed);
                    if (rnd() & 1) {             // turn the seed into a $I v2 file
                        memset(seed, 0, 28);
                        seed[0] = 2; seed[24] = (unsigned char)(rnd() % 40);
                    }
                    n = mutate(seed, n, buf, sizeof buf);
                    if (rb_parse_i(buf, n, &re) == 0) rb_reason(re.path);
                    for (size_t i = 0, c = rb_info2_count(buf, n); i < c && i < 64; i++)
                        if (rb_info2_record(buf, n, i, &re) == 0) filetime_utc_str(re.deleted, ts, sizeof ts);
                }
                break;
        case 2: n = seed_shim(seed); n = mutate(seed, n, buf, sizeof buf);
                shim_parse(buf, n, nop_shim, NULL);
                {
                    uint32_t dv, dp;
                    n = seed_destlist(seed); n = mutate(seed, n, buf, sizeof buf);
                    destlist_parse(buf, n, &dv, &dp, nop_dl, NULL);
                }
                {
                    shellitem si;
                    n = seed_shellitem(seed); n = mutate(seed, n, buf, sizeof buf);
                    for (size_t off = 0; off < n; off += 128) shellitem_parse(buf + off, n - off, &si);
                }
                {
                    regf_hive rh;
                    uint32_t k;
                    n = seed_regf(seed); n = mutate(seed, n, buf, sizeof buf);
                    if (regf_open(&rh, buf, n) == 0) {
                        regf_subkeys(&rh, rh.root, nop_key, NULL);
                        regf_values(&rh, rh.root, nop_val, NULL);
                        regf_find(&rh, "Sub", &k);
                        unsigned char tmp16[16];
                        regf_get(&rh, rh.root, "big", NULL, tmp16, sizeof tmp16);
                    }
                }
                break;
        case 3: n = seed_lnk(seed); n = mutate(seed, n, buf, sizeof buf);
                lnk_parse(buf, n, &li);
                {   // small registry blobs: MRUListEx, RecentDocs, UserAssist
                    uint32_t ord[64], runs; uint64_t last; char nm[128];
                    mrulistex_order(buf, n, ord, 64);
                    recentdocs_name(buf, n, nm, sizeof nm);
                    userassist_record(buf, n, &runs, &last);
                }
                break;
        default: {
            const char *t = texts[rnd() % (sizeof texts / sizeof texts[0])];
            n = mutate((const unsigned char *)t, strlen(t), buf, sizeof buf - 1);
            memcpy(text, buf, n);
            text[n] = '\0';
            char out[256];
            evt_data(text, "ServiceName", out, sizeof out);
            evt_system(text, "EventID", out, sizeof out);
            evt_time(text, out, sizeof out);
            motw_parse(text, &mi);
            fw_field(text, "App", out, sizeof out);
            ioc_classify(text);
            ioc_script_host(text);
            ioc_ps_reason(text);
            {
                task_info ti;
                task_parse(text, &ti);
                com_path_same(text, "shell32.dll");
                com_path_same("C:\\Windows\\System32\\x.dll", text);
                bits_reason(text, text, text);
                jm_free(jm_parse(text, n));
            }
            ioc_command_image(text, out, sizeof out);
            ioc_user_writable(text);
            ioc_pipe_known(text);
            ioc_ip_scope(text);
            svc_unquoted_path(text);
            runmru_clean(text);
            rot13_inplace(text);
            capa_category(text);
            capa_packer_section(text);
            char norm[300];
            drv_path_normalize(text, "C:\\Windows", norm, sizeof norm);
            rights_decode(text, rnd(), out, sizeof out);
            {
                // The newer text parsers. Those that cut lines in place get a copy.
                static const char *const chans[] = { "Security", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "x" };
                boot_rec bk;
                boot_parse(text, &bk);
                char nth[64];
                evt_data_nth(text, (int)(rnd() % 8), nth, sizeof nth);
                evt_provider(text, nth, sizeof nth);
                iso_epoch(text);
                logon_rec lr;
                if (logon_parse(text, chans[rnd() % 3], &lr)) { logon_reason(&lr); logon_is_noise(&lr); logon_type_name(lr.type); }
                char copy[8192];
                memcpy(copy, text, n + 1);
                wer_report wr;
                if (wer_parse(copy, &wr) == 0) wer_reason(&wr);
                memcpy(copy, text, n + 1);
                hashlist hl;
                if (hashlist_parse(copy, &hl) >= 0) { hashlist_find(&hl, text); hashlist_free(&hl); }
                const char *grp;
                magic_name_reason(text, magic_sniff(buf, n, &grp) ? grp : NULL);
                magic_name_reason(text, "program");
                char tp[64];
                trustrec_path(text, tp, sizeof tp);
                trustrec_reason(text, 1);
                trustloc_reason(text);
                office_setting_reason(text, rnd() % 3);
                uint64_t ft; int en;
                trustrec_parse(buf, n, &ft, &en);
                patch_run pr[8];
                uint32_t td;
                patch_runs((const unsigned char *)t, buf, n < strlen(t) ? n : strlen(t), pr, 8, &td);
                uint64_t tgt;
                patch_decode(buf, n, rnd(), (int)(rnd() & 1), &tgt);
            }
            break;
        }
        }
    }
    printf("fuzz_parsers: %ld iterations, no sanitizer findings\n", iters);
    return 0;
}
