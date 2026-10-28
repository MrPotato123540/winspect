// Host-runnable unit tests for winspect's portable helpers.
//
// Most of winspect is Windows-only, but a few building blocks are pure C with no
// OS dependency: the MD5 used for imphash/exphash/Rich-hash, and the JSON/CSV
// string emitters every --json/--csv path relies on. Those are exactly the parts
// where a subtle bug would silently corrupt output or make a fingerprint not
// match VirusTotal/YARA, so they are worth pinning down with tests that run
// anywhere (Linux CI included), independent of Windows.
//
// Build:  cc -I inc src/md5.c src/jsonutil.c src/ioc.c src/entropy.c src/pecksum.c
//             src/imphash_ords.c src/pfparse.c src/artparse.c src/capa.c src/lnkparse.c
//             src/rights.c src/destlist.c tests/test_util.c -o test_util -lm
// Run:    ./test_util   (exit 0 = all passed)

#include "md5.h"
#include "jsonutil.h"
#include "ioc.h"
#include "entropy.h"
#include "pecksum.h"
#include "imphash_ords.h"
#include "pfparse.h"
#include "artparse.h"
#include "capa.h"
#include "lnkparse.h"
#include "destlist.h"
#include "rights.h"

#include <stdio.h>
#include <string.h>
#include <math.h>

static int failures = 0;

// Callback sinks for the prefetch list walkers.
static int pf_test_names;
static char pf_test_first[64];
static char pf_test_dev[64];
static unsigned pf_test_serial;
static void pf_test_name_cb(const char *name, void *ctx)
{
    (void)ctx;
    if (pf_test_names++ == 0) { snprintf(pf_test_first, sizeof pf_test_first, "%s", name); }
}
static int shim_test_n;
static char shim_test_path[64];
static unsigned long long shim_test_time;
static int shim_test_exec;
static void shim_test_cb(const char *path, uint64_t modified, int executed, void *ctx)
{
    (void)ctx;
    shim_test_exec = executed;
    if (shim_test_n++ == 0) {
        snprintf(shim_test_path, sizeof shim_test_path, "%s", path);
        shim_test_time = modified;
    }
}
static void pf_test_vol_cb(const char *dev, uint32_t serial, uint64_t created, void *ctx)
{
    (void)ctx; (void)created;
    snprintf(pf_test_dev, sizeof pf_test_dev, "%s", dev);
    pf_test_serial = serial;
}

static void check_str(const char *what, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "FAIL %s: got [%s], want [%s]\n", what, got, want);
        failures++;
    } else {
        fprintf(stderr, "ok   %s\n", what);
    }
}

static void check_int(const char *what, int got, int want)
{
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %d, want %d\n", what, got, want);
        failures++;
    } else {
        fprintf(stderr, "ok   %s\n", what);
    }
}

static void check_double(const char *what, double got, double want)
{
    if (fabs(got - want) > 1e-9) {
        fprintf(stderr, "FAIL %s: got %f, want %f\n", what, got, want);
        failures++;
    } else {
        fprintf(stderr, "ok   %s\n", what);
    }
}

static void check_md5(const char *in, const char *want)
{
    char out[33];
    md5_hex((const unsigned char *)in, strlen(in), out);
    char label[64];
    snprintf(label, sizeof label, "md5(\"%.20s\")", in);
    check_str(label, out, want);
}

static void dl_test_cb(const dl_entry *e, void *ctx)
{
    dl_entry *out = (dl_entry *)ctx;
    if (e->mru < 4) out[e->mru] = *e;
}

int main(void)
{
    // --- MD5 against the RFC 1321 / well-known test vectors -------------------
    check_md5("", "d41d8cd98f00b204e9800998ecf8427e");
    check_md5("a", "0cc175b9c0f1b6a831c399e269772661");
    check_md5("abc", "900150983cd24fb0d6963f7d28e17f72");
    check_md5("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
    check_md5("The quick brown fox jumps over the lazy dog",
              "9e107d9d372bb6826bd81d3542a419d6");

    // --- IOC classification ---------------------------------------------------
    check_str("ioc url",     ioc_classify("GET http://evil.example/x"), "url");
    check_str("ioc url2",    ioc_classify("https://a.b/c"), "url");
    check_str("ioc reg",     ioc_classify("HKEY_LOCAL_MACHINE\\Software"), "registry");
    check_str("ioc reg2",    ioc_classify("...\\CurrentVersion\\Run"), "registry");
    check_str("ioc ip",      ioc_classify("beacon 10.0.0.1 ok"), "ip");
    check_str("ioc path",    ioc_classify("C:\\Windows\\x.dll"), "path");
    check_str("ioc unc",     ioc_classify("\\\\server\\share"), "path");
    check_str("ioc none",    ioc_classify("just some words"), "");
    check_int("ipv4 ok",     ioc_is_ipv4("192.168.1.1"), 1);
    check_int("ipv4 edge",   ioc_is_ipv4("255.255.255.255"), 1);
    check_int("ipv4 oob",    ioc_is_ipv4("256.1.1.1"), 0);
    check_int("ipv4 short",  ioc_is_ipv4("1.2.3"), 0);
    check_int("ipv4 none",   ioc_is_ipv4("hello"), 0);

    // --- Shannon entropy against hand-computable values -----------------------
    {
        unsigned char zeros[64];
        memset(zeros, 0, sizeof zeros);
        check_double("entropy zeros", shannon_entropy(zeros, sizeof zeros), 0.0);

        unsigned char half[64];                 // 32x 'A', 32x 'B' => 1 bit/byte
        for (int i = 0; i < 64; i++) { half[i] = (i < 32) ? 'A' : 'B'; }
        check_double("entropy 50/50", shannon_entropy(half, sizeof half), 1.0);

        unsigned char uniform[256];             // each byte value once => 8 bits/byte
        for (int i = 0; i < 256; i++) { uniform[i] = (unsigned char)i; }
        check_double("entropy uniform", shannon_entropy(uniform, sizeof uniform), 8.0);

        check_double("entropy empty", shannon_entropy(zeros, 0), 0.0);
    }

    // --- imphash library-name rule (pefile-compatible) ------------------------
    {
        char lib[64];
        imphash_libname("KERNEL32.DLL", lib, sizeof lib); check_str("imp kernel32", lib, "kernel32");
        imphash_libname("WS2_32.dll",  lib, sizeof lib);  check_str("imp ws2_32", lib, "ws2_32");
        imphash_libname("Foo.OCX",     lib, sizeof lib);  check_str("imp ocx", lib, "foo");
        imphash_libname("bar.SYS",     lib, sizeof lib);  check_str("imp sys", lib, "bar");
        imphash_libname("thing.exe",   lib, sizeof lib);  check_str("imp exe-kept", lib, "thing.exe");
        imphash_libname("noext",       lib, sizeof lib);  check_str("imp noext", lib, "noext");
        imphash_libname("api-ms-win-core-x.dll", lib, sizeof lib);
        check_str("imp apiset", lib, "api-ms-win-core-x");
        check_int("imp ord unknown-dll", imphash_ord_name("notareal.dll", 1) == NULL, 1);
    }

    // --- PE checksum against hand-computed values -----------------------------
    {
        // csfield out of range => no word skipped. 8 zero bytes: sum 0, +size 8.
        unsigned char z8[8] = {0};
        check_int("cksum zeros", (int)pe_checksum(z8, 8, 1000), 8);
        // one word 0x0001, +size 2 => 3.
        unsigned char one[2] = { 0x01, 0x00 };
        check_int("cksum 0x0001", (int)pe_checksum(one, 2, 1000), 3);
        // word 0xFFFF folds to 0xFFFF, +size 2 => 0x10001.
        unsigned char ff[2] = { 0xFF, 0xFF };
        check_int("cksum 0xFFFF", (int)pe_checksum(ff, 2, 1000), 0x10001);
        // Invariant: the 4 CheckSum bytes are ignored, so changing them must not
        // change the result (two buffers differing only at csfield compare equal).
        unsigned char a[16], b[16];
        for (int i = 0; i < 16; i++) { a[i] = (unsigned char)(i * 7 + 1); b[i] = a[i]; }
        b[4] = 0xAA; b[5] = 0xBB; b[6] = 0xCC; b[7] = 0xDD;   // csfield = 4
        check_int("cksum ignores field",
                  (int)(pe_checksum(a, 16, 4) == pe_checksum(b, 16, 4)), 1);
    }

    // --- prefetch (SCCA) parser on synthetic headers --------------------------
    {
        static unsigned char pf[256];
        memset(pf, 0, sizeof pf);
        pf[0] = 30;                                   // version 30 (Windows 10)
        memcpy(pf + 4, "SCCA", 4);
        const char *nm = "CMD.EXE";                   // UTF-16LE at offset 16
        for (int i = 0; nm[i]; i++) { pf[16 + 2 * i] = (unsigned char)nm[i]; }
        pf[76] = 0x78; pf[77] = 0x56; pf[78] = 0x34; pf[79] = 0x12;   // hash
        pf[84] = 0x30; pf[85] = 0x01;                 // metrics @0x130 => long form
        pf[128] = 0x11; pf[135] = 0x01;               // times[0] = 0x0100000000000011
        pf[136] = 0x22;                               // times[1] = 0x22
        pf[208] = 42;                                 // run count (long form)
        pf[200] = 7;                                  // decoy for the short form
        pf_info pi;
        check_int("pf parse rc", pf_parse(pf, sizeof pf, &pi), 0);
        check_str("pf exe", pi.exe, "CMD.EXE");
        check_int("pf hash", (int)(pi.hash == 0x12345678u), 1);
        check_int("pf runs v30 long", (int)pi.run_count, 42);
        check_int("pf ntimes", pi.ntimes, 2);
        check_int("pf time0", (int)(pi.times[0] == 0x0100000000000011ull), 1);
        pf[84] = 0x28;                                // metrics @0x128 => short form
        pf_parse(pf, sizeof pf, &pi);
        check_int("pf runs v30 short", (int)pi.run_count, 7);
        pf[0] = 23; pf[152] = 9;                      // Vista/7 layout
        pf_parse(pf, sizeof pf, &pi);
        check_int("pf runs v23", (int)pi.run_count, 9);
        check_int("pf v23 ntimes", pi.ntimes, 1);
        pf[0] = 99;
        check_int("pf unknown ver", pf_parse(pf, sizeof pf, &pi), -2);
        pf[0] = 30;                                   // valid version, cut short
        check_int("pf truncated", pf_parse(pf, 150, &pi), -2);
        check_int("pf too short", pf_parse(pf, 40, &pi), -1);
        pf[5] = 'X';
        check_int("pf not scca", pf_parse(pf, sizeof pf, &pi), -1);

        unsigned fmt; uint32_t us; size_t off;
        unsigned char mam[12] = { 'M', 'A', 'M', 0x04, 0x00, 0x10, 0, 0 };
        check_int("mam detect", pf_mam_header(mam, sizeof mam, &fmt, &us, &off), 1);
        check_int("mam fmt", (int)fmt, 4);
        check_int("mam usize", (int)us, 0x1000);
        check_int("mam off", (int)off, 8);
        mam[3] = 0x84;
        pf_mam_header(mam, sizeof mam, &fmt, &us, &off);
        check_int("mam crc off", (int)off, 12);
        check_int("mam not", pf_mam_header(pf, sizeof pf, &fmt, &us, &off), 0);
    }

    // --- prefetch referenced files + volumes -----------------------------------
    {
        static unsigned char pf[512];
        memset(pf, 0, sizeof pf);
        pf[0] = 30;
        memcpy(pf + 4, "SCCA", 4);
        // filename strings @300, 20 bytes: "A.DLL\0" "B\0" (UTF-16)
        pf[100] = 44; pf[101] = 1; pf[104] = 20;
        const char *names = "A.DLL\0B\0";
        for (int i = 0; i < 8; i++) { pf[300 + 2 * i] = (unsigned char)names[i]; }
        // volumes @340: 1 entry of 96 bytes, path at +96 ("C:", 2 chars)
        pf[108] = 0x54; pf[109] = 1; pf[112] = 1; pf[116] = 120;
        pf[340] = 96; pf[344] = 2;
        pf[340 + 16] = 0xEF; pf[340 + 17] = 0xBE;          // serial 0xBEEF
        pf[436] = 'C'; pf[438] = ':';
        pf_test_names = 0; pf_test_first[0] = '\0';
        check_int("pf files count", pf_filenames(pf, sizeof pf, pf_test_name_cb, NULL), 2);
        check_str("pf files first", pf_test_first, "A.DLL");
        check_int("pf vols count", pf_volumes(pf, sizeof pf, pf_test_vol_cb, NULL), 1);
        check_str("pf vol dev", pf_test_dev, "C:");
        check_int("pf vol serial", (int)pf_test_serial, 0xBEEF);
        pf[104] = 0xFF; pf[105] = 0xFF;                      // size past the buffer
        check_int("pf files oob", pf_filenames(pf, sizeof pf, pf_test_name_cb, NULL), -1);
    }

    // --- prefetch: full path of the executable from the referenced files ---------
    {
        static unsigned char pf[600];
        memset(pf, 0, sizeof pf);
        pf[0] = 30;
        memcpy(pf + 4, "SCCA", 4);
        const char *names = "\\V\\W\\NTDLL.DLL\0\\V\\USERS\\B\\DOWNLOADS\\TOOL.EXE\0"
                            "\\V\\X\\ABCDEFGHIJKLMNOPQRSTUVWXYZ0123.EXE\0";
        size_t nl = 0;
        while (!(names[nl] == 0 && names[nl + 1] == 0 && nl > 60)) nl++;
        nl += 1;
        pf[100] = 0x2C; pf[101] = 1; pf[104] = (unsigned char)(2 * nl);
        for (size_t i = 0; i < nl; i++) pf[300 + 2 * i] = (unsigned char)names[i];
        char path[256];
        check_int("pf exe found", pf_exe_path(pf, sizeof pf, "tool.exe", path, sizeof path), 1);
        check_str("pf exe path", path, "\\V\\USERS\\B\\DOWNLOADS\\TOOL.EXE");
        check_int("pf exe 29 prefix", pf_exe_path(pf, sizeof pf, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012", path, sizeof path), 1);
        check_int("pf exe no partial", pf_exe_path(pf, sizeof pf, "OOL.EXE", path, sizeof path), 0);
        check_str("pf exe empty", path, "");
        check_int("pf exe small buf", pf_exe_path(pf, sizeof pf, "TOOL.EXE", path, 8), 0);
    }

    // --- ShimCache (Win10 layout) ----------------------------------------------
    {
        static unsigned char sc[0x34 + 2 * 40];
        memset(sc, 0, sizeof sc);
        sc[0] = 0x34;                                  // Creators Update header
        // Two entries of: "10ts" | unk | size=24 | psize=6 "X.E" | time | dsize=4 | data
        for (int k = 0; k < 2; k++) {
            unsigned char *e = sc + 0x34 + k * 36;
            memcpy(e, "10ts", 4);
            e[8] = 24;                                 // 2+6+8+4+4 = 24
            e[12] = 6;
            e[14] = 'X'; e[16] = '.'; e[18] = (unsigned char)('E' + k);
            e[20] = 0x99;                              // FILETIME low byte
            e[28] = 4;                                 // data size
        }
        shim_test_n = 0;
        check_int("shim count", shim_parse(sc, 0x34 + 72, shim_test_cb, NULL), 2);
        check_str("shim path", shim_test_path, "X.E");
        check_int("shim time", (int)shim_test_time, 0x99);
        sc[0x34 + 28] = 200;                           // data size overflows entry
        shim_test_n = 0;
        check_int("shim malformed", shim_parse(sc, 0x34 + 72, shim_test_cb, NULL), -2);
        sc[0] = 0x80;                                  // Windows 8 header: not handled
        check_int("shim old layout", shim_parse(sc, sizeof sc, shim_test_cb, NULL), -1);
    }

    // --- ShimCache, Windows 7 x64 / x86 layouts ---------------------------------
    {
        static unsigned char w7[512];
        memset(w7, 0, sizeof w7);
        w7[0] = 0xEE; w7[1] = 0x0F; w7[2] = 0xDC; w7[3] = 0xBA;   // 0xBADC0FEE
        w7[4] = 2;                                                // 2 entries
        // x64 entries at 128 and 176; paths at 300 ("A.EXE") and 320 ("B")
        unsigned char *e = w7 + 128;
        e[0] = 10; e[2] = 10; e[8] = 0x2C; e[9] = 0x01;          // len 10, off 300
        e[16] = 0x55;                                             // FILETIME
        e[24] = 0x02;                                             // InsertFlags: executed
        e = w7 + 176;
        e[0] = 2; e[2] = 2; e[8] = 0x40; e[9] = 0x01;            // len 2, off 320
        const char *p1 = "A.EXE";
        for (int i = 0; i < 5; i++) w7[300 + 2 * i] = (unsigned char)p1[i];
        w7[320] = 'B';
        const char *fmt = NULL;
        shim_test_n = 0;
        check_int("shim7 count", shim_parse_ex(w7, sizeof w7, shim_test_cb, NULL, &fmt), 2);
        check_str("shim7 fmt", fmt, "win7-x64");
        check_str("shim7 path", shim_test_path, "A.EXE");
        check_int("shim7 time", (int)shim_test_time, 0x55);
        check_int("shim7 last exec flag", shim_test_exec, 0);       // second entry: not executed
        w7[176 + 8] = 0xF0; w7[176 + 9] = 0x7F;                     // second path out of range
        shim_test_n = 0;
        check_int("shim7 bad offset", shim_parse(w7, sizeof w7, shim_test_cb, NULL), -2);
        // x86: 32-byte entries, 32-bit path offset @4, FILETIME @8, flags @16
        memset(w7 + 128, 0, 100);
        w7[4] = 1;
        e = w7 + 128;
        e[0] = 10; e[2] = 10; e[4] = 0x2C; e[5] = 0x01; e[8] = 0x66; e[16] = 0x02;
        shim_test_n = 0;
        check_int("shim7 x86 count", shim_parse_ex(w7, sizeof w7, shim_test_cb, NULL, &fmt), 1);
        check_str("shim7 x86 fmt", fmt, "win7-x86");
        check_int("shim7 x86 exec", shim_test_exec, 1);
        check_int("shim7 x86 time", (int)shim_test_time, 0x66);
    }

    // --- firewall rule fields + user-writable path hint ---------------------------
    {
        const char *r = "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|"
                        "App=%APPDATA%\\x.exe|Name=Remote|";
        char v[64];
        check_int("fw has Action", fw_field(r, "Action", v, sizeof v), 1);
        check_str("fw Action", v, "Allow");
        fw_field(r, "LPort", v, sizeof v);
        check_str("fw LPort", v, "3389");
        check_int("fw Port != LPort", fw_field(r, "Port", v, sizeof v), 0);
        fw_field(r, "Name", v, sizeof v);
        check_str("fw last field", v, "Remote");
        check_int("fw missing", fw_field(r, "RPort", v, sizeof v), 0);
        check_int("uw appdata var", ioc_user_writable("%APPDATA%\\x.exe"), 1);
        check_int("uw temp", ioc_user_writable("C:\\Users\\a\\AppData\\Local\\Temp\\y.dll"), 1);
        check_int("uw system32", ioc_user_writable("C:\\Windows\\System32\\svchost.exe"), 0);
    }

    // --- unquoted service paths + driver path normalisation ----------------------
    {
        check_int("unq spaces", svc_unquoted_path("C:\\Program Files\\My App\\svc.exe -k x"), 1);
        check_int("unq quoted", svc_unquoted_path("\"C:\\Program Files\\A\\svc.exe\" -k"), 0);
        check_int("unq nospace", svc_unquoted_path("C:\\Windows\\system32\\svchost.exe -k netsvcs"), 0);
        check_int("unq args only", svc_unquoted_path("C:\\Tools\\svc.exe --name \"a b\""), 0);
        check_int("unq no exe", svc_unquoted_path("C:\\Program Files\\x.sys"), 0);
        check_int("unq .exec dir", svc_unquoted_path("C:\\a.executables\\b c\\d.exe"), 1);
        char o[128];
        drv_path_normalize("\\SystemRoot\\system32\\drivers\\x.sys", "C:\\Windows", o, sizeof o);
        check_str("drv systemroot", o, "C:\\Windows\\system32\\drivers\\x.sys");
        drv_path_normalize("\\??\\D:\\x.sys", "C:\\Windows", o, sizeof o);
        check_str("drv dosdev", o, "D:\\x.sys");
        drv_path_normalize("System32\\drivers\\y.sys", "C:\\Windows", o, sizeof o);
        check_str("drv relative", o, "C:\\Windows\\System32\\drivers\\y.sys");
        drv_path_normalize("\\Windows\\z.sys", "E:\\Windows", o, sizeof o);
        check_str("drv rootless", o, "E:\\Windows\\z.sys");
    }

    // --- import capability tagging --------------------------------------------
    {
        check_str("capa wpm", capa_category("WriteProcessMemory"), "process-injection");
        check_str("capa hook W", capa_category("SetWindowsHookExW"), "keyboard-input");
        check_str("capa url A", capa_category("InternetOpenUrlA"), "network");
        check_str("capa token W", capa_category("CreateProcessAsUserW"), "privilege-token");
        check_int("capa common", capa_category("GetProcAddress") == NULL, 1);
        check_int("capa no strip", capa_category("IsDebuggerPresentX") == NULL, 1);
        check_int("capa empty", capa_category("") == NULL, 1);
        capa_sum cs;
        capa_init(&cs);
        capa_add(&cs, "OpenProcess");
        capa_add(&cs, "ReadProcessMemory");
        capa_add(&cs, "lstrlenW");
        check_int("capa sum count", (int)cs.count[1], 2);
        check_str("capa sum ex", cs.example[1][1], "ReadProcessMemory");
        check_str("packer upx", capa_packer_section("UPX1"), "UPX");
        check_str("packer vmp", capa_packer_section(".vmp0"), "VMProtect");
        check_int("packer text", capa_packer_section(".text") == NULL, 1);
        check_int("packer case", capa_packer_section("upx1") == NULL, 1);
    }

    // --- .lnk parser (MS-SHLLINK) on a hand-built link ---------------------------
    {
        static unsigned char lk[512];
        memset(lk, 0, sizeof lk);
        static const unsigned char clsid[16] = { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0,
                                                 0xC0, 0, 0, 0, 0, 0, 0, 0x46 };
        lk[0] = 0x4C;
        memcpy(lk + 4, clsid, 16);
        // LinkFlags: HasLinkInfo | HasArguments | IsUnicode
        lk[0x14] = 0x02 | 0x20 | 0x80;
        lk[0x1C] = 0x11;                               // CreationTime low byte
        // LinkInfo at 0x4C: size 0x40, header 0x1C, flags 1 (local path),
        // LocalBasePath at +0x1C, CommonPathSuffix at +0x3F (empty string).
        size_t li = 0x4C;
        lk[li] = 0x40; lk[li + 4] = 0x1C; lk[li + 8] = 1;
        lk[li + 16] = 0x1C; lk[li + 24] = 0x3F;
        memcpy(lk + li + 0x1C, "C:\\Tools\\run.exe", 16);
        // StringData: COMMAND_LINE_ARGUMENTS, 3 UTF-16 chars "/q!"
        size_t sd = li + 0x40;
        lk[sd] = 3;
        lk[sd + 2] = '/'; lk[sd + 4] = 'q'; lk[sd + 6] = '!';
        lnk_info li_out;
        check_int("lnk rc", lnk_parse(lk, sd + 8, &li_out), 0);
        check_str("lnk target", li_out.target, "C:\\Tools\\run.exe");
        check_str("lnk args", li_out.arguments, "/q!");
        check_int("lnk ctime", (int)li_out.created, 0x11);
        check_int("lnk truncated", lnk_parse(lk, sd + 4, &li_out), -2);
        check_str("lnk partial kept", li_out.target, "C:\\Tools\\run.exe");
        lk[li + 16] = 0xF0;                            // base path offset out of LinkInfo
        lnk_parse(lk, sd + 8, &li_out);
        check_str("lnk bad offset ignored", li_out.target, "");
        lk[4] = 0;                                     // wrong CLSID
        check_int("lnk not a link", lnk_parse(lk, sd + 8, &li_out), -1);
    }

    // --- .lnk: inflated WORKING_DIR count, padding, VolumeID, TrackerDataBlock --
    {
        static unsigned char lk[2048];
        memset(lk, 0, sizeof lk);
        static const unsigned char clsid[16] = { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0,
                                                 0xC0, 0, 0, 0, 0, 0, 0, 0x46 };
        lk[0] = 0x4C;
        memcpy(lk + 4, clsid, 16);
        // LinkFlags: HasLinkInfo | HasWorkingDir | HasArguments | IsUnicode
        lk[0x14] = 0x02 | 0x10 | 0x20 | 0x80;
        // LinkInfo: header 0x1C, flags 1, VolumeID at +0x1C (size 0x14: type 2
        // removable, serial 0x1A2B3C4D, label offset 0x10 -> "USB"), base path
        // at +0x30, suffix at +0x3F.
        size_t li = 0x4C;
        lk[li] = 0x40; lk[li + 4] = 0x1C; lk[li + 8] = 1;
        lk[li + 12] = 0x1C; lk[li + 16] = 0x30; lk[li + 24] = 0x3F;
        size_t v = li + 0x1C;
        lk[v] = 0x14; lk[v + 4] = 2;
        lk[v + 8] = 0x4D; lk[v + 9] = 0x3C; lk[v + 10] = 0x2B; lk[v + 11] = 0x1A;
        lk[v + 12] = 0x10; memcpy(lk + v + 0x10, "USB", 3);
        memcpy(lk + li + 0x30, "E:\\x.exe", 8);
        // WORKING_DIR claims 1000 chars but only 260 are read; the arguments
        // follow right after those 260 characters (all blanks here).
        size_t sd = li + 0x40;
        lk[sd] = 0xE8; lk[sd + 1] = 0x03;               // 1000
        for (int i = 0; i < 260; i++) lk[sd + 2 + 2 * i] = ' ';
        size_t ar = sd + 2 + 520;
        lk[ar] = 2; lk[ar + 2] = '/'; lk[ar + 4] = 'c';
        // TrackerDataBlock after the strings: size 0x60, sig 0xA0000003,
        // MachineID "pc-1", file droid = v1 UUID with node 00:11:22:33:44:55.
        size_t tb = ar + 6;
        lk[tb] = 0x60; lk[tb + 4] = 0x03; lk[tb + 7] = 0xA0;
        memcpy(lk + tb + 16, "pc-1", 4);
        lk[tb + 48 + 7] = 0x11;                         // Data3 high byte: version 1
        for (int i = 0; i < 6; i++) lk[tb + 48 + 10 + i] = (unsigned char)(i * 0x11);
        size_t end = tb + 0x60 + 4;                     // + terminal block
        lnk_info o;
        check_int("lnk2 rc", lnk_parse(lk, end, &o), 0);
        check_str("lnk2 args after 260", o.arguments, "/c");
        check_int("lnk2 oversized", (int)(o.anomalies & LNK_ANOM_OVERSIZED_STRING), 1);
        check_int("lnk2 padded", (o.anomalies & LNK_ANOM_PADDING) != 0, 1);
        check_int("lnk2 vol type", (int)o.drive_type, 2);
        check_int("lnk2 vol serial", o.drive_serial == 0x1A2B3C4Du, 1);
        check_str("lnk2 vol label", o.volume_label, "USB");
        check_str("lnk2 drive name", lnk_drive_type_name(o.drive_type), "removable");
        check_str("lnk2 machine", o.machine_id, "pc-1");
        check_str("lnk2 mac", o.mac, "00:11:22:33:44:55");
        lk[tb + 48 + 7] = 0x41;                         // version 4 (random) UUID: no MAC
        lnk_parse(lk, end, &o);
        check_str("lnk2 v4 no mac", o.mac, "");
        lk[tb] = 0xFF; lk[tb + 1] = 0x7F;               // block runs past the buffer
        check_int("lnk2 bad block rc", lnk_parse(lk, end, &o), 0);
        check_str("lnk2 bad block skipped", o.machine_id, "");
    }

    // --- Jump List DestList (version 1 layout) + v1 UUID ------------------------
    {
        static unsigned char dl[400];
        memset(dl, 0, sizeof dl);
        dl[0] = 1; dl[4] = 2; dl[8] = 0;                 // v1, 2 entries, 0 pinned
        unsigned char *e = dl + 32;
        // file droid: v1 UUID, time_low 0x01020304, time_mid 0x0506, time_hi
        // 0x1D2 (Data3 = 0x11D2: version 1), node 0a:0b:0c:0d:0e:0f
        e[24] = 0x04; e[25] = 0x03; e[26] = 0x02; e[27] = 0x01; e[28] = 0x06; e[29] = 0x05;
        e[30] = 0xD2; e[31] = 0x11;
        for (int i = 0; i < 6; i++) e[24 + 10 + i] = (unsigned char)(0x0A + i);
        memcpy(e + 72, "pc-9", 4);
        e[88] = 0x1A;                                    // entry number 0x1a
        e[100] = 0x10;                                   // last used FILETIME 0x10
        e[108] = 0xFF; e[109] = 0xFF; e[110] = 0xFF; e[111] = 0xFF;   // not pinned
        e[112] = 2; e[114] = 'C'; e[116] = ':';
        unsigned char *e2 = e + 114 + 4;                 // second entry: pinned, empty path
        e2[88] = 2;
        static dl_entry got[4];
        uint32_t ver = 0, pin = 0;
        check_int("dl count", destlist_parse(dl, 32 + 118 + 114, &ver, &pin, dl_test_cb, got), 2);
        check_int("dl version", (int)ver, 1);
        check_int("dl entry hex", (int)got[0].entry, 0x1A);
        check_str("dl host", got[0].host, "pc-9");
        check_str("dl path", got[0].path, "C:");
        check_int("dl not pinned", got[0].pinned, 0);
        check_int("dl pinned", got[1].pinned, 1);
        check_int("dl v1 no interactions", got[0].has_interactions, 0);
        check_str("dl mac", got[0].mac, "0a:0b:0c:0d:0e:0f");
        check_int("dl droid time", got[0].droid_time == 0x01D2050601020304ULL - 5748192000000000ULL, 1);
        check_int("dl mru", (int)got[1].mru, 1);
        check_int("dl truncated", destlist_parse(dl, 32 + 118 + 50, &ver, &pin, dl_test_cb, got), 1);
        check_int("dl bad version", (dl[0] = 9, destlist_parse(dl, sizeof dl, &ver, &pin, dl_test_cb, got)), -1);
    }

    // --- script host / LOLBin launcher detection --------------------------------
    {
        check_int("sh powershell", ioc_script_host("powershell.exe -enc AAAA"), 1);
        check_int("sh quoted", ioc_script_host("\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop"), 1);
        check_int("sh bare", ioc_script_host("mshta http://x/y.hta"), 1);
        check_int("sh rundll", ioc_script_host("C:\\Windows\\system32\\rundll32.exe a.dll,Run"), 1);
        check_int("sh arg only", ioc_script_host("C:\\Apps\\tool.exe --shell powershell"), 0);
        check_int("sh similar name", ioc_script_host("C:\\x\\cmdhelper.exe"), 0);
        check_int("sh spaced path", ioc_script_host("C:\\Program Files\\App\\app.exe /s"), 0);
        check_int("sh spaced host", ioc_script_host("C:\\My Tools\\wscript.exe x.vbs"), 1);
    }

    // --- process lineage rules ----------------------------------------------------
    {
        check_int("asep exefile stock", asep_exefile_default("\"%1\" %*"), 1);
        check_int("asep exefile blanks", asep_exefile_default("  \"%1\" %*  "), 1);
        check_int("asep exefile wrapped", asep_exefile_default("C:\\x\\w.exe \"%1\" %*"), 0);
        check_int("asep exefile empty", asep_exefile_default(""), 0);
        check_int("asep tp sysroot", asep_time_provider_default("%systemroot%\\system32\\w32time.dll"), 1);
        check_int("asep tp bare", asep_time_provider_default("vmictimeprovider.dll"), 1);
        check_int("asep tp case", asep_time_provider_default("C:\\WINDOWS\\System32\\W32TIME.DLL"), 1);
        check_int("asep tp elsewhere", asep_time_provider_default("C:\\Users\\a\\w32time.dll"), 0);
        check_int("asep tp other dll", asep_time_provider_default("C:\\Windows\\System32\\evil.dll"), 0);
        check_int("asep tp short", asep_time_provider_default("\\w32time.dll"), 0);
        check_int("lin acct lsass", lineage_system_account("LSASS.EXE"), 1);
        check_int("lin acct svchost", lineage_system_account("svchost.exe"), 0);
        check_int("lin late lsass", lineage_started_late("lsass.exe", 3600), 1);
        check_int("lin early lsass", lineage_started_late("lsass.exe", 40), 0);
        check_int("lin late edge", lineage_started_late("services.exe", LINEAGE_BOOT_WINDOW_S), 0);
        check_int("lin late csrss", lineage_started_late("csrss.exe", 99999), 0);
        {   // event XPath time window + failed-logon summary
            char xp[256];
            check_int("xp since rc", evt_xpath_since("*[System[(EventID=4625)]]", 24, xp, sizeof xp), 0);
            check_str("xp since", xp, "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]");
            check_int("xp zero", evt_xpath_since("*[System[(EventID=1)]]", 0, xp, sizeof xp), 0);
            check_str("xp zero same", xp, "*[System[(EventID=1)]]");
            check_int("xp bad shape", evt_xpath_since("Event/System", 1, xp, sizeof xp), -1);
            check_int("xp too small", evt_xpath_since("*[System[(EventID=1)]]", 1, xp, 20), -1);
            static evt_fail_table ft;
            memset(&ft, 0, sizeof ft);
            for (int i = 0; i < 12; i++) evt_fail_add(&ft, "10.0.0.9", "admin", i == 3 ? "2024-01-01 00:00:01" : "2024-01-02 10:00:00");
            evt_fail_add(&ft, "10.0.0.9", "ADMIN", "2024-01-03 00:00:00");
            const char *users[] = { "a", "b", "c", "d", "e" };
            for (int i = 0; i < 5; i++) evt_fail_add(&ft, "203.0.113.5", users[i], "2024-01-02 00:00:00");
            evt_fail_add(&ft, "", "bob", "2024-01-02 00:00:00");
            check_int("fail sources", (int)ft.n, 3);
            check_int("fail count", (int)ft.src[0].count, 13);
            check_int("fail users ci", (int)ft.src[0].nusers, 1);
            check_str("fail first", ft.src[0].first, "2024-01-01 00:00:01");
            check_str("fail last", ft.src[0].last, "2024-01-03 00:00:00");
            check_int("fail guess", evt_fail_verdict(&ft.src[0]) != NULL && strstr(evt_fail_verdict(&ft.src[0]), "guessing") != NULL, 1);
            check_int("fail spray", evt_fail_verdict(&ft.src[1]) != NULL && strstr(evt_fail_verdict(&ft.src[1]), "spraying") != NULL, 1);
            check_str("fail local ip", ft.src[2].ip, "-");
            check_int("fail quiet", evt_fail_verdict(&ft.src[2]) == NULL, 1);
        }
        {
            char sh[41];
            check_int("amc sha1", amcache_sha1("0000056f4b9d9ec9b5dc548e1b460da889e44089d76f", sh), 1);
            check_str("amc sha1 val", sh, "056f4b9d9ec9b5dc548e1b460da889e44089d76f");
            check_int("amc sha1 upper", amcache_sha1("056F4B9D9EC9B5DC548E1B460DA889E44089D76F", sh), 1);
            check_str("amc sha1 lower", sh, "056f4b9d9ec9b5dc548e1b460da889e44089d76f");
            check_int("amc sha1 short", amcache_sha1("0000abc", sh), 0);
            check_int("amc sha1 nonhex", amcache_sha1("0000zz6f4b9d9ec9b5dc548e1b460da889e44089d76f", sh), 0);
            check_str("amc sha1 cleared", sh, "");
            check_int("amc sha1 bad prefix", amcache_sha1("1111056f4b9d9ec9b5dc548e1b460da889e44089d76f", sh), 0);
        }
        check_int("masq subdir", asep_masquerade("c:\\windows\\system32\\dllhost\\svchost.exe"), 1);
        check_int("masq real", asep_masquerade("C:\\Windows\\System32\\svchost.exe"), 0);
        check_int("masq env", asep_masquerade("%SystemRoot%\\system32\\lsass.exe"), 0);
        check_int("masq wow", asep_masquerade("C:\\Windows\\SysWOW64\\rundll32.exe"), 0);
        check_int("masq bare", asep_masquerade("svchost.exe"), 0);
        check_int("masq temp", asep_masquerade("C:\\Users\\a\\AppData\\Local\\Temp\\lsass.exe"), 1);
        check_int("masq other name", asep_masquerade("C:\\Tools\\svc.exe"), 0);
        {
            char st[32];
            static const unsigned char created[16] = { 0xda, 0x07, 0x0b, 0, 0x03, 0, 0x0a, 0, 0x0b, 0, 0x17, 0, 0x2b, 0, 0x9f, 0x02 };
            check_int("systime ok", systemtime_str(created, 16, st, sizeof st), 1);
            check_str("systime val", st, "2010-11-10 11:23:43");
            static const unsigned char bad[16] = { 0xda, 0x07, 0x0d, 0 };
            check_int("systime bad month", systemtime_str(bad, 16, st, sizeof st), 0);
            check_int("systime short", systemtime_str(created, 8, st, sizeof st), 0);
            unix_time_str(0x4cdac847u, st, sizeof st);
            check_str("unix install", st, "2010-11-10 16:28:55");
            unix_time_str(951782400u, st, sizeof st);          // 2000-02-29 (leap day)
            check_str("unix leap", st, "2000-02-29 00:00:00");
            unix_time_str(0, st, sizeof st);
            check_str("unix zero", st, "");
            check_str("nl wireless", netlist_name_type(71), "wireless");
            check_str("nl domain", netlist_category(2), "domain");
        }
        check_int("lin lsass ok", lineage_parent_ok("lsass.exe", "wininit.exe"), 1);
        check_int("lin lsass bad", lineage_parent_ok("LSASS.EXE", "explorer.exe"), 0);
        check_int("lin svchost ok", lineage_parent_ok("svchost.exe", "services.exe"), 1);
        check_int("lin svchost bad", lineage_parent_ok("svchost.exe", "cmd.exe"), 0);
        check_int("lin csrss exited", lineage_parent_ok("csrss.exe", NULL), 1);
        check_int("lin lsass exited", lineage_parent_ok("lsass.exe", NULL), -1);
        check_int("lin no rule", lineage_parent_ok("notepad.exe", "explorer.exe"), -1);
        check_int("lin singleton", lineage_singleton("Lsass.exe"), 1);
        check_int("lin not singleton", lineage_singleton("svchost.exe"), 0);
        check_int("lin sys32 only", lineage_system32_only("svchost.exe"), 1);
        check_int("lin not sys32", lineage_system32_only("chrome.exe"), 0);
    }

    // --- posture rule evaluation ------------------------------------------------
    {
        check_int("pos eq good", posture_judge(PR_GOOD_IF_EQ, 1, 1, 1, POSTURE_INFO), POSTURE_OK);
        check_int("pos eq bad", posture_judge(PR_GOOD_IF_EQ, 1, 1, 0, POSTURE_INFO), POSTURE_WARN);
        check_int("pos badeq hit", posture_judge(PR_BAD_IF_EQ, 1, 1, 1, POSTURE_OK), POSTURE_WARN);
        check_int("pos ge", posture_judge(PR_GOOD_IF_GE, 3, 1, 5, POSTURE_OK), POSTURE_OK);
        check_int("pos ge low", posture_judge(PR_GOOD_IF_GE, 3, 1, 2, POSTURE_OK), POSTURE_WARN);
        check_int("pos missing", posture_judge(PR_GOOD_IF_EQ, 1, 0, 0, POSTURE_WARN), POSTURE_WARN);
        check_int("pos nonzero", posture_judge(PR_GOOD_IF_NONZERO, 0, 1, 2, POSTURE_INFO), POSTURE_OK);
    }

    // --- known tool pipe names + IPv4 scope ---------------------------------------
    {
        check_int("pipe msse", ioc_pipe_known("MSSE-1234-server") != NULL, 1);
        check_int("pipe msse short", ioc_pipe_known("MSSE-123-server") == NULL, 1);
        check_int("pipe msagent", ioc_pipe_known("msagent_3f") != NULL, 1);
        check_int("pipe msagent long", ioc_pipe_known("msagent_3f1") == NULL, 1);
        check_int("pipe postex", ioc_pipe_known("postex_ab12") != NULL, 1);
        check_int("pipe psexec", ioc_pipe_known("PSEXESVC-HOST-1234-stdin") != NULL, 1);
        check_int("pipe normal", ioc_pipe_known("lsass") == NULL, 1);
        check_int("pipe status nohex", ioc_pipe_known("status_zz") == NULL, 1);
        check_str("ip loop", ioc_ip_scope("127.0.0.1"), "loopback");
        check_str("ip any", ioc_ip_scope("0.0.0.0"), "unspecified");
        check_str("ip 172", ioc_ip_scope("172.20.1.1"), "private");
        check_str("ip 172 pub", ioc_ip_scope("172.32.1.1"), "public");
        check_str("ip cgnat", ioc_ip_scope("100.100.1.1"), "cgnat");
        check_str("ip pub", ioc_ip_scope("8.8.8.8"), "public");
        check_str("ip bad", ioc_ip_scope("1.2.3"), "");
        check_str("ip bad2", ioc_ip_scope("256.1.1.1"), "");
        check_str("ip trail", ioc_ip_scope("1.2.3.4x"), "");
    }

    // --- IP Helper port fields (regression: unmasked byte swap) -----------------
    {
        check_int("port 80", (int)ioc_port_from_net(0x5000), 80);          // 00 50 -> 80
        check_int("port 443", (int)ioc_port_from_net(0xBB01), 443);        // 01 BB -> 443
        check_int("port 0x1234", (int)ioc_port_from_net(0x3412), 0x1234);
        check_int("port garbage hi", (int)ioc_port_from_net(0xDEAD5000ul), 80);
        check_int("port max", (int)ioc_port_from_net(0xFFFF), 65535);
    }

    // --- access-mask decoding per object type ------------------------------------
    {
        char r[256];
        rights_decode("Key", 0x000F003F, r, sizeof r);
        check_str("rights key all", r, "QUERY_VALUE|SET_VALUE|CREATE_SUBKEY|ENUM_SUBKEYS|NOTIFY|CREATE_LINK|DELETE|READ_CONTROL|WRITE_DAC|WRITE_OWNER");
        rights_decode("Thread", 0x0010, r, sizeof r);
        check_str("rights thread 0x10", r, "SET_CONTEXT");
        rights_decode("Process", 0x0010, r, sizeof r);
        check_str("rights process 0x10", r, "VM_READ");
        rights_decode("Mystery", 0x00120004, r, sizeof r);
        check_str("rights unknown type", r, "READ_CONTROL|SYNCHRONIZE|0x4");
        rights_decode("Job", 0x001F003F, r, sizeof r);
        check_str("rights job", r, "ASSIGN_PROCESS|SET_ATTRIBUTES|QUERY|TERMINATE|SET_SECURITY_ATTRIBUTES|IMPERSONATE|DELETE|READ_CONTROL|WRITE_DAC|WRITE_OWNER|SYNCHRONIZE");
        rights_decode("File", 0, r, sizeof r);
        check_str("rights none", r, "(none)");
        rights_decode("Key", 0x000F003F, r, 20);
        check_int("rights truncation safe", (int)strlen(r) < 20, 1);
    }

    // --- event XML field extraction ----------------------------------------------
    {
        const char *x =
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7045</EventID>"
            "<EventIDX>9</EventIDX><TimeCreated SystemTime='2024-05-01T12:34:56.1234567Z'/>"
            "<Computer>HOST</Computer></System><EventData>"
            "<Data Name='ServiceName'>Evil &amp; Co</Data>"
            "<Data Name=\"ImagePath\">C:\\x\\a.exe</Data><Data Name='Empty'></Data>"
            "</EventData></Event>";
        char v[128];
        check_int("evt id found", evt_system(x, "EventID", v, sizeof v), 1);
        check_str("evt id", v, "7045");
        evt_system(x, "Computer", v, sizeof v);
        check_str("evt computer", v, "HOST");
        check_int("evt provider selfclose", evt_system(x, "Provider", v, sizeof v), 0);
        evt_time(x, v, sizeof v);
        check_str("evt time", v, "2024-05-01 12:34:56");
        evt_data(x, "ServiceName", v, sizeof v);
        check_str("evt data entity", v, "Evil & Co");
        evt_data(x, "ImagePath", v, sizeof v);
        check_str("evt data dq", v, "C:\\x\\a.exe");
        check_int("evt data empty", evt_data(x, "Empty", v, sizeof v), 1);
        check_int("evt data missing", evt_data(x, "Nope", v, sizeof v), 0);
        check_int("evt truncated", evt_data("<Data Name='A'>abc", "A", v, sizeof v), 0);
        evt_data(x, "ServiceName", v, 5);
        check_str("evt small buf", v, "Evil");
    }

    // --- base64 + encoded PowerShell classification -------------------------------
    {
        check_str("ioc b64", ioc_classify("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG9mIGJhc2U2NA=="), "base64");
        check_str("ioc b64 short", ioc_classify("SGVsbG8gV29ybGQh"), "");
        check_str("ioc b64 word", ioc_classify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "");
        check_str("ioc b64 bad pad", ioc_classify("SGVsbG8=V29ybGQhIFRoaXMgaXMgYSB0ZXN0IG9mIGJhc2U2"), "");
        check_str("ioc b64 hex", ioc_classify("0123456789abcdef0123456789abcdef0123456789abcdef"), "");
        check_str("ioc enc", ioc_classify("powershell.exe -nop -w hidden -enc SQBFAFgA"), "encoded-cmd");
        check_str("ioc enc long", ioc_classify("pwsh -EncodedCommand SQBFAFgA"), "encoded-cmd");
        check_str("ioc ps plain", ioc_classify("powershell.exe -File x.ps1"), "");
    }

    // --- Mark-of-the-Web parsing ----------------------------------------------------
    {
        motw_info m;
        motw_parse("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://a.example/p\r\nHostUrl=https://a.example/f.exe\r\n", &m);
        check_int("motw zone", m.zone, 3);
        check_str("motw zone name", zone_name(m.zone), "internet");
        check_str("motw host", m.host, "https://a.example/f.exe");
        check_str("motw ref", m.referrer, "https://a.example/p");
        motw_parse("[ZoneTransfer]\nZoneId=2\n", &m);
        check_int("motw lf only", m.zone, 2);
        check_str("motw no host", m.host, "");
        motw_parse("garbage", &m);
        check_int("motw none", m.zone, -1);
        check_str("motw unknown zone", zone_name(9), "?");
    }

    // --- command line -> image to verify ---------------------------------------------
    {
        char im[512];
        ioc_command_image("\"C:\\Program Files\\A B\\a.exe\" -x", im, sizeof im);
        check_str("img quoted", im, "C:\\Program Files\\A B\\a.exe");
        ioc_command_image("C:\\Program Files\\A B\\a.exe -x y", im, sizeof im);
        check_str("img unquoted spaces", im, "C:\\Program Files\\A B\\a.exe");
        ioc_command_image("rundll32.exe C:\\x\\evil.dll,Run", im, sizeof im);
        check_str("img rundll", im, "C:\\x\\evil.dll");
        ioc_command_image("C:\\Windows\\system32\\regsvr32.exe /s /i:http://x C:\\x\\a.dll", im, sizeof im);
        check_str("img regsvr", im, "C:\\x\\a.dll");
        ioc_command_image("%SystemRoot%\\system32\\svchost.exe -k netsvcs", im, sizeof im);
        check_str("img env kept", im, "%SystemRoot%\\system32\\svchost.exe");
        ioc_command_image("notepad readme.txt", im, sizeof im);
        check_str("img bare", im, "notepad");
        check_int("img empty", ioc_command_image("", im, sizeof im), 0);
        ioc_command_image("autocheck autochk *", im, sizeof im);
        check_str("img autocheck", im, "autochk");
    }

    // --- UserAssist: ROT13 names + record layouts -----------------------------------
    {
        char nm[64] = "P:\\Jvaqbjf\\abgrcnq.rkr";
        rot13_inplace(nm);
        check_str("ua rot13", nm, "C:\\Windows\\notepad.exe");
        unsigned char r7[72];
        memset(r7, 0, sizeof r7);
        r7[4] = 7; r7[60] = 0x55; r7[67] = 0x01;
        uint32_t runs = 0; uint64_t last = 0;
        check_int("ua win7", userassist_record(r7, 72, &runs, &last), 1);
        check_int("ua win7 runs", (int)runs, 7);
        check_int("ua win7 last", (int)(last == 0x0100000000000055ull), 1);
        unsigned char rx[16];
        memset(rx, 0, sizeof rx);
        rx[4] = 9; rx[8] = 0x11;
        userassist_record(rx, 16, &runs, &last);
        check_int("ua xp runs-5", (int)runs, 4);
        check_int("ua bad size", userassist_record(rx, 30, &runs, &last), 0);
    }

    // --- MRU list helpers -------------------------------------------------------------
    {
        unsigned char ex[16] = { 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF };
        uint32_t ord[8];
        check_int("mruex count", (int)mrulistex_order(ex, sizeof ex, ord, 8), 3);
        check_int("mruex first", (int)ord[0], 2);
        check_int("mruex trunc", (int)mrulistex_order(ex, 6, ord, 8), 1);
        char cmd[64] = "powershell -enc AAAA\\1";
        runmru_clean(cmd);
        check_str("runmru strip", cmd, "powershell -enc AAAA");
        char cmd2[64] = "cmd";
        runmru_clean(cmd2);
        check_str("runmru noop", cmd2, "cmd");
        unsigned char rd[] = { 'a', 0, '.', 0, 't', 0, 'x', 0, 't', 0, 0, 0, 0x14, 0x00 };
        char nm[32];
        check_int("recentdocs ok", recentdocs_name(rd, sizeof rd, nm, sizeof nm), 1);
        check_str("recentdocs name", nm, "a.txt");
        check_int("recentdocs no nul", recentdocs_name(rd, 8, nm, sizeof nm), 0);
    }

    // --- json_str / csv_str: capture stdout to a temp file and read it back ---
    // The emitters write to stdout, so we redirect it, run every case separated
    // by a newline, then reopen the file and compare line by line.
    const char *tmp = "test_util_out.tmp";
    if (freopen(tmp, "w", stdout) == NULL) {
        fprintf(stderr, "FAIL: cannot redirect stdout\n");
        return 2;
    }
    json_str("abc");            putchar('\n');   // 1
    json_str("a\"b");           putchar('\n');   // 2  quote escaped
    json_str("x\ty");           putchar('\n');   // 3  tab escaped
    json_str("back\\slash");    putchar('\n');   // 4  backslash escaped
    csv_str("plain");           putchar('\n');   // 5  no quoting
    csv_str("a,b");             putchar('\n');   // 6  comma -> quoted
    csv_str("he\"llo");         putchar('\n');   // 7  quote -> quoted + doubled
    csv_str("line\nbreak");     putchar('\n');   // 8  newline -> quoted
    fflush(stdout);
    fclose(stdout);

    FILE *r = fopen(tmp, "r");
    if (r == NULL) {
        fprintf(stderr, "FAIL: cannot reopen capture file\n");
        return 2;
    }
    static const char *expect[] = {
        "\"abc\"",
        "\"a\\\"b\"",
        "\"x\\ty\"",
        "\"back\\\\slash\"",
        "plain",
        "\"a,b\"",
        "\"he\"\"llo\"",
        "\"line",          /* the embedded newline splits this case over 2 lines */
        "break\"",
    };
    size_t n = sizeof expect / sizeof expect[0];
    char line[256];
    size_t i = 0;
    for (; i < n && fgets(line, sizeof line, r) != NULL; i++) {
        size_t L = strlen(line);
        if (L > 0 && line[L - 1] == '\n') { line[L - 1] = '\0'; }
        char label[32];
        snprintf(label, sizeof label, "emit[%zu]", i);
        check_str(label, line, expect[i]);
    }
    fclose(r);
    remove(tmp);
    if (i != n) {
        fprintf(stderr, "FAIL: expected %zu output lines, read %zu\n", n, i);
        failures++;
    }

    fprintf(stderr, "\n%s (%d failure%s)\n",
            failures == 0 ? "ALL PASSED" : "FAILED", failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
