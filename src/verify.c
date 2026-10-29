// winspect verify - consistency checks that compare two sources of one fact
//
// The idea in one line: Windows often exposes the same truth through more than
// one window, and on a healthy process those windows agree. When they disagree,
// something interesting is going on. This command runs six cheap checks, each
// reusing data the other commands already know how to read:
//
//   1. ntdll stub check    - the first bytes of a native stub in THIS process vs
//                            in the target. They should be identical (ntdll maps
//                            at the same address in every process this boot). A
//                            difference means the target's stub was patched, i.e.
//                            an inline hook (an EDR, or injected code).
//   2. masquerade check    - the image path the process reports in its own PEB vs
//                            the real path the kernel knows (QueryFullProcessImage-
//                            Name). The PEB is user-writable, so a process can lie
//                            about what it is; the kernel value cannot be faked
//                            the same way. Disagreement = possible masquerading.
//   3. hidden module check - the loaded-module list from the PEB loader data vs an
//                            independent enumeration (EnumProcessModulesEx). A
//                            module in one but not the other suggests the loader
//                            list was tampered with to hide a module.
//   4. private exec check  - committed, private, executable memory with no module
//                            behind it; sharpened by RWX and "is there a PE header".
//   5. image tamper check  - the main image's executable sections in memory vs the
//                            file on disk, after undoing relocations. A mismatch is
//                            the shape of process hollowing or an in-memory patch.
//                            (checks 5 and 6 live in detect.c, shared with triage.)
//   6. IAT integrity check - every resolved import should land inside some loaded
//                            module; a slot pointing into unbacked memory is a hook.
//
// None of this needs a kernel driver; it is all user-mode reads. Where a check
// cannot see the whole truth (noted inline) it says so rather than over-claiming.

#include "verify.h"
#include "jsonutil.h"
#include "detect.h"     // shared image-tamper / IAT-hook detection

#include <windows.h>
#include <winternl.h>
#include <psapi.h>      // EnumProcessModulesEx
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>     // uintptr_t
#include <string.h>     // memcpy, memcmp, strcmp

#define MAX_MODS 2048

// Bounded, all-or-nothing ReadProcessMemory wrapper (same idea as inspect.c).
static int rpm(HANDLE h, const void *remote, void *local, SIZE_T n)
{
    SIZE_T got = 0;
    return (ReadProcessMemory(h, remote, local, n, &got) && got == n) ? 1 : 0;
}

// Reads a UNICODE_STRING's text out of the target into a UTF-8 buffer. The
// header is already local; only its Buffer field points into the target.
static void read_ustr(HANDLE h, const UNICODE_STRING *us, char *out, size_t outsz)
{
    out[0] = '\0';
    if (us->Length == 0 || us->Buffer == NULL) {
        return;
    }
    WCHAR wbuf[1024];
    USHORT bytes = us->Length;
    USHORT cap = (USHORT)(sizeof wbuf - sizeof(WCHAR));
    if (bytes > cap) {
        bytes = cap;
    }
    if (!rpm(h, us->Buffer, wbuf, bytes)) {
        return;
    }
    wbuf[bytes / sizeof(WCHAR)] = L'\0';
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, (int)outsz, NULL, NULL);
}

// --- Check 1: ntdll stub bytes (this process vs the target) -------------------
// We compare a handful of frequently-hooked native stubs. Because ntdll is
// mapped at the same base in every process for a given boot, a stub's address in
// our process is also valid in the target, so we can read both and compare.
static int check_ntdll(HANDLE h, int json)
{
    static const char *names[] = {
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtCreateThreadEx",
        "NtMapViewOfSection",
    };
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        if (json) { fputs("\"ntdll_stubs\":{\"warnings\":0,\"findings\":[]}", stdout); }
        else      { puts("  ntdll: cannot locate ntdll in this process"); }
        return 0;
    }

    if (json) { fputs("\"ntdll_stubs\":{\"findings\":[", stdout); }
    int warnings = 0;
    int first = 1;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        FARPROC fn = GetProcAddress(ntdll, names[i]);
        if (fn == NULL) {
            continue;   // not present on this Windows version; skip quietly
        }
        // Turn the function pointer into an object pointer without the
        // function->object cast the standard forbids (copy the bits via an int).
        uintptr_t fn_addr;
        memcpy(&fn_addr, &fn, sizeof fn_addr);
        const void *fn_ptr = (const void *)fn_addr;

        unsigned char local[8], remote[8];
        memcpy(local, fn_ptr, sizeof local);             // our own ntdll bytes
        int readable = rpm(h, fn_ptr, remote, sizeof remote);
        int patched = readable && (memcmp(local, remote, sizeof local) != 0);
        if (patched) {
            warnings++;
        }

        if (json) {
            char ours[24], tgt[24];
            snprintf(ours, sizeof ours, "%02X%02X%02X%02X%02X%02X%02X%02X",
                     local[0], local[1], local[2], local[3],
                     local[4], local[5], local[6], local[7]);
            if (readable) {
                snprintf(tgt, sizeof tgt, "%02X%02X%02X%02X%02X%02X%02X%02X",
                         remote[0], remote[1], remote[2], remote[3],
                         remote[4], remote[5], remote[6], remote[7]);
            } else {
                tgt[0] = '\0';
            }
            printf("%s{\"function\":", first ? "" : ",");
            json_str(names[i]);
            printf(",\"status\":\"%s\",\"ours\":",
                   !readable ? "unreadable" : (patched ? "patched" : "clean"));
            json_str(ours);
            fputs(",\"target\":", stdout);
            if (readable) { json_str(tgt); } else { fputs("null", stdout); }
            putchar('}');
            first = 0;
            continue;
        }

        if (!readable) {
            printf("  ntdll: %-26s (cannot read target)\n", names[i]);
        } else if (!patched) {
            printf("  [OK]   %-26s clean\n", names[i]);
        } else {
            printf("  [WARN] %-26s differs -> target stub patched (inline hook?)\n", names[i]);
            printf("           ours   : %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   local[0], local[1], local[2], local[3], local[4], local[5], local[6], local[7]);
            printf("           target : %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   remote[0], remote[1], remote[2], remote[3], remote[4], remote[5], remote[6], remote[7]);
        }
    }
    if (json) { printf("],\"warnings\":%d}", warnings); }
    return warnings;
}

// --- Check 2: PEB image path vs the kernel's real path ------------------------
static int check_masquerade(HANDLE h, int json)
{
    // Kernel's answer: the real backing file. This cannot be spoofed from
    // user mode the way the PEB field can.
    char real[MAX_PATH];
    DWORD rlen = sizeof real;
    if (!QueryFullProcessImageNameA(h, 0, real, &rlen)) {
        if (json) { fputs("\"masquerade\":{\"warnings\":0,\"error\":\"cannot get real image path\"}", stdout); }
        else      { puts("  masquerade: cannot get real image path"); }
        return 0;
    }

    // PEB's answer: what the process says about itself. Walk to
    // ProcessParameters->ImagePathName and read it.
    PROCESS_BASIC_INFORMATION pbi;
    if (NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof pbi, NULL) < 0 ||
        pbi.PebBaseAddress == NULL) {
        if (json) { fputs("\"masquerade\":{\"warnings\":0,\"error\":\"cannot read PEB\"}", stdout); }
        else      { puts("  masquerade: cannot read PEB"); }
        return 0;
    }
    PEB peb;
    char peb_path[MAX_PATH * 2] = "";
    if (rpm(h, pbi.PebBaseAddress, &peb, sizeof peb) && peb.ProcessParameters != NULL) {
        RTL_USER_PROCESS_PARAMETERS params;
        if (rpm(h, peb.ProcessParameters, &params, sizeof params)) {
            read_ustr(h, &params.ImagePathName, peb_path, sizeof peb_path);
        }
    }

    // A mismatch is a hint to look closer, not a hard verdict (the PEB sometimes
    // uses \??\ or native forms); compare case-insensitively.
    int mismatch = (peb_path[0] && _stricmp(real, peb_path) != 0);

    if (json) {
        fputs("\"masquerade\":{\"real_path\":", stdout); json_str(real);
        fputs(",\"peb_path\":", stdout);                json_str(peb_path);
        printf(",\"match\":%s,\"warnings\":%d}", mismatch ? "false" : "true", mismatch ? 1 : 0);
        return mismatch ? 1 : 0;
    }

    printf("  real path (kernel): %s\n", real);
    printf("  PEB ImagePathName : %s\n", peb_path[0] ? peb_path : "(empty)");
    if (mismatch) {
        puts("  [WARN] paths differ -> process may be lying about its identity");
        return 1;
    }
    puts("  [OK]   PEB path matches the kernel path");
    return 0;
}

// Collects module base addresses the loader lists in the PEB (InMemoryOrder).
static unsigned collect_ldr(HANDLE h, uintptr_t *out, unsigned cap)
{
    PROCESS_BASIC_INFORMATION pbi;
    if (NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof pbi, NULL) < 0) {
        return 0;
    }
    PEB peb;
    if (!rpm(h, pbi.PebBaseAddress, &peb, sizeof peb) || peb.Ldr == NULL) {
        return 0;
    }
    PEB_LDR_DATA ldr;
    if (!rpm(h, peb.Ldr, &ldr, sizeof ldr)) {
        return 0;
    }
    const BYTE *head = (const BYTE *)peb.Ldr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);
    LIST_ENTRY node = ldr.InMemoryOrderModuleList;
    unsigned n = 0;
    for (unsigned i = 0; i < cap && (const BYTE *)node.Flink != head; i++) {
        const BYTE *entry_addr = (const BYTE *)node.Flink -
                                 offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        LDR_DATA_TABLE_ENTRY e;
        if (!rpm(h, entry_addr, &e, sizeof e)) {
            break;
        }
        out[n++] = (uintptr_t)e.DllBase;
        node = e.InMemoryOrderLinks;
    }
    return n;
}

// --- Check 3: loader list vs an independent module enumeration ----------------
static int check_hidden_modules(HANDLE h, int json)
{
    uintptr_t ldr[MAX_MODS];
    unsigned nldr = collect_ldr(h, ldr, MAX_MODS);

    // Independent-ish source. EnumProcessModulesEx ultimately reads loader data
    // too, so on its own it rarely contradicts the PEB walk; it mainly catches
    // cases where one path is confused and the other is not. A stronger check
    // would scan committed image regions with VirtualQueryEx - noted for a later
    // pass so we don't over-claim what this one proves.
    HMODULE mods[MAX_MODS];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(h, mods, sizeof mods, &needed, LIST_MODULES_ALL)) {
        if (json) { fputs("\"hidden_modules\":{\"warnings\":0,\"error\":\"EnumProcessModulesEx failed\"}", stdout); }
        else      { puts("  modules: EnumProcessModulesEx failed"); }
        return 0;
    }
    unsigned nenum = needed / sizeof(HMODULE);
    if (nenum > MAX_MODS) {
        nenum = MAX_MODS;
    }

    if (json) {
        printf("\"hidden_modules\":{\"loader_count\":%u,\"enum_count\":%u,\"findings\":[",
               nldr, nenum);
    } else {
        printf("  loader list: %u modules, enumeration: %u modules\n", nldr, nenum);
    }

    int warnings = 0;
    int first = 1;
    // Any loader entry missing from the enumeration?
    for (unsigned i = 0; i < nldr; i++) {
        int found = 0;
        for (unsigned j = 0; j < nenum; j++) {
            if ((uintptr_t)mods[j] == ldr[i]) { found = 1; break; }
        }
        if (!found) {
            warnings++;
            if (json) {
                printf("%s{\"base\":\"0x%016llX\",\"issue\":\"missing_from_enumeration\"}",
                       first ? "" : ",", (unsigned long long)ldr[i]);
                first = 0;
            } else {
                printf("  [WARN] base 0x%016llX in loader list but not in enumeration\n",
                       (unsigned long long)ldr[i]);
            }
        }
    }
    // Any enumerated module missing from the loader list? (the classic "unlinked
    // from the loader list to hide" shape)
    for (unsigned j = 0; j < nenum; j++) {
        int found = 0;
        for (unsigned i = 0; i < nldr; i++) {
            if ((uintptr_t)mods[j] == ldr[i]) { found = 1; break; }
        }
        if (!found) {
            warnings++;
            if (json) {
                printf("%s{\"base\":\"0x%016llX\",\"issue\":\"missing_from_loader\"}",
                       first ? "" : ",", (unsigned long long)(uintptr_t)mods[j]);
                first = 0;
            } else {
                printf("  [WARN] base 0x%016llX enumerated but missing from loader list\n",
                       (unsigned long long)(uintptr_t)mods[j]);
            }
        }
    }
    if (json) {
        printf("],\"warnings\":%d}", warnings);
    } else if (warnings == 0) {
        puts("  [OK]   loader list and enumeration agree");
    }
    return warnings;
}

// --- Check 4: private executable memory (the truly independent source) --------
// Legitimate code lives in MEM_IMAGE regions backed by a real module on disk.
// A committed, PRIVATE, executable region is code with no backing file - the
// shape of manually mapped or injected code. Unlike the module-list check, this
// reads the raw page tables via VirtualQueryEx, so it does not depend on the
// loader data a stealthy module might have tampered with.
static int check_private_exec(HANDLE h, int json)
{
    if (json) { fputs("\"private_exec\":{\"regions\":[", stdout); }
    uintptr_t addr = 0;
    int flagged = 0;
    int first = 1;
    for (unsigned guard = 0; guard < 1000000; guard++) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof mbi) != sizeof mbi) {
            break;
        }
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) {
            break;
        }
        addr = next;

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            DWORD base = mbi.Protect & 0xFF;
            int exec = (base & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            if (exec) {
                flagged++;
                // Two extra signals that sharpen "private+executable":
                //   - RWX (writable AND executable at once): legit code almost
                //     never needs this; it is the classic shellcode-staging shape.
                //   - an "MZ" at the top of the region: a whole PE mapped into
                //     private memory with no file behind it = a reflectively /
                //     manually loaded module.
                int rwx = (base & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                unsigned char magic[2] = { 0, 0 };
                SIZE_T got = 0;
                int mz = (ReadProcessMemory(h, mbi.BaseAddress, magic, 2, &got) && got == 2 &&
                          magic[0] == 'M' && magic[1] == 'Z');
                if (json) {
                    printf("%s{\"base\":\"0x%016llX\",\"size\":%llu,\"protect\":\"0x%lX\","
                           "\"rwx\":%s,\"pe_header\":%s}",
                           first ? "" : ",",
                           (unsigned long long)(uintptr_t)mbi.BaseAddress,
                           (unsigned long long)mbi.RegionSize,
                           (unsigned long)mbi.Protect,
                           rwx ? "true" : "false", mz ? "true" : "false");
                    first = 0;
                } else {
                    printf("  [WARN] private executable region @ 0x%016llX  %llu bytes  prot 0x%lX%s%s\n",
                           (unsigned long long)(uintptr_t)mbi.BaseAddress,
                           (unsigned long long)mbi.RegionSize,
                           (unsigned long)mbi.Protect,
                           rwx ? "  RWX" : "",
                           mz ? "  <= PE header (reflectively loaded module?)" : "");
                }
            }
        }
    }
    if (json) {
        printf("],\"warnings\":%d}", flagged);
    } else if (flagged == 0) {
        puts("  [OK]   no private executable regions");
    }
    return flagged;
}

// --- Check 5: image tamper (disk vs memory, relocation-aware) -----------------
// Delegates the heavy comparison to detect_image_tamper and renders its result.
static int check_image_tamper(HANDLE h, int json)
{
    struct tamper_result t;
    detect_image_tamper(h, &t);

    if (json) {
        fputs("\"image_tamper\":{", stdout);
        printf("\"checked\":%s,\"modified_sections\":%d",
               t.checked ? "true" : "false", t.modified_sections);
        if (t.modified_sections > 0) {
            fputs(",\"first_section\":", stdout); json_str(t.first_section);
            printf(",\"diff_bytes\":%u,\"first_diff_rva\":\"0x%08lX\"",
                   t.diff_bytes, (unsigned long)t.first_diff_rva);
        }
        if (!t.checked && t.note[0]) {
            fputs(",\"note\":", stdout); json_str(t.note);
        }
        printf(",\"warnings\":%d}", t.modified_sections);
        return t.modified_sections;
    }

    if (!t.checked) {
        printf("  (could not compare: %s)\n", t.note[0] ? t.note : "unknown");
        return 0;
    }
    if (t.modified_sections == 0) {
        puts("  [OK]   image in memory matches the file on disk");
    } else {
        printf("  [WARN] %d executable section(s) differ from disk "
               "(hollowing / patched code)\n", t.modified_sections);
        printf("         first: section %s, %u byte(s) changed, from RVA 0x%08lX\n",
               t.first_section, t.diff_bytes, (unsigned long)t.first_diff_rva);
    }
    return t.modified_sections;
}

// --- Check 6: IAT entries pointing into unbacked memory (hook) ----------------
static int check_iat_hooks(HANDLE h, int json)
{
    struct iathook_result r;
    detect_iat_hooks(h, &r);

    if (json) {
        fputs("\"iat_hooks\":{", stdout);
        printf("\"checked\":%s,\"hooked_entries\":%d",
               r.checked ? "true" : "false", r.hooked_entries);
        if (r.hooked_entries > 0) {
            fputs(",\"first_dll\":", stdout); json_str(r.first_dll);
            printf(",\"first_target\":\"0x%016llX\"", (unsigned long long)r.first_target);
        }
        if (!r.checked && r.note[0]) {
            fputs(",\"note\":", stdout); json_str(r.note);
        }
        printf(",\"warnings\":%d}", r.hooked_entries);
        return r.hooked_entries;
    }

    if (!r.checked) {
        printf("  (could not walk the IAT: %s)\n", r.note[0] ? r.note : "unknown");
        return 0;
    }
    if (r.hooked_entries == 0) {
        puts("  [OK]   every IAT entry points into a loaded module");
    } else {
        printf("  [WARN] %d IAT entry(ies) point into unbacked memory (hook/trampoline)\n",
               r.hooked_entries);
        printf("         first: %s -> 0x%016llX\n",
               r.first_dll[0] ? r.first_dll : "(unnamed)",
               (unsigned long long)r.first_target);
    }
    return r.hooked_entries;
}

// --- Check 7: thread start addresses (injection / hijack) ---------------------
static int check_threads(HANDLE h, DWORD pid, int json)
{
    struct thread_result t;
    detect_unbacked_threads(h, pid, &t);

    if (json) {
        fputs("\"thread_start\":{", stdout);
        printf("\"checked\":%s,\"threads\":%d,\"unbacked\":%d",
               t.checked ? "true" : "false", t.threads, t.unbacked);
        if (t.unbacked > 0) {
            printf(",\"first_tid\":%lu,\"first_start\":\"0x%016llX\"",
                   (unsigned long)t.first_tid, (unsigned long long)t.first_start);
        }
        if (!t.checked && t.note[0]) {
            fputs(",\"note\":", stdout); json_str(t.note);
        }
        printf(",\"warnings\":%d}", t.unbacked);
        return t.unbacked;
    }

    if (!t.checked) {
        printf("  (could not enumerate threads: %s)\n", t.note[0] ? t.note : "unknown");
        return 0;
    }
    if (t.unbacked == 0) {
        printf("  [OK]   all %d thread start addresses point into a module\n", t.threads);
    } else {
        printf("  [WARN] %d of %d thread(s) start outside any module (injected thread?)\n",
               t.unbacked, t.threads);
        printf("         first: tid %lu starts at 0x%016llX\n",
               (unsigned long)t.first_tid, (unsigned long long)t.first_start);
    }
    return t.unbacked;
}

// --- Check 8: section permissions (memory vs header) --------------------------
static int check_section_perms(HANDLE h, int json)
{
    struct secperm_result s;
    detect_section_perms(h, &s);

    if (json) {
        fputs("\"section_perms\":{", stdout);
        printf("\"checked\":%s,\"mismatches\":%d", s.checked ? "true" : "false", s.mismatches);
        if (s.mismatches > 0) {
            fputs(",\"first_section\":", stdout); json_str(s.first_section);
            fputs(",\"header\":", stdout);        json_str(s.first_disk);
            fputs(",\"memory\":", stdout);         json_str(s.first_mem);
        }
        if (!s.checked && s.note[0]) {
            fputs(",\"note\":", stdout); json_str(s.note);
        }
        printf(",\"warnings\":%d}", s.mismatches);
        return s.mismatches;
    }

    if (!s.checked) {
        printf("  (could not read sections: %s)\n", s.note[0] ? s.note : "unknown");
        return 0;
    }
    if (s.mismatches == 0) {
        puts("  [OK]   section permissions in memory match the headers");
    } else {
        printf("  [WARN] %d section(s) more permissive in memory than on disk "
               "(patched/staged code?)\n", s.mismatches);
        printf("         first: %s header=%s memory=%s\n",
               s.first_section, s.first_disk, s.first_mem);
    }
    return s.mismatches;
}

int cmd_verify(int argc, char **argv)
{
    const char *pid_arg = NULL;
    int json = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) json = 1;
        else if (pid_arg == NULL)           pid_arg = argv[a];
        else {
            fprintf(stderr, "verify: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (pid_arg == NULL) {
        fputs("usage: winspect verify <pid> [--json]\n", stderr);
        return 1;
    }
    char *end = NULL;
    unsigned long pid = strtoul(pid_arg, &end, 10);
    if (end == pid_arg || *end != '\0' || pid == 0) {
        fprintf(stderr, "verify: '%s' is not a valid pid\n", pid_arg);
        return 1;
    }

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h == NULL) {
        DWORD err = GetLastError();
        fprintf(stderr, "verify: cannot open pid %lu (error %lu)\n", pid, (unsigned long)err);
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "        (try an elevated console; a Medium process can't read a High one)\n");
        }
        return 1;
    }

    if (json) {
        int total = 0;
        printf("{\"pid\":%lu,\"checks\":{", pid);
        total += check_ntdll(h, 1);          putchar(',');
        total += check_masquerade(h, 1);     putchar(',');
        total += check_hidden_modules(h, 1); putchar(',');
        total += check_private_exec(h, 1);   putchar(',');
        total += check_image_tamper(h, 1);   putchar(',');
        total += check_iat_hooks(h, 1);      putchar(',');
        total += check_threads(h, (DWORD)pid, 1); putchar(',');
        total += check_section_perms(h, 1);
        printf("},\"total_warnings\":%d}\n", total);
        CloseHandle(h);
        return 0;
    }

    printf("verify  pid %lu\n\n", pid);

    int total = 0;
    puts("1) ntdll stub integrity (this process vs target)");
    total += check_ntdll(h, 0);
    putchar('\n');

    puts("2) image path masquerade (PEB vs kernel)");
    total += check_masquerade(h, 0);
    putchar('\n');

    puts("3) hidden modules (loader list vs enumeration)");
    total += check_hidden_modules(h, 0);
    putchar('\n');

    puts("4) private executable memory (page tables, independent of loader data)");
    total += check_private_exec(h, 0);
    putchar('\n');

    puts("5) image tamper (memory vs disk, relocation-aware)");
    total += check_image_tamper(h, 0);
    putchar('\n');

    puts("6) IAT integrity (imports resolve into loaded modules)");
    total += check_iat_hooks(h, 0);
    putchar('\n');

    puts("7) thread start addresses (threads begin inside a module)");
    total += check_threads(h, (DWORD)pid, 0);
    putchar('\n');

    puts("8) section permissions (memory vs on-disk headers)");
    total += check_section_perms(h, 0);
    putchar('\n');

    if (total == 0) {
        puts("result: no inconsistencies found");
    } else {
        printf("result: %d warning(s) - worth a closer look\n", total);
    }

    CloseHandle(h);
    return 0;
}
