// winspect inspect - live process PEB reader
//
// The PEB (Process Environment Block) is a user-mode structure the loader keeps
// for every process. It is the source of much of what Process Explorer shows:
// the command line, the image path, the environment, the list of loaded modules,
// and the BeingDebugged flag. We read it the honest way: open the target, ask
// the kernel where its PEB lives, then copy bytes out of the target's address
// space with ReadProcessMemory.
//
// The walk is: OpenProcess -> NtQueryInformationProcess(ProcessBasicInformation)
//   -> PEB.ProcessParameters (-> CommandLine, ImagePathName, Environment)
//   -> PEB.Ldr (-> InMemoryOrderModuleList -> each LDR_DATA_TABLE_ENTRY)
//
// Important subtlety: every pointer inside these structures (UNICODE_STRING.Buffer,
// the list links, the module entries) points into the TARGET process, not ours.
// So each one needs its own ReadProcessMemory; we can never just dereference it.

// Ask for a Windows 10-era API surface so GetProcessMitigationPolicy and its
// policy structs are declared (they are guarded by _WIN32_WINNT >= Win8).
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "pidarg.h"
#include "inspect.h"
#include "jsonutil.h"

#include <windows.h>
#include <winternl.h>   // PEB, PROCESS_BASIC_INFORMATION, NtQueryInformationProcess
#include <stdio.h>
#include <stdlib.h>     // strtoul
#include <stddef.h>     // offsetof
#include <string.h>     // strcmp

// winternl.h gives us the public, partially-documented layout of these structs.
// The fields we use (BeingDebugged, Ldr, ProcessParameters, ImagePathName,
// CommandLine, InMemoryOrderModuleList, DllBase, FullDllName) all sit at their
// real offsets there, so we don't need to hand-roll the structs. The only two
// things winternl.h hides are:
//   - ImageBaseAddress: it is Reserved3[1] in winternl's PEB (offset 0x10 on x64)
//   - Environment pointer: it sits at offset 0x80 inside RTL_USER_PROCESS_PARAMETERS,
//     past the end of winternl's declared struct, so we read it by raw offset.
#define PEB_IMAGEBASE_RESERVED3_INDEX 1
#define PARAMS_ENVIRONMENT_OFFSET     0x80

// A bounded, all-or-nothing wrapper around ReadProcessMemory.
// ReadProcessMemory fails (returns FALSE) if ANY byte of the range is not
// readable, which is exactly what we want: a partial read of a struct would
// leave us interpreting garbage. Returns 1 on a complete read, 0 otherwise.
static int rpm(HANDLE h, const void *remote, void *local, SIZE_T n)
{
    SIZE_T got = 0;
    if (!ReadProcessMemory(h, remote, local, n, &got) || got != n) {
        return 0;
    }
    return 1;
}

// Reads a UNICODE_STRING's text out of the target. The UNICODE_STRING header
// (Length in bytes, MaximumLength, Buffer pointer) has already been copied into
// our address space by the caller; only its Buffer field still points into the
// target, so that is the pointer we follow here.
//
// UNICODE_STRING is UTF-16 and NOT guaranteed to be NUL-terminated (Length is a
// byte count), so we read exactly Length bytes and convert to UTF-8 ourselves.
static void read_ustr(HANDLE h, const UNICODE_STRING *us, char *out, size_t outsz)
{
    out[0] = '\0';
    if (us->Length == 0 || us->Buffer == NULL) {
        return;
    }
    USHORT bytes = us->Length;
    WCHAR wbuf[1024];
    USHORT cap = (USHORT)(sizeof wbuf - sizeof(WCHAR));   // leave room to NUL-terminate
    if (bytes > cap) {
        bytes = cap;
    }
    if (!rpm(h, us->Buffer, wbuf, bytes)) {
        snprintf(out, outsz, "(unreadable @ %p)", (void *)us->Buffer);
        return;
    }
    wbuf[bytes / sizeof(WCHAR)] = L'\0';
    // Convert UTF-16 -> UTF-8/ANSI for printing. If conversion fails we leave
    // out empty rather than print undefined bytes.
    if (WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, (int)outsz, NULL, NULL) == 0) {
        snprintf(out, outsz, "(conversion failed)");
    }
}

// Opens the target with the two rights we need and nothing more:
//   PROCESS_QUERY_INFORMATION - to call NtQueryInformationProcess
//   PROCESS_VM_READ           - to call ReadProcessMemory
// Least privilege is deliberate: we never ask for write or terminate rights.
static HANDLE open_target(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (h == NULL) {
        DWORD err = GetLastError();
        fprintf(stderr, "inspect: cannot open pid %lu (error %lu)\n",
                (unsigned long)pid, (unsigned long)err);
        // ERROR_ACCESS_DENIED is the common one and almost always means a
        // privilege/integrity boundary, not a bug: a Medium-integrity process
        // cannot read a High-integrity (elevated) or protected one. Say so.
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "         access denied: the target likely runs at a higher integrity "
                            "level (try an elevated console), or it is a protected process.\n");
        }
    }
    return h;
}

// Prints the loaded-module list by walking PEB.Ldr.InMemoryOrderModuleList.
// A Windows doubly-linked list is a ring of LIST_ENTRY nodes. The list head
// lives inside PEB_LDR_DATA; each module's node is the InMemoryOrderLinks field
// *embedded inside* an LDR_DATA_TABLE_ENTRY. So to go from a node back to the
// module record we subtract the offset of that field (the CONTAINING_RECORD
// idiom). We stop when we loop back to the head, or hit our safety cap.
static void print_modules(HANDLE h, const PEB *peb_local, int json)
{
    // peb_local->Ldr is a pointer into the TARGET; read the PEB_LDR_DATA it names.
    PEB_LDR_DATA ldr;
    if (!rpm(h, peb_local->Ldr, &ldr, sizeof ldr)) {
        if (json) { fputs(",\"modules\":[]", stdout); }
        else      { puts("  (cannot read PEB_LDR_DATA)"); }
        return;
    }

    if (json) { fputs(",\"modules\":[", stdout); }

    // The head node sits at this address inside the target's PEB_LDR_DATA.
    // We compute it from Ldr + offsetof so we recognise when the ring closes.
    const BYTE *head = (const BYTE *)peb_local->Ldr +
                       offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);
    LIST_ENTRY node = ldr.InMemoryOrderModuleList;   // first real node (Flink)

    int first = 1;
    for (unsigned i = 0; i < 1024; i++) {
        if ((const BYTE *)node.Flink == head) {
            break;   // walked the whole ring back to the head
        }

        // node.Flink points at the InMemoryOrderLinks field of an entry; step
        // back to the start of the LDR_DATA_TABLE_ENTRY to read the whole record.
        const BYTE *entry_addr = (const BYTE *)node.Flink -
                                 offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        LDR_DATA_TABLE_ENTRY entry;
        if (!rpm(h, entry_addr, &entry, sizeof entry)) {
            if (!json) { puts("  (module list truncated: unreadable entry)"); }
            break;
        }

        char name[1024];
        read_ustr(h, &entry.FullDllName, name, sizeof name);
        if (json) {
            char base[32];
            snprintf(base, sizeof base, "0x%016llX",
                     (unsigned long long)(uintptr_t)entry.DllBase);
            printf("%s{\"base\":\"%s\",\"name\":", first ? "" : ",", base);
            json_str(name);
            putchar('}');
            first = 0;
        } else {
            printf("  0x%016llX  %s\n",
                   (unsigned long long)(uintptr_t)entry.DllBase,
                   name[0] ? name : "(no name)");
        }

        // Advance to the next node. We already copied this entry's links.
        node = entry.InMemoryOrderLinks;
    }

    if (json) { putchar(']'); }
}

// Best-effort dump of the environment block. It is a single buffer of
// back-to-back UTF-16 "NAME=VALUE\0" strings, ending with one extra NUL.
// Its exact length is not reliably exposed, so we read as large a chunk as the
// target will give us and scan for the double-NUL terminator.
static void print_environment(HANDLE h, const BYTE *params_remote, int json)
{
    // Environment pointer lives past winternl's struct, so read it by raw offset.
    PVOID env_ptr = NULL;
    if (!rpm(h, params_remote + PARAMS_ENVIRONMENT_OFFSET, &env_ptr, sizeof env_ptr) ||
        env_ptr == NULL) {
        if (json) { fputs(",\"environment\":[]", stdout); }
        else      { puts("  (no environment pointer)"); }
        return;
    }

    // Try progressively smaller reads: a full environment can be several KB, but
    // we must not fail just because the tail page isn't mapped contiguously.
    static WCHAR buf[16384];
    SIZE_T want = sizeof buf - sizeof(WCHAR);
    SIZE_T got = 0;
    while (want >= 512) {
        if (ReadProcessMemory(h, env_ptr, buf, want, &got) && got > 0) {
            break;
        }
        want /= 2;
    }
    if (got == 0) {
        if (json) { fputs(",\"environment\":[]", stdout); }
        else      { puts("  (environment unreadable)"); }
        return;
    }
    size_t wcount = got / sizeof(WCHAR);
    buf[wcount] = L'\0';

    if (json) { fputs(",\"environment\":[", stdout); }

    // Walk the double-NUL-terminated list of wide strings.
    unsigned printed = 0;
    int first = 1;
    for (size_t i = 0; i < wcount && buf[i] != L'\0'; ) {
        char line[2048];
        if (WideCharToMultiByte(CP_UTF8, 0, &buf[i], -1, line, sizeof line, NULL, NULL) > 0) {
            if (json) {
                if (!first) { putchar(','); }
                json_str(line);
                first = 0;
            } else {
                printf("  %s\n", line);
            }
        }
        // Skip to the NUL that ends this entry, then one past it.
        while (i < wcount && buf[i] != L'\0') {
            i++;
        }
        i++;
        if (++printed >= 256) {   // cap output on absurdly large environments
            if (!json) { puts("  ... (truncated)"); }
            break;
        }
    }

    if (json) { putchar(']'); }
}

// Prints the process's runtime exploit mitigations. Unlike the pe command's
// build-time view (DllCharacteristics on disk), these are what the kernel is
// actually enforcing on the LIVE process right now, which can differ (a policy
// can be tightened at launch). GetProcessMitigationPolicy needs the handle to
// have PROCESS_QUERY_INFORMATION, which open_target already requested.
static void print_mitigations(HANDLE h, int json)
{
    if (json) { fputs(",\"mitigations\":{", stdout); }
    else      { puts("Mitigation policies (live)"); }
    int first = 1;

    PROCESS_MITIGATION_DEP_POLICY dep;
    ZeroMemory(&dep, sizeof dep);
    if (GetProcessMitigationPolicy(h, ProcessDEPPolicy, &dep, sizeof dep)) {
        if (json) {
            printf("%s\"dep\":{\"enabled\":%s,\"permanent\":%s}",
                   first ? "" : ",", dep.Enable ? "true" : "false",
                   dep.Permanent ? "true" : "false");
            first = 0;
        } else {
            printf("  DEP                  %s%s\n",
                   dep.Enable ? "on" : "off", dep.Permanent ? " (permanent)" : "");
        }
    }

    PROCESS_MITIGATION_ASLR_POLICY aslr;
    ZeroMemory(&aslr, sizeof aslr);
    if (GetProcessMitigationPolicy(h, ProcessASLRPolicy, &aslr, sizeof aslr)) {
        if (json) {
            printf("%s\"aslr\":{\"bottom_up\":%u,\"force_reloc\":%u,\"high_entropy\":%u}",
                   first ? "" : ",", aslr.EnableBottomUpRandomization,
                   aslr.EnableForceRelocateImages, aslr.EnableHighEntropy);
            first = 0;
        } else {
            printf("  ASLR                 bottom-up:%u force-reloc:%u high-entropy:%u\n",
                   aslr.EnableBottomUpRandomization, aslr.EnableForceRelocateImages,
                   aslr.EnableHighEntropy);
        }
    }

    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg;
    ZeroMemory(&cfg, sizeof cfg);
    if (GetProcessMitigationPolicy(h, ProcessControlFlowGuardPolicy, &cfg, sizeof cfg)) {
        if (json) {
            printf("%s\"cfg\":%s", first ? "" : ",",
                   cfg.EnableControlFlowGuard ? "true" : "false");
            first = 0;
        } else {
            printf("  Control Flow Guard   %s\n", cfg.EnableControlFlowGuard ? "on" : "off");
        }
    }

    // Image-load signature policy: when on, the process may only load images
    // signed by Microsoft / the Store (a strong anti-injection measure).
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig;
    ZeroMemory(&sig, sizeof sig);
    if (GetProcessMitigationPolicy(h, ProcessSignaturePolicy, &sig, sizeof sig)) {
        if (json) {
            printf("%s\"signature\":{\"ms_signed_only\":%u,\"store_only\":%u}",
                   first ? "" : ",", sig.MicrosoftSignedOnly, sig.StoreSignedOnly);
            first = 0;
        } else {
            printf("  Signature policy     ms-signed-only:%u store-only:%u\n",
                   sig.MicrosoftSignedOnly, sig.StoreSignedOnly);
        }
    }

    // Dynamic code (ACG, Arbitrary Code Guard): when on, the process cannot
    // allocate new executable memory or make data executable.
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn;
    ZeroMemory(&dyn, sizeof dyn);
    if (GetProcessMitigationPolicy(h, ProcessDynamicCodePolicy, &dyn, sizeof dyn)) {
        if (json) {
            printf("%s\"dynamic_code_prohibited\":%s", first ? "" : ",",
                   dyn.ProhibitDynamicCode ? "true" : "false");
            first = 0;
        } else {
            printf("  Dynamic code (ACG)   prohibit:%u\n", dyn.ProhibitDynamicCode);
        }
    }

    if (json) { putchar('}'); }
    else      { putchar('\n'); }
}

int cmd_inspect(int argc, char **argv)
{
    const char *pid_arg = NULL;
    int json = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) json = 1;
        else if (pid_arg == NULL)           pid_arg = argv[a];
        else {
            fprintf(stderr, "inspect: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (pid_arg == NULL) {
        fputs("usage: winspect inspect <pid> [--json]\n", stderr);
        return 1;
    }

    // Parse the PID. strtoul reports the first non-digit via endptr, so we can
    // reject "12ab" instead of silently treating it as 12.
    unsigned long pid = 0;
    if (!pid_from_arg("inspect", pid_arg, &pid)) {
        return 1;
    }

    HANDLE h = open_target((DWORD)pid);
    if (h == NULL) {
        return 1;
    }

    int rc = 1;

    // Step 1: ask the kernel where this process's PEB lives. The PEB address is
    // in the target's address space; we only learn the pointer here, not the data.
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retlen = 0;
    NTSTATUS st = NtQueryInformationProcess(h, ProcessBasicInformation,
                                            &pbi, sizeof pbi, &retlen);
    if (st < 0) {   // NTSTATUS: negative means an error code
        fprintf(stderr, "inspect: NtQueryInformationProcess failed (status 0x%08lX)\n",
                (unsigned long)st);
        goto done;
    }
    if (pbi.PebBaseAddress == NULL) {
        fputs("inspect: process has no PEB (system/minimal process?)\n", stderr);
        goto done;
    }

    // Step 2: copy the whole PEB out of the target.
    PEB peb;
    if (!rpm(h, pbi.PebBaseAddress, &peb, sizeof peb)) {
        fputs("inspect: cannot read the PEB\n", stderr);
        goto done;
    }

    // ---- JSON path ------------------------------------------------------------
    // One object with the same facts as the text view. Each sub-section prints
    // its own ",key":value fragment so this stays a flat assembly.
    if (json) {
        printf("{\"pid\":%lu", (unsigned long)pid);
        printf(",\"peb_address\":\"0x%016llX\"",
               (unsigned long long)(uintptr_t)pbi.PebBaseAddress);
        printf(",\"being_debugged\":%s", peb.BeingDebugged ? "true" : "false");
        printf(",\"image_base\":\"0x%016llX\"",
               (unsigned long long)(uintptr_t)peb.Reserved3[PEB_IMAGEBASE_RESERVED3_INDEX]);
        print_mitigations(h, 1);
        if (peb.ProcessParameters != NULL) {
            RTL_USER_PROCESS_PARAMETERS params;
            if (rpm(h, peb.ProcessParameters, &params, sizeof params)) {
                char path[1024], cmd[2048];
                read_ustr(h, &params.ImagePathName, path, sizeof path);
                read_ustr(h, &params.CommandLine, cmd, sizeof cmd);
                fputs(",\"image_path\":", stdout);   json_str(path);
                fputs(",\"command_line\":", stdout); json_str(cmd);
                print_environment(h, (const BYTE *)peb.ProcessParameters, 1);
            }
        }
        if (peb.Ldr != NULL) {
            print_modules(h, &peb, 1);
        } else {
            fputs(",\"modules\":[]", stdout);
        }
        puts("}");
        rc = 0;
        goto done;
    }

    printf("process  pid %lu\n", (unsigned long)pid);
    printf("  PEB                  @ %p\n", (void *)pbi.PebBaseAddress);
    // BeingDebugged is the single byte that IsDebuggerPresent() reads. A simple
    // anti-debug check just looks at this flag; here we read it directly.
    printf("  BeingDebugged        %u\n", peb.BeingDebugged);
    // ImageBaseAddress = where the main .exe is actually mapped (post-ASLR).
    printf("  ImageBaseAddress     @ %p\n\n",
           (void *)peb.Reserved3[PEB_IMAGEBASE_RESERVED3_INDEX]);

    // Live mitigations the kernel enforces on this process right now.
    print_mitigations(h, 0);

    // Step 3: read ProcessParameters for the command line / image path / env.
    // peb.ProcessParameters is a pointer into the target.
    if (peb.ProcessParameters != NULL) {
        RTL_USER_PROCESS_PARAMETERS params;
        if (rpm(h, peb.ProcessParameters, &params, sizeof params)) {
            char path[1024], cmd[2048];
            read_ustr(h, &params.ImagePathName, path, sizeof path);
            read_ustr(h, &params.CommandLine, cmd, sizeof cmd);
            puts("Process parameters");
            printf("  ImagePathName        %s\n", path[0] ? path : "(empty)");
            printf("  CommandLine          %s\n\n", cmd[0] ? cmd : "(empty)");

            puts("Environment");
            print_environment(h, (const BYTE *)peb.ProcessParameters, 0);
            putchar('\n');
        } else {
            puts("Process parameters\n  (cannot read RTL_USER_PROCESS_PARAMETERS)\n");
        }
    }

    // Step 4: the loaded-module list from the loader (Ldr).
    puts("Modules (InMemoryOrder)");
    if (peb.Ldr != NULL) {
        print_modules(h, &peb, 0);
    } else {
        puts("  (Ldr not initialized yet)");
    }

    rc = 0;

done:
    CloseHandle(h);
    return rc;
}
