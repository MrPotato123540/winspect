// winspect threads - per-thread CPU snapshot of a live process
//
// A process is just an address space and a bag of resources; the things that
// actually run on a CPU are its threads. This command enumerates them and, for
// each, reads the register state the scheduler saved when the thread last
// stopped running: RIP (what it is about to execute) and RSP (how deep its
// stack is), plus its priority, start address and accumulated CPU time.
//
// To read register state we must momentarily freeze the thread:
//   OpenThread -> SuspendThread -> GetThreadContext -> ResumeThread
// We ResumeThread on every path, because leaving another process's thread
// suspended would hang that process.
//
// With -s/--stack we go further: DbgHelp + StackWalk64 unwind each thread's full
// call stack and resolve symbols, turning bare addresses into
// "ntdll!NtWaitForSingleObject+0x14". That needs symbols, so it is opt-in (it
// can be slow and may consult a symbol server); the default stays fast.

#include "pidarg.h"
#include "threads.h"
#include "jsonutil.h"

#include <windows.h>
#include <tlhelp32.h>   // Toolhelp: thread and module snapshots
#include <dbghelp.h>    // SymInitialize, StackWalk64, SymFromAddr
#include <stdio.h>
#include <stdlib.h>     // strtoul
#include <string.h>     // strcmp (option parsing)

#define MAX_MODULES 1024

// One loaded module reduced to just what we need to place an address inside it.
struct module_span {
    uintptr_t base;
    uintptr_t end;      // base + size (one past the last byte)
    char      name[64];
};

// NtQueryInformationThread reads a thread's Win32 start address (information
// class 9). Not declared in every toolchain's headers, so we resolve it at run
// time from ntdll.
typedef LONG (NTAPI *NtQueryInformationThread_t)(
    HANDLE ThreadHandle, int ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
#define ThreadQuerySetWin32StartAddress 9

// Builds the target's module table with a Toolhelp module snapshot (used to
// place a bare RIP as "module+offset" in the default output).
static unsigned build_modules(DWORD pid, struct module_span *out, unsigned cap)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    MODULEENTRY32 me;
    me.dwSize = sizeof me;     // Toolhelp refuses the call if this isn't set
    unsigned n = 0;
    if (Module32First(snap, &me)) {
        do {
            if (n >= cap) {
                break;
            }
            out[n].base = (uintptr_t)me.modBaseAddr;
            out[n].end  = (uintptr_t)me.modBaseAddr + me.modBaseSize;
            snprintf(out[n].name, sizeof out[n].name, "%s", me.szModule);
            n++;
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return n;
}

// Formats addr as "module+0xoffset" into buf when it falls inside a known
// module, else just the bare address.
static void place_addr(uintptr_t addr, const struct module_span *mods, unsigned n,
                       char *buf, size_t buflen)
{
    for (unsigned i = 0; i < n; i++) {
        if (addr >= mods[i].base && addr < mods[i].end) {
            snprintf(buf, buflen, "0x%016llX  %s+0x%llX",
                     (unsigned long long)addr, mods[i].name,
                     (unsigned long long)(addr - mods[i].base));
            return;
        }
    }
    snprintf(buf, buflen, "0x%016llX  (unknown module)", (unsigned long long)addr);
}

#ifdef _WIN64
// Unwinds and prints one thread's call stack using the (already captured)
// register context. StackWalk64 reads the target's memory and stack through the
// supplied process/thread handles; DbgHelp resolves each frame's symbol. We pass
// a COPY of the context because StackWalk64 mutates it as it walks.
static void walk_stack(HANDLE hproc, HANDLE hthread, const CONTEXT *ctx_in)
{
    CONTEXT ctx = *ctx_in;
    STACKFRAME64 frame;
    ZeroMemory(&frame, sizeof frame);
    frame.AddrPC.Offset    = ctx.Rip; frame.AddrPC.Mode    = AddrModeFlat;
    frame.AddrFrame.Offset = ctx.Rbp; frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = ctx.Rsp; frame.AddrStack.Mode = AddrModeFlat;

    for (int depth = 0; depth < 32; depth++) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hproc, hthread, &frame, &ctx,
                         NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }
        DWORD64 addr = frame.AddrPC.Offset;
        if (addr == 0) {
            break;
        }

        // Module name for this frame.
        IMAGEHLP_MODULE64 mi;
        ZeroMemory(&mi, sizeof mi);
        mi.SizeOfStruct = sizeof mi;
        const char *mod = SymGetModuleInfo64(hproc, addr, &mi) ? mi.ModuleName : "?";

        // Symbol name + offset, if symbols are available for this module.
        char symbuf[sizeof(SYMBOL_INFO) + 256];
        SYMBOL_INFO *si = (SYMBOL_INFO *)symbuf;
        ZeroMemory(si, sizeof(SYMBOL_INFO));
        si->SizeOfStruct = sizeof(SYMBOL_INFO);
        si->MaxNameLen   = 255;
        DWORD64 disp = 0;
        if (SymFromAddr(hproc, addr, &disp, si)) {
            printf("      %s!%s+0x%llX\n", mod, si->Name, (unsigned long long)disp);
        } else {
            printf("      0x%016llX  %s\n", (unsigned long long)addr, mod);
        }
    }
}
#endif

int cmd_threads(int argc, char **argv)
{
    // Args: <pid> plus optional -s/--stack and --json/--csv. Order-independent.
    const char *pid_arg = NULL;
    int want_stack = 0;
    enum out_mode mode = OUT_TEXT;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "-s") == 0 || strcmp(argv[a], "--stack") == 0) {
            want_stack = 1;
        } else if (strcmp(argv[a], "--json") == 0) {
            mode = OUT_JSON;
        } else if (strcmp(argv[a], "--csv") == 0) {
            mode = OUT_CSV;
        } else if (pid_arg == NULL) {
            pid_arg = argv[a];
        } else {
            fprintf(stderr, "threads: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (pid_arg == NULL) {
        fputs("usage: winspect threads <pid> [-s | --stack] [--json | --csv]\n", stderr);
        return 1;
    }
    // The machine-readable modes emit a per-thread summary; the call stack is a
    // human view, so --json/--csv override -s.
    if (mode != OUT_TEXT) {
        want_stack = 0;
    }
    unsigned long pid = 0;
    if (!pid_from_arg("threads", pid_arg, &pid)) {
        return 1;
    }

    NtQueryInformationThread_t NtQIT = NULL;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll != NULL) {
        NtQIT = (NtQueryInformationThread_t)(void(*)(void))
                GetProcAddress(ntdll, "NtQueryInformationThread");
    }

    static struct module_span mods[MAX_MODULES];
    unsigned nmods = build_modules((DWORD)pid, mods, MAX_MODULES);

    // The stack walk needs a process handle and symbols; set them up only when
    // asked, because SymInitialize with fInvadeProcess loads every module's
    // symbols and can be slow / hit a symbol server.
    HANDLE hproc = NULL;
    if (want_stack) {
        hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
        if (hproc == NULL) {
            fprintf(stderr, "threads: -s needs to open the process (error %lu)\n",
                    (unsigned long)GetLastError());
            return 1;
        }
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        SymInitialize(hproc, NULL, TRUE);   // TRUE = load all module symbols
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "threads: snapshot failed (error %lu)\n", (unsigned long)GetLastError());
        if (hproc) { SymCleanup(hproc); CloseHandle(hproc); }
        return 1;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof te;
    if (!Thread32First(snap, &te)) {
        fprintf(stderr, "threads: no threads found (error %lu)\n", (unsigned long)GetLastError());
        CloseHandle(snap);
        if (hproc) { SymCleanup(hproc); CloseHandle(hproc); }
        return 1;
    }

    if (mode == OUT_TEXT) {
        printf("process  pid %lu  (%u modules known)\n\n", (unsigned long)pid, nmods);
    } else if (mode == OUT_CSV) {
        puts("tid,prio,cpu_ms,start,rip,rsp");
    } else {
        putchar('[');
    }
    unsigned count = 0;
    unsigned emitted = 0;   // for JSON comma separation
    do {
        if (te.th32OwnerProcessID != (DWORD)pid) {
            continue;
        }
        count++;

        HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |
                               THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (th == NULL) {
            if (mode == OUT_TEXT) {
                printf("  tid %-6lu  (cannot open: error %lu)\n",
                       (unsigned long)te.th32ThreadID, (unsigned long)GetLastError());
            }
            continue;
        }

        // Start address (no suspend needed).
        char start_str[128] = "(unavailable)";
        if (NtQIT != NULL) {
            PVOID start = NULL;
            if (NtQIT(th, ThreadQuerySetWin32StartAddress, &start, sizeof start, NULL) >= 0) {
                place_addr((uintptr_t)start, mods, nmods, start_str, sizeof start_str);
            }
        }

        int prio = GetThreadPriority(th);

        // Accumulated CPU time (kernel + user), in milliseconds. FILETIME here
        // is a duration in 100-nanosecond units, not a wall-clock time.
        unsigned long long cpu_ms = 0;
        FILETIME tc, tx, tk, tu;
        if (GetThreadTimes(th, &tc, &tx, &tk, &tu)) {
            ULONGLONG k = ((ULONGLONG)tk.dwHighDateTime << 32) | tk.dwLowDateTime;
            ULONGLONG u = ((ULONGLONG)tu.dwHighDateTime << 32) | tu.dwLowDateTime;
            cpu_ms = (k + u) / 10000ULL;
        }

        // Freeze, snapshot registers, thaw. For the stack walk we need the full
        // context (RBP etc.), otherwise just the control registers.
        char rip_str[128] = "(context unavailable)";
        char rsp_str[128] = "(context unavailable)";
        CONTEXT ctx;
        int have_ctx = 0;
        if (SuspendThread(th) != (DWORD)-1) {
            ZeroMemory(&ctx, sizeof ctx);
            ctx.ContextFlags = want_stack ? CONTEXT_FULL : CONTEXT_CONTROL;
            if (GetThreadContext(th, &ctx)) {
                have_ctx = 1;
#ifdef _WIN64
                place_addr((uintptr_t)ctx.Rip, mods, nmods, rip_str, sizeof rip_str);
                snprintf(rsp_str, sizeof rsp_str, "0x%016llX", (unsigned long long)ctx.Rsp);
#else
                place_addr((uintptr_t)ctx.Eip, mods, nmods, rip_str, sizeof rip_str);
                snprintf(rsp_str, sizeof rsp_str, "0x%08lX", (unsigned long)ctx.Esp);
#endif
            }
            // Keep the thread suspended across the stack walk (it reads the
            // thread's stack memory), then resume no matter what.
#ifdef _WIN64
            if (want_stack && have_ctx && hproc != NULL) {
                printf("  tid %-6lu  prio %+d  cpu %llums\n",
                       (unsigned long)te.th32ThreadID, prio, cpu_ms);
                printf("    start  %s\n", start_str);
                printf("    stack:\n");
                walk_stack(hproc, th, &ctx);
                ResumeThread(th);
                CloseHandle(th);
                continue;
            }
#endif
            ResumeThread(th);
        }
        (void)have_ctx;

        if (mode == OUT_TEXT) {
            printf("  tid %-6lu  prio %+d  cpu %llums\n",
                   (unsigned long)te.th32ThreadID, prio, cpu_ms);
            printf("    start  %s\n", start_str);
            printf("    rip    %s\n", rip_str);
            printf("    rsp    %s\n", rsp_str);
        } else if (mode == OUT_CSV) {
            printf("%lu,%d,%llu,", (unsigned long)te.th32ThreadID, prio, cpu_ms);
            csv_str(start_str); putchar(',');
            csv_str(rip_str);   putchar(',');
            csv_str(rsp_str);   putchar('\n');
        } else {
            printf("%s{\"tid\":%lu,\"prio\":%d,\"cpu_ms\":%llu,\"start\":",
                   emitted ? "," : "", (unsigned long)te.th32ThreadID, prio, cpu_ms);
            json_str(start_str);
            fputs(",\"rip\":", stdout); json_str(rip_str);
            fputs(",\"rsp\":", stdout); json_str(rsp_str);
            putchar('}');
            emitted++;
        }

        CloseHandle(th);
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    if (hproc != NULL) {
        SymCleanup(hproc);
        CloseHandle(hproc);
    }
    if (count == 0 && mode == OUT_TEXT) {
        fprintf(stderr, "threads: no threads for pid %lu (does it exist?)\n", (unsigned long)pid);
        return 1;
    }
    if (mode == OUT_TEXT) {
        printf("\n%u threads\n", count);
    } else if (mode == OUT_JSON) {
        puts("]");
    }
    return 0;
}
