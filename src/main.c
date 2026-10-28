#include <stdio.h>
#include <string.h>
#include <windows.h>    // SetConsoleOutputCP

// cmd_list now lives in list.c (Phase 1)
// The header gives main.c the prototype, the linker connects the two .obj files
#include "list.h"

// cmd_pe lives in pe.c (Phase 2), same pattern as list
#include "pe.h"

// cmd_inspect lives in inspect.c (Phase 4): reads a live process's PEB
#include "inspect.h"

// cmd_threads / cmd_handles live in threads.c and handles.c (Phase 5)
#include "threads.h"
#include "handles.h"

// cmd_token / cmd_secinfo live in token.c and secinfo.c (Phase 6)
#include "token.h"
#include "secinfo.h"

// cmd_ssn / cmd_launch live in ssn.c and launch.c (Phase 7)
#include "ssn.h"
#include "launch.h"

// cmd_verify lives in verify.c (Phase 8): the consistency/hook detector
#include "verify.h"

// cmd_sign lives in sign.c: Authenticode signature check
#include "sign.h"

// cmd_regions lives in regions.c: virtual memory map
#include "regions.h"

// cmd_net lives in net.c: per-process TCP/UDP endpoints
#include "net.h"

// cmd_triage lives in triage.c: one-shot suspicion report
#include "triage.h"

// cmd_strings lives in strings.c: static string + indicator extraction
#include "strings.h"

// cmd_services lives in services.c: SCM service enumeration
#include "services.h"

// cmd_drivers lives in drivers.c: loaded kernel driver list
#include "drivers.h"

// cmd_autoruns lives in autoruns.c: registry auto-start sweep
#include "autoruns.h"

// cmd_pipes lives in pipes.c: named pipe listing
#include "pipes.h"

// cmd_hash lives in hash.c: file digest (MD5/SHA1/SHA256)
#include "hash.h"

// cmd_hosts / cmd_certstore / cmd_tasks: more read-only DFIR views
#include "hosts.h"
#include "certstore.h"
#include "objects.h"
#include "defender.h"
#include "usb.h"
#include "prefetch.h"
#include "shimcache.h"
#include "bam.h"
#include "firewall.h"
#include "taskcache.h"
#include "wmi.h"
#include "lnk.h"
#include "streams.h"
#include "hunt.h"
#include "posture.h"
#include "events.h"
#include "hidden.h"
#include "sweep.h"
#include "usage.h"
#include "userassist.h"
#include "mru.h"
#include "jumplist.h"
#include "hive.h"
#include "amcache.h"
#include "rdp.h"
#include "sysinfo.h"
#include "programs.h"
#include "shellbags.h"
#include "pshistory.h"
#include "recyclebin.h"
#include "tasks.h"

// cmd_modules lives in modules.c: a live process's loaded modules
#include "modules.h"

// cmd_arp / cmd_sessions: network neighbours and logon sessions
#include "arp.h"
#include "sessions.h"

// cmd_shares lives in shares.c: SMB share enumeration
#include "shares.h"

// cmd_routes lives in routes.c: IPv4 routing table
#include "routes.h"

// Row count computed by the compiler from the table itself
// No separate MAX_COMMANDS constant that we could forget to update
#define COMMAND_COUNT (sizeof commands / sizeof commands[0])

// Every subcommand has the same signature so they can sit in one table
// argc/argv here are the command's OWN arguments, not the program's
// for example: "winspect pe notepad.exe" -> cmd_pe gets argc=1, argv[0]="notepad.exe"
// Return value becomes the process exit code: 0 = success, anything else = failure
// CI relies on this, a non-zero exit code turns the GitHub Actions step red
typedef int (*cmd_fn)(int argc, char** argv);

/*
 * ============================================================================
 * COMMAND DISPATCH TABLE (Static Function Pointer Mapping)
 * ============================================================================
 *
 * 1. ARCHITECTURAL PARALLEL (Hardware IDT / Vector Table vs CLI Dispatcher):
 * ----------------------------------------------------------------------------
 * This structure closely models low-level CPU interrupt / trap dispatching:
 *
 *   A. Hardware Level (x86 IDT / ARM Vector Table):
 *      - Trigger: Exception (e.g., #PF 0x0E) or Hardware IRQ (e.g., Keyboard).
 *      - Resolution: The CPU reads the table base address from IDTR (or VBAR)
 *        and computes the target entry via direct array indexing:
 *
 *          Descriptor_VA = IDTR.Base + (Vector_ID * sizeof(GateDescriptor))
 *
 *      - Dispatch: CPU extracts the target ISR address (CS:RIP / PC) and
 *        jumps directly in hardware (deterministic O(1) latency).
 *
 *   B. Software CLI Level (Winspect Command Dispatcher):
 *      - Trigger: User token passed via argv[1] (e.g., "list" or "pe").
 *      - Resolution: Because keys are string tokens rather than integer IDs,
 *        we perform a linear scan matching tokens via strcmp().
 *      - Dispatch: Once matched, execution transfers directly to the function
 *        pointer (cmd_fn) mapped in that entry.
 *
 * 2. DISPATCH LOOP & POINTER ARITHMETIC (Argument Slicing):
 * ----------------------------------------------------------------------------
 * The dispatcher in main() dynamically determines the table bounds and shifts
 * arguments forward so subcommands behave as standalone CLI entry points. Example Usage:
 *
 *      const size_t num_cmds = sizeof(commands) / sizeof(commands[0]);
 *      for (size_t i = 0; i < num_cmds; ++i) {
 *          if (strcmp(argv[1], commands[i].name) == 0) {
 *              return commands[i].fn(argc - 2, argv + 2);
 *          }
 *      }
 *
 *   Argument Slicing Walkthrough:
 *   Assume invocation:
 *      $ winspect.exe list --tree 1024
 *
 *   State in main():
 *      argc    = 4
 *      argv[0] = "winspect.exe"
 *      argv[1] = "list"
 *      argv[2] = "--tree"
 *      argv[3] = "1024"
 *
 *   State inside cmd_list(argc - 2, argv + 2):
 *      argc    = 2                  (decremented by 2)
 *      argv[0] = "--tree"           (argv shifted forward: argv + 2)
 *      argv[1] = "1024"
 *
 *   Result: cmd_list receives only its own flags, starting at argv[0].
 *   It never sees the root binary name or its own command name.
 *
 * 3. DESIGN PROPERTIES:
 * ----------------------------------------------------------------------------
 * - Open/Closed Principle: Adding a new subcommand (e.g., "tokens" or "dump")
 *   requires adding exactly one row to this array. Neither main(), argument
 *   parsing, nor usage generation routines ever need modification.
 * - static: Internal linkage restricts symbol visibility to this translation
 *   unit, preventing LNK2005 symbol collisions across object files.
 *
 * 4. MEMORY PLACEMENT & PE INTERNALS (.rdata & Hardware Write Protection):
 * ----------------------------------------------------------------------------
 * - Immutability: Declared 'const', signaling to MSVC/GCC that this table
 *   and its embedded string literals must never be altered at runtime.
 * - PE Placement: The compiler usually emits this struct and its strings into
 *   the .rdata (Read-Only Data) section of the generated winspect.exe binary.
 * - OS Loader Setup: During process creation, the kernel maps the whole .exe
 *   as an image section (ntdll!LdrLoadDll is only for DLLs loaded later).
 *   .rdata pages end up PAGE_READONLY, their PTEs have the R/W flag cleared.
 * - Relocation Nuance: The table holds pointers (name, fn, help). With ASLR the
 *   image may load at a different base, so the ntdll loader patches these
 *   pointers using the .reloc section. While doing so it makes the pages
 *   temporarily writable, then restores PAGE_READONLY.
 * - Compile-Time Enforcement:
 *   A direct write never even compiles, because the table is const:
 *
 *      commands[0].name = "overwrite";  // MSVC C2166 / GCC: "assignment of member in read-only object"
 *
 * - Hardware Enforcement:
 *   Only by casting const away does the write reach the CPU:
 *
 *      *(const char **)&commands[0].name = "overwrite";  // compiles, faults at runtime
 *
 *   The Memory Management Unit (MMU) catches the write attempt against a
 *   read-only PTE and raises a Page Fault (#PF, Vector 14). A user-mode write
 *   to a read-only page always faults (CR0.WP only matters for kernel-mode
 *   writes). The Windows kernel translates this hardware fault into
 *   STATUS_ACCESS_VIOLATION (0xC0000005) and, if unhandled, terminates the process.
 *
 * - Phase 2 Verification:
 *   When cmd_pe parses winspect.exe, inspect the Section Header table:
 *   cross-reference .rdata's VirtualAddress and PointerToRawData to locate
 *   this exact dispatch table and its RVA layout directly in the raw binary.
 * ============================================================================
 */
static const struct {
    const char* name;
    cmd_fn      fn;
    const char* help;
    const char* cat;       // for the grouped usage listing
} commands[] = {
    { "pe",      cmd_pe,      "parse and dump PE file headers",             "file" },
    { "sign",    cmd_sign,    "Authenticode signature + trust (or --scan)", "file" },
    { "strings", cmd_strings, "printable strings + indicators from a file", "file" },
    { "hash",    cmd_hash,    "MD5/SHA1/SHA256 of a file",                  "file" },
    { "lnk",      cmd_lnk,      "shortcut files (default: Recent folder)",  "file" },
    { "streams",  cmd_streams,  "alternate data streams + Mark-of-the-Web", "file" },
    { "jumplist", cmd_jumplist, "Jump Lists: recent items per application",  "file" },
    { "recyclebin", cmd_recyclebin, "Recycle Bin: deleted files, owner, time", "file" },
    { "pshistory", cmd_pshistory, "PowerShell command history (PSReadLine)", "file" },
    { "shellbags", cmd_shellbags, "folders browsed in Explorer (ShellBags)", "file" },
    { "hive",     cmd_hive,     "browse an offline registry hive file",      "file" },
    { "amcache",  cmd_amcache,  "Amcache.hve: file inventory with SHA-1",    "file" },
    { "rdp",      cmd_rdp,      "outgoing Remote Desktop history (mstsc)",   "system" },
    { "sysinfo",  cmd_sysinfo,  "machine facts: name, build, users, networks", "system" },
    { "programs", cmd_programs, "installed software; flags remote-access tools", "system" },

    { "list",    cmd_list,    "process/thread tree via Toolhelp",           "process" },
    { "inspect", cmd_inspect, "dump a live process PEB (cmdline/modules)",  "process" },
    { "modules", cmd_modules, "loaded modules of a process (+flags)",       "process" },
    { "threads", cmd_threads, "per-thread register snapshot (RIP/RSP)",     "process" },
    { "handles", cmd_handles, "kernel object handles a process holds",      "process" },
    { "regions", cmd_regions, "virtual memory map (flags private+exec)",    "process" },
    { "token",   cmd_token,   "process security context (SID/privileges)",  "process" },
    { "launch",  cmd_launch,  "start a program suspended, show entry point","process" },

    { "secinfo", cmd_secinfo, "owner/DACL of process/file/service/key",     "security" },
    { "verify",  cmd_verify,  "consistency checks (hook/masquerade/tamper)","security" },
    { "triage",  cmd_triage,  "one-shot suspicion score for a process",     "security" },
    { "hunt",     cmd_hunt,     "lineage/masquerade checks on all processes", "security" },
    { "posture",  cmd_posture,  "host hardening checks (UAC, LSA, SMBv1...)", "security" },
    { "events",   cmd_events,   "high-signal event log timeline",          "security" },
    { "hidden",   cmd_hidden,   "cross-view: hidden processes / services",  "security" },
    { "sweep",    cmd_sweep,    "all system-wide checks, findings only",   "security" },
    { "ssn",     cmd_ssn,     "read an ntdll stub's service number",        "security" },

    { "net",     cmd_net,     "per-process TCP/UDP endpoints",              "system" },
    { "arp",     cmd_arp,     "IPv4 neighbour (ARP) cache",                 "system" },
    { "routes",  cmd_routes,  "IPv4 routing table",                         "system" },
    { "sessions",cmd_sessions,"terminal/logon sessions and users",          "system" },
    { "shares",  cmd_shares,  "SMB shares this machine exposes",            "system" },
    { "services",cmd_services,"SCM services: state, start, path, account",  "system" },
    { "drivers", cmd_drivers, "loaded kernel drivers (+ --sig check)",        "system" },
    { "autoruns",cmd_autoruns,"auto-start locations, flagged with reasons", "system" },
    { "tasks",   cmd_tasks,   "scheduled tasks (command + author)",         "system" },
    { "pipes",   cmd_pipes,   "named pipes on the system",                  "system" },
    { "hosts",   cmd_hosts,   "active entries in the hosts file",           "system" },
    { "certstore",cmd_certstore,"certificates in a system store (Root)",    "system" },
    { "objects",  cmd_objects,  "named kernel objects (BaseNamedObjects)",  "system" },
    { "usb",      cmd_usb,      "USB storage history (Enum\\USBSTOR)",       "system" },
    { "prefetch", cmd_prefetch, "execution evidence from Prefetch (*.pf)",   "system" },
    { "shimcache",cmd_shimcache,"AppCompatCache entries (programs seen)",    "system" },
    { "bam",      cmd_bam,      "BAM: last run per program per user",        "system" },
    { "userassist",cmd_userassist,"GUI program launches (UserAssist)",       "system" },
    { "mru",      cmd_mru,      "Run box / typed paths / recent docs",     "system" },
    { "firewall", cmd_firewall, "firewall rules (flags risky inbound allow)", "security" },
    { "taskcache",cmd_taskcache,"scheduled tasks hidden from schtasks",      "security" },
    { "wmi",      cmd_wmi,      "WMI permanent event subscriptions",        "security" },
    { "defender", cmd_defender, "Defender exclusions + disabling policies",  "security" },
};

static void usage(void) {
    // Fixed category order with a readable heading for each.
    static const struct { const char *key, *title; } groups[] = {
        { "file",     "Static file analysis" },
        { "process",  "Live process inspection" },
        { "security", "Security / triage" },
        { "system",   "System-wide views" },
    };
    puts("winspect - Windows internals inspector\n");
    for (size_t g = 0; g < sizeof groups / sizeof groups[0]; g++) {
        printf("%s:\n", groups[g].title);
        for (size_t i = 0; i < COMMAND_COUNT; i++) {
            if (strcmp(commands[i].cat, groups[g].key) == 0) {
                // %-9s pads the name so the help texts line up in a column
                printf("  %-10s %s\n", commands[i].name, commands[i].help);
            }
        }
        putchar('\n');
    }
    puts("Most commands accept --json; tabular ones also accept --csv.");
    puts("Details for one command: winspect help <command>   (or: winspect <command> --help)");
}

// Was the program launched by double-clicking it (so Windows spawned a fresh
// console just for us), rather than run from an existing shell? If we are the
// ONLY process attached to this console, nobody was here before us, which is the
// double-click case. GetConsoleProcessList fills a buffer with the PIDs attached
// to our console and returns the count; 1 means just winspect.
//
// This matters because a double-clicked console window closes the instant main()
// returns, so any output flashes by unread. When we detect it we pause at the
// end and, with no command given, print a few copy-paste examples.
static int launched_by_doubleclick(void) {
    DWORD pids[4];
    DWORD n = GetConsoleProcessList(pids, (DWORD)(sizeof pids / sizeof pids[0]));
    return (n == 1);
}

// Prints a short getting-started block for someone who just double-clicked.
static void examples(void) {
    puts("\nThis is a command-line tool. Open a terminal (PowerShell or cmd) and run,");
    puts("for example:");
    puts("  winspect list                     list processes");
    puts("  winspect triage <pid>             quick suspicion report for a process");
    puts("  winspect pe C:\\Windows\\notepad.exe   parse a PE file");
    puts("  winspect net                      per-process network endpoints");
    puts("\nAlmost every command also accepts --json (and tables accept --csv).");
}

// Waits for the user to press Enter, used only in the double-click case so the
// window does not vanish before anything can be read.
static void pause_exit(void) {
    fputs("\nPress Enter to close this window...", stdout);
    fflush(stdout);
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        /* drain the line */
    }
}

/*
 * ============================================================================
 * COMMAND DISPATCHER & IN-PLACE ARGUMENT SLICER
 * ============================================================================
 *
 * 1. MICROARCHITECTURAL JUSTIFICATION: LINEAR SCAN OVER HASHING / BINARY SEARCH
 * ----------------------------------------------------------------------------
 * Algorithmic complexity classes (O(1) vs O(N)) assume uniform memory access
 * cost. On modern CPU architectures, memory hierarchy and latency invert these
 * trade-offs for small datasets (N <= ~10):
 *
 *   A. Memory Footprint & Cache Lines (x86-64 / AArch64):
 *      - Each dispatch row consists of 3 64-bit pointers (24 bytes total):
 *          * const char *name  : 8 bytes
 *          * cmd_fn      fn    : 8 bytes
 *          * const char *help  : 8 bytes
 *      - A 10-command table consumes: 10 * 24 = 240 bytes.
 *      - Modern L1 Data Cache line size = 64 bytes.
 *      - Total cache lines required = ceil(240 / 64) = 4 cache lines.
 *
 *   B. Hardware Spatial Prefetching:
 *      - Accessing commands[0] can trigger the CPU's hardware prefetcher
 *        (L2 Streamer / Spatial Prefetcher) to pull the neighbouring cache
 *        lines of the table into cache ahead of the scan.
 *      - Caveat: the rows only hold pointers. strcmp reads the name strings
 *        themselves, which live elsewhere in .rdata, so those are separate
 *        accesses. On a cold start everything comes from disk/RAM anyway.
 *
 *   C. Branch Prediction & Instruction Overhead:
 *      - Hash Table Overhead: Computing a string hash (e.g., FNV-1a or djb2)
 *        requires iterating through the characters of argv[1], executing byte-level
 *        arithmetic/bitwise instructions, followed by modulo arithmetic and
 *        pointer-chasing across bucket links.
 *      - Binary Search Overhead: Non-linear indexing causes pipeline stalls and
 *        penalizes the CPU Branch Predictor on branch mispredictions (~15-20
 *        cycle penalty per mispredicted jump).
 *      - Linear strcmp Loop: A short sequential loop with predictable forward
 *        fall-through, and most strcmp calls stop at the first differing
 *        character. For N <= 10 it is at least as fast in practice and far
 *        simpler (not measured, and for a lookup that runs once per program
 *        start it does not need to be).
 *
 * 2. ZERO-COPY ARGUMENT SLICING (argc - 2, argv + 2):
 * ----------------------------------------------------------------------------
 * The slicing itself does no heap allocation (malloc), buffer copying (strdup),
 * or tokenization. It relies purely on pointer arithmetic over the argument
 * vector the CRT already built.
 *
 * Where argv lives on Windows: NOT on the stack. Before main() runs, the MSVC
 * CRT startup code calls GetCommandLineA/W, splits that single string into
 * words and builds the argv array on the HEAP. The string itself comes from
 * PEB->ProcessParameters->CommandLine (the field Phase 4 'inspect' reads).
 *
 *   CLI Invocation:
 *      $ winspect.exe pe --headers target.dll
 *
 *   Memory Layout of argv (CRT heap, char** array of pointers):
 *   -------------------------------------------------------------------------
 *   Address Offset       Vector Slot     Pointer Target (String in Memory)
 *   -------------------------------------------------------------------------
 *   argv + 0 (Base)   -> argv[0]      -> "winspect.exe\0"  (Binary Path)
 *   argv + 1 (+8B)    -> argv[1]      -> "pe\0"            (Subcommand)
 *   argv + 2 (+16B)   -> argv[2]      -> "--headers\0"     (First Option)
 *   argv + 3 (+24B)   -> argv[3]      -> "target.dll\0"    (Operand)
 *   argv + 4 (+32B)   -> argv[4]      -> NULL              (argv[argc] == NULL, C standard)
 *   -------------------------------------------------------------------------
 *
 *   Pointer Arithmetic Mechanics:
 *      argv + 2 == (char**)((uintptr_t)argv + (2 * sizeof(char*)))
 *
 *   Subcommand Isolation (Inside cmd_pe):
 *      - Forwarded argc: argc - 2  ==>  4 - 2 = 2
 *      - Forwarded argv: argv + 2  ==>  Points directly to address of argv[2]
 *
 *   From cmd_pe's frame of reference:
 *      argv[0] == "--headers"
 *      argv[1] == "target.dll"
 *      argc    == 2
 *
 *   Decoupling Guarantee:
 *   Subcommands operate as completely independent CLI utilities. They parse
 *   their own flags starting directly at argv[0], completely oblivious to the
 *   root binary name ("winspect.exe") or their own dispatch verb ("pe").
 * ============================================================================
 */
int main(int argc, char** argv) {

    // Make the console interpret our output as UTF-8. All our string conversions
    // (account names, module paths, UNICODE_STRINGs) emit UTF-8, so without this
    // non-ASCII names render as mojibake under the console's legacy code page.
    SetConsoleOutputCP(CP_UTF8);

    // If double-clicked, the console closes the moment we return, so remember to
    // pause at the end and be friendlier about a missing command.
    int dbl = launched_by_doubleclick();

    int rc;

    // argv[0] is the program path, argv[1] is the subcommand
    // No subcommand means the user does not know what to type, show help
    if (argc < 2) {
        usage();
        if (dbl) {
            examples();
        }
        rc = 1;
    } else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 ||
               strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "/?") == 0) {
        // "winspect help <command>": the long description from the command's
        // header (src/usage.c, generated). Bare "help" shows the overview.
        const char *text = (argc >= 3) ? command_usage(argv[2]) : NULL;
        if (text != NULL) {
            fputs(text, stdout);
            rc = 0;
        } else {
            if (argc >= 3) {
                fprintf(stderr, "unknown command: %s\n\n", argv[2]);
            }
            usage();
            rc = (argc >= 3) ? 1 : 0;
        }
    } else if (argc >= 3 && (strcmp(argv[2], "--help") == 0 || strcmp(argv[2], "-h") == 0) &&
               command_usage(argv[1]) != NULL) {
        // "winspect <command> --help" is the same as "winspect help <command>".
        fputs(command_usage(argv[1]), stdout);
        rc = 0;
    } else {
        // Cache-localized linear scan across the read-only dispatch table (.rdata)
        int found = 0;
        rc = 1;
        for (size_t i = 0; i < COMMAND_COUNT; i++) {
            if (strcmp(argv[1], commands[i].name) == 0) {
                // Skip program path + subcommand so each command sees its own
                // arguments starting at index 0.
                rc = commands[i].fn(argc - 2, argv + 2);
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "unknown command: %s\n\n", argv[1]);
            usage();
            rc = 1;
        }
    }

    if (dbl) {
        pause_exit();
    }
    return rc;
}