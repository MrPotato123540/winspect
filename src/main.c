#include <stdio.h>
#include <string.h>

// cmd_list now lives in list.c (Phase 1)
// The header gives main.c the prototype, the linker connects the two .obj files
#include "list.h"

// Row count computed by the compiler from the table itself
// No separate MAX_COMMANDS constant that we could forget to update
#define COMMAND_COUNT (sizeof commands / sizeof commands[0])

// Every subcommand has the same signature so they can sit in one table
// argc/argv here are the command's OWN arguments, not the program's
// for example: "winspect pe notepad.exe" -> cmd_pe gets argc=1, argv[0]="notepad.exe"
// Return value becomes the process exit code: 0 = success, anything else = failure
// CI relies on this, a non-zero exit code turns the GitHub Actions step red
typedef int (*cmd_fn)(int argc, char** argv);

// Placeholder for Phase 2 (PE header parsing)
static int cmd_pe(int argc, char** argv)
{
    // pe needs exactly one path, refuse early instead of reading past argv
    if (argc < 1) {
        // Errors go to stderr so stdout stays clean when output is piped to a file
        fputs("usage: winspect pe <path>\n", stderr);
        return 1;
    }

    printf("pe: '%s' (Phase 2)\n", argv[0]);
    return 0;
}

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
} commands[] = {
    { "list", cmd_list, "process/thread tree via Toolhelp" },
    { "pe",   cmd_pe,   "parse and dump PE file headers"   },
};

static void usage(void) {
    puts("winspect - Windows internals inspector\n\ncommands:");
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        // %-8s pads the name to 8 chars so the help texts line up in a column
        printf("  %-8s %s\n", commands[i].name, commands[i].help);
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

    // argv[0] is the program path, argv[1] is the subcommand
    // No subcommand means the user does not know what to type, show help
    if (argc < 2) {
        usage();
        return 1;
    }

    // Cache-localized linear scan across the read-only dispatch table (.rdata)
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        if (strcmp(argv[1], commands[i].name) == 0) {
            // Skip program path + subcommand
            // so each command sees its own arguments starting at index 0
            return commands[i].fn(argc - 2, argv + 2);
        }
    }

    fprintf(stderr, "unknown command: %s\n\n", argv[1]);
    usage();
    return 1;
}