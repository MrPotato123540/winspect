// winspect list - process/thread tree via Toolhelp
// Takes one snapshot of every running process and thread, copies them into our
// own arrays, adds each process's creation time, then prints an indented
// parent/child tree with a thread count per process (-t lists every thread)

#include "list.h"

#include <windows.h>
#include <tlhelp32.h>   // CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First/Next
#include <stdio.h>
#include <string.h>     // strcmp for option parsing

// Fixed cap instead of a growing heap buffer, keeps this first version simple
// A desktop rarely runs more than a few hundred processes, 4096 is plenty of headroom
// 4096 * ~280 bytes = ~1.1 MB, lives in .bss (zero-filled at load time)
// so it costs RAM at runtime but does not make the .exe file bigger
#define MAX_PROC 4096

// A desktop usually runs a few thousand threads, 32768 leaves room for busy machines
// 32768 * 12 bytes = ~384 KB, again in .bss
#define MAX_THR 32768

/*
 * ============================================================================
 * INTERNAL PROCESS TOPOLOGY NODE (struct proc)
 * ============================================================================
 *
 * 1. DATA PROJECTION & OWNERSHIP:
 * ----------------------------------------------------------------------------
 * The Win32 Toolhelp32 API returns a PROCESSENTRY32 descriptor (304 B on x64,
 * ANSI build) containing fields irrelevant to topology reconstruction.
 * cntUsage, th32DefaultHeapID and th32ModuleID are documented as unused and
 * always zero; cntThreads and pcPriClassBase are not needed for the tree:
 *
 *   PROCESSENTRY32 (Win32, ANSI, x64)      struct proc (Winspect Internal)
 *   +-------------------------+            +---------------------------+
 *   | dwSize             (4B) |            | DWORD     pid       (4B)  |
 *   | cntUsage           (4B) |            | DWORD     ppid      (4B)  |
 *   | th32ProcessID      (4B) | -------->  | ULONGLONG created   (8B)  |
 *   | (padding)          (4B) |            | char      name[260] (260B)|
 *   | th32DefaultHeapID  (8B) |            | int       printed   (4B)  |
 *   | th32ModuleID       (4B) |            +---------------------------+
 *   | cntThreads         (4B) |            Total: 280 Bytes (8B aligned)
 *   | th32ParentProcessID(4B) |
 *   | pcPriClassBase     (4B) |
 *   | dwFlags            (4B) |
 *   | szExeFile[260]   (260B) |
 *   +-------------------------+
 *   Total: 304 Bytes
 *   (PROCESSENTRY32W, the UNICODE variant, stores WCHAR[260] -> ~568 Bytes)
 *
 * The size saving is small (~8%), both structs are dominated by the 260-byte
 * name. The real reasons for copying out are:
 *   - Ownership: once copied, the snapshot handle can be closed immediately.
 *   - Extension: we add fields the API does not have (created, printed).
 *
 * 2. BUFFER SIZING & COMPILER DIAGNOSTIC GUARDS (MAX_PATH):
 * ----------------------------------------------------------------------------
 * Although szExeFile represents only the binary image name ("explorer.exe")
 * rather than a fully qualified path, the Win32 SDK types it as CHAR[MAX_PATH].
 *
 *   Diagnostic Risk (-Wformat-truncation, GCC):
 *   If struct proc shrinks this buffer (for example: char name[64]):
 *
 *      snprintf(dest->name, sizeof(dest->name), "%s", pe.szExeFile);
 *
 *   GCC's static analysis detects that the source buffer (260 bytes) can
 *   exceed the destination buffer (64 bytes) and emits a truncation warning.
 *   With warnings treated as errors (-Werror) the MinGW CI build fails.
 *   MSVC has no equivalent diagnostic, so this risk is GCC-only.
 *   Matching MAX_PATH guarantees zero-warning compliance across all toolchains.
 *
 * 3. TOPOLOGICAL REALITIES IN WINDOWS (Why 'printed' is required):
 * ----------------------------------------------------------------------------
 * Unlike POSIX environments where orphaned processes are automatically
 * reparented to init / systemd (PID 1), Windows maintains no strict tree
 * lifecycle invariant:
 *
 *   A. Orphan Processes:
 *      When a parent process exits, its children continue executing with their
 *      original th32ParentProcessID intact, even though that parent PID no
 *      longer exists in the active snapshot.
 *
 *   B. Aggressive PID Recycling:
 *      The Windows kernel recycles process identifiers quickly. A terminated
 *      parent's PID may be reassigned to an entirely unrelated, newer process,
 *      creating misleading ancestry or even cycles (A -> B -> A) in the graph.
 *      is_real_parent() rejects most of these by comparing creation times, but
 *      when a time is unknown (access denied) the raw PID link is trusted.
 *
 *   C. Multi-Root Forest:
 *      The result is not a single tree. Roots are [System Process] (PID 0,
 *      with System PID 4 under it) plus every orphan subtree.
 *
 *   The 'printed' flag is a visitation marker for the Depth-First Search (DFS)
 *   in print_subtree():
 *      - Set (1): the node has been emitted, never enter it again. This is
 *        what stops infinite recursion when an unresolved cycle remains.
 *      - Clear (0): not emitted yet. Orphans are already emitted as roots in
 *        pass 1; pass 2 sweeps whatever is still clear, which can only be
 *        nodes trapped in a cycle unreachable from any root.
 * ============================================================================
 */
struct proc {
    DWORD     pid;
    DWORD     ppid;
    ULONGLONG created;
    char      name[MAX_PATH];
    int       printed;
};


static struct proc g_procs[MAX_PROC];
static int g_count;

// One entry per thread, taken from the SAME snapshot as the processes
// so both lists describe the same instant (two separate snapshots could disagree)
// owner is the PID of the process this thread belongs to, prio its base priority
struct thr {
    DWORD tid;
    DWORD owner;
    LONG  prio;
};

static struct thr g_thrs[MAX_THR];
static int g_thr_count;

// Set by the -t / --threads option, read by print_subtree
static int g_show_threads;

// Asks the kernel when this process was created
// Returns the creation time as one 64-bit number, or 0 if we are not allowed to ask
static ULONGLONG query_create_time(DWORD pid) {

    // PROCESS_QUERY_LIMITED_INFORMATION is the smallest access right that
    // still allows GetProcessTimes. Asking for less means more processes say yes:
    // it even works on many protected processes where full query access is denied
    // Note: OpenProcess returns NULL on failure, NOT INVALID_HANDLE_VALUE like Toolhelp
    // Win32 is inconsistent here, always check the docs for which one an API uses
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == NULL) {
        // Typical reasons: access denied (SYSTEM processes from a non-admin shell),
        // invalid parameter (PID 0 is not a real process), or it exited meanwhile
        return 0;
    }

    // GetProcessTimes fills all four, we only need the creation time
    FILETIME created, exited, kernel, user;
    ULONGLONG t = 0;
    if (GetProcessTimes(h, &created, &exited, &kernel, &user)) {
        // FILETIME is split into two 32-bit halves for historical reasons
        // Gluing them into one 64-bit value lets us compare times with a plain <
        t = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
    }

    // Close on every path that got a handle, same rule as the snapshot handle
    CloseHandle(h);
    return t;
}

// Returns the index of the process with this PID, or -1 if it is not in the snapshot
static int find_index(DWORD pid) {

    for (int i = 0; i < g_count; i++) {
        if (g_procs[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

// Decides whether g_procs[p] really is the parent of g_procs[c]
// This is the single place where "who is whose child" is decided,
// both the root search and the child walk go through here so they never disagree
static int is_real_parent(int p, int c) {

    // A process cannot be its own parent ([System Process] lists PID 0 as its parent)
    if (p == c) {
        return 0;
    }

    // The child must at least claim this PID as its parent
    if (g_procs[c].ppid != g_procs[p].pid) {
        return 0;
    }

    // PID reuse check:
    // th32ParentProcessID is only the PID the parent HAD at creation time
    // Windows does not update it when the parent exits, and PIDs get reused,
    // so an unrelated newer process can end up holding the dead parent's PID
    // A parent can never be younger than its child, so if the "parent" was
    // created AFTER the child, that PID belongs to a different process now
    // If either time is unknown (0) we cannot prove anything and trust the PID
    if (g_procs[p].created != 0 && g_procs[c].created != 0 &&
        g_procs[p].created > g_procs[c].created) {
        return 0;
    }

    return 1;
}

// Counts how many threads in the snapshot belong to this PID
// Linear scan over all threads, called once per printed process: O(N * T)
// A few hundred processes times a few thousand threads is still instant
static int count_threads(DWORD pid) {

    int n = 0;
    for (int i = 0; i < g_thr_count; i++) {
        if (g_thrs[i].owner == pid) {
            n++;
        }
    }
    return n;
}

// Prints every thread of this PID, one line each, one level deeper than its process
// The "- " prefix keeps thread lines visually different from child processes
static void print_threads(DWORD pid, int depth) {

    for (int i = 0; i < g_thr_count; i++) {
        if (g_thrs[i].owner != pid) {
            continue;
        }
        for (int d = 0; d < depth; d++) {
            fputs("  ", stdout);
        }
        // LONG is 32-bit on Windows (also on x64), %ld matches it
        printf("- tid %lu  prio %ld\n", (unsigned long)g_thrs[i].tid, (long)g_thrs[i].prio);
    }
}

// Prints one process, then recurses into its children
// depth drives the indentation, two spaces per level
static void print_subtree(int index, int depth) {

    // Cycle guard: when creation times are unknown the reuse check above
    // cannot run, so two entries may still point at each other (A -> B -> A)
    // and plain recursion would never end. Never revisiting a node prevents that
    if (g_procs[index].printed) {
        return;
    }
    g_procs[index].printed = 1;

    for (int d = 0; d < depth; d++) {
        fputs("  ", stdout);
    }

    // DWORD is unsigned long on Windows, %lu matches it on both MSVC and MinGW
    printf("%s (%lu)  threads: %d\n", g_procs[index].name,
        (unsigned long)g_procs[index].pid, count_threads(g_procs[index].pid));

    // Threads go right under their process, before its child processes,
    // so each thread line sits next to the process that owns it
    if (g_show_threads) {
        print_threads(g_procs[index].pid, depth + 1);
    }

    // Children = every process whose real parent is us
    // Full linear scan for every node, so the whole print is O(N^2)
    // For a few hundred processes that is still well under a millisecond
    for (int i = 0; i < g_count; i++) {
        if (is_real_parent(index, i)) {
            print_subtree(i, depth + 1);
        }
    }
}

int cmd_list(int argc, char** argv) {

    // Start from a clean state in case cmd_list is ever called twice
    g_count = 0;
    g_thr_count = 0;
    g_show_threads = 0;

    // Our own options start at argv[0], main() already sliced off "winspect list"
    // Anything we do not recognize is an error, never silently ignored:
    // a typo like "--thread" should fail loudly instead of printing the wrong thing
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "-t") == 0 || strcmp(argv[a], "--threads") == 0) {
            g_show_threads = 1;
        }
        else {
            fprintf(stderr, "list: unknown option '%s'\n", argv[a]);
            fputs("usage: winspect list [-t | --threads]\n", stderr);
            return 1;
        }
    }

    // A snapshot is a frozen copy of the system at this instant
    // Processes or threads that start or exit after this call are simply not in it
    // We ask for processes AND threads in one snapshot so the two lists match
    // Gotcha: with TH32CS_SNAPTHREAD the PID argument does NOT filter threads,
    // the snapshot always holds every thread in the system, we filter by owner ourselves
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        // Note: Toolhelp returns INVALID_HANDLE_VALUE (-1) on failure, not NULL
        // GetLastError gives the real reason, print it so failures are diagnosable
        fprintf(stderr, "CreateToolhelp32Snapshot failed (error %lu)\n",
            (unsigned long)GetLastError());
        return 1;
    }

    // dwSize MUST be set before the first call or Process32First fails
    // The API uses it to know which version of the struct we compiled against,
    // same versioning trick you will see again in many Win32 structs
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    // Walk every entry of the snapshot into our own compact array
    // We copy out so we can close the snapshot handle before building the tree
    if (Process32First(snap, &pe)) {
        do {
            if (g_count >= MAX_PROC) {
                fprintf(stderr, "warning: more than %d processes, list truncated\n", MAX_PROC);
                break;
            }

            g_procs[g_count].pid = pe.th32ProcessID;
            g_procs[g_count].ppid = pe.th32ParentProcessID;
            g_procs[g_count].printed = 0;

            // Bounded copy, never strcpy (our rule from the CMake discussion)
            // Names come from other processes, never trust their length
            // snprintf always null-terminates, even when it has to truncate
            snprintf(g_procs[g_count].name, sizeof g_procs[g_count].name, "%s", pe.szExeFile);

            g_count++;
        } while (Process32Next(snap, &pe));
    }

    // Same pattern for threads: set dwSize, First, then Next until it returns FALSE
    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te)) {
        do {
            if (g_thr_count >= MAX_THR) {
                fprintf(stderr, "warning: more than %d threads, thread list truncated\n", MAX_THR);
                break;
            }

            g_thrs[g_thr_count].tid = te.th32ThreadID;
            g_thrs[g_thr_count].owner = te.th32OwnerProcessID;
            g_thrs[g_thr_count].prio = te.tpBasePri;
            g_thr_count++;
        } while (Thread32Next(snap, &te));
    }

    // We have our own copy now, the kernel object is no longer needed
    // Every path after a successful open must close it, otherwise we leak a handle
    CloseHandle(snap);

    // Second walk: ask each process for its creation time
    // Done after the snapshot, so there is a tiny window where a process exits
    // and its PID is reused before we open it. We would then read the newer
    // process's time. Rare enough to accept here, the snapshot itself has the
    // same kind of window anyway
    for (int i = 0; i < g_count; i++) {
        g_procs[i].created = query_create_time(g_procs[i].pid);
    }

    // Pass 1: print every real root
    // A root is a process with no real parent in the snapshot:
    // either the parent PID is gone (parent exited, e.g. the per-session smss.exe)
    // or it now belongs to a younger, unrelated process (PID reuse)
    for (int i = 0; i < g_count; i++) {
        int p = find_index(g_procs[i].ppid);
        if (p < 0 || !is_real_parent(p, i)) {
            print_subtree(i, 0);
        }
    }

    // Pass 2: anything still unprinted is stuck in a cycle
    // (nobody in the cycle is a root, so pass 1 never reached it)
    // Print it as its own root so no process silently disappears from the output
    for (int i = 0; i < g_count; i++) {
        if (!g_procs[i].printed) {
            print_subtree(i, 0);
        }
    }

    return 0;
}