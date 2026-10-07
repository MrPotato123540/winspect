// winspect list - process tree via Toolhelp
// Takes a snapshot of every running process, copies PID / parent PID / name
// into our own array, then prints it as an indented parent/child tree

#include "list.h"

#include <windows.h>
#include <tlhelp32.h>   // CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First/Next
#include <stdio.h>

// Fixed cap instead of a growing heap buffer, keeps this first version simple
// A desktop rarely runs more than a few hundred processes, 4096 is plenty of headroom
// 4096 * ~272 bytes = ~1.1 MB, lives in .bss (zero-filled at load time)
// so it costs RAM at runtime but does not make the .exe file bigger
#define MAX_PROC 4096


/*
 * ============================================================================
 * INTERNAL PROCESS TOPOLOGY NODE (struct proc)
 * ============================================================================
 *
 * 1. DATA PROJECTION & MEMORY FOOTPRINT:
 * ----------------------------------------------------------------------------
 * The Win32 Toolhelp32 API returns a heavy PROCESSENTRY32 descriptor (~560 B)
 * containing fields irrelevant to topology reconstruction (heap IDs, module
 * IDs, execution thread counts, base priority classes):
 *
 *   PROCESSENTRY32 (Win32)                 struct proc (Winspect Internal)
 *   +-----------------------+              +-----------------------+
 *   | dwSize (4B)           |              | DWORD pid       (4B)  |
 *   | cntUsage (4B)         |              | DWORD ppid      (4B)  |
 *   | th32ProcessID (4B)    | ---------->  | char  name[260] (260B)|
 *   | th32DefaultHeapID (8B)|              | int   printed   (4B)  |
 *   | th32ModuleID (4B)     |              +-----------------------+
 *   | cntThreads (4B)       |              Total: ~272 Bytes
 *   | th32ParentProcessID(4B)|
 *   | pcPriClassBase (4B)   |
 *   | dwFlags (4B)          |
 *   | szExeFile[260] (260B) |
 *   +-----------------------+
 *
 * By isolating only the coordinates required for tree building, we cut the
 * per-node memory footprint by ~50%, improving CPU L1/L2 cache line locality
 * when scanning through hundreds of active system processes.
 *
 * 2. BUFFER SIZING & COMPILER DIAGNOSTIC GUARDS (MAX_PATH):
 * ----------------------------------------------------------------------------
 * Although szExeFile represents only the binary image name ("explorer.exe")
 * rather than a fully qualified path, the Win32 SDK types it as CHAR[MAX_PATH].
 *
 *   Diagnostic Risk (-Wformat-truncation / -Wstringop-truncation):
 *   If struct proc shrinks this buffer (e.g., char name[64]) to conserve space:
 *
 *      snprintf(dest->name, sizeof(dest->name), "%s", pe.szExeFile);
 *
 *   GCC/Clang's static analysis detects that the source buffer (260 bytes) can
 *   exceed the destination buffer (64 bytes) and emits a truncation warning.
 *   In strict build environments where warnings are treated as fatal errors
 *   (/WX on MSVC, -Werror on GCC/Clang), this triggers an immediate CI failure.
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
 *      creating synthetic cycles or misleading ancestry in the process graph.
 *
 *   C. Multi-Root Forest:
 *      The system is not a single tree rooted at PID 0/4; it is a disconnected
 *      forest comprising System, System Idle, and multiple orphan subtrees.
 *
 *   The 'printed' flag serves as a traversal / visitation marker during Depth-
 *   First Search (DFS) in print_subtree():
 *      - Bit set (1): Node and its reachable subtree have been emitted.
 *      - Bit clear (0): Prevents double-emission and allows a second-pass sweep
 *        to identify and render disconnected orphan roots cleanly.
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

// Asks the kernel when this process was created
// Returns the creation time as one 64-bit number, or 0 if we are not allowed to ask
static ULONGLONG query_create_time(DWORD pid)
{
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
static int find_index(DWORD pid)
{
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
static int is_real_parent(int p, int c)
{
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

// Prints one process, then recurses into its children
// depth drives the indentation, two spaces per level
static void print_subtree(int index, int depth)
{
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
    printf("%s (%lu)\n", g_procs[index].name, (unsigned long)g_procs[index].pid);

    // Children = every process whose real parent is us
    // Full linear scan for every node, so the whole print is O(N^2)
    // For a few hundred processes that is still well under a millisecond
    for (int i = 0; i < g_count; i++) {
        if (is_real_parent(index, i)) {
            print_subtree(i, depth + 1);
        }
    }
}

int cmd_list(int argc, char** argv)
{
    // list takes no arguments yet
    (void)argc;
    (void)argv;

    // Start from a clean state in case cmd_list is ever called twice
    g_count = 0;

    // A snapshot is a frozen copy of the process list at this instant
    // Processes that start or exit after this call are simply not in it
    // TH32CS_SNAPPROCESS = processes only, the 0 (PID) is ignored for this flag
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
