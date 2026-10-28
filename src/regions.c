// winspect regions - a live process's virtual memory map
//
// A process's address space is a patchwork of regions. VirtualQueryEx walks it
// region by region: for each one it reports where it is, how big it is, what it
// may be used for (read/write/execute), and what kind of memory it is:
//   - MEM_IMAGE   : part of a mapped .exe/.dll (code and data of a module)
//   - MEM_MAPPED  : a mapped data file or shared section
//   - MEM_PRIVATE : private memory (heaps, stacks, VirtualAlloc)
//
// Why this is useful beyond curiosity: executable code normally lives in
// MEM_IMAGE regions (a real module on disk backs it). A region that is BOTH
// private AND executable has code with no backing file - the shape of manually
// mapped or injected code. We flag those. (This is also what a stronger verify
// check would scan; see docs/07-verify.md.)

#include "regions.h"
#include "jsonutil.h"

#include <windows.h>
#include <psapi.h>      // GetMappedFileNameA
#include <stdio.h>
#include <stdlib.h>     // strtoul
#include <stdint.h>
#include <string.h>     // strcmp

// Builds a 3-char "rwx" string from a page-protection value. The base access
// lives in the low byte; each base constant (PAGE_READONLY, PAGE_EXECUTE_READ,
// ...) is a distinct bit there, so bit tests classify it cleanly. The high bits
// (PAGE_GUARD / PAGE_NOCACHE) are modifiers we strip off first.
static void prot_rwx(DWORD prot, char out[4])
{
    DWORD base = prot & 0xFF;
    int exec  = (base & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    int write = (base & (PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    int read  = (base & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                         PAGE_EXECUTE_WRITECOPY)) != 0;
    out[0] = read  ? 'r' : '-';
    out[1] = write ? 'w' : '-';
    out[2] = exec  ? 'x' : '-';
    out[3] = '\0';
}

// Short name for the region's type.
static const char *mem_type(DWORD type)
{
    switch (type) {
    case MEM_IMAGE:   return "image  ";
    case MEM_MAPPED:  return "mapped ";
    case MEM_PRIVATE: return "private";
    default:          return "?      ";
    }
}

// Untrimmed names for machine-readable output.
static const char *mem_type_clean(DWORD type)
{
    switch (type) {
    case MEM_IMAGE:   return "image";
    case MEM_MAPPED:  return "mapped";
    case MEM_PRIVATE: return "private";
    default:          return "unknown";
    }
}

int cmd_regions(int argc, char **argv)
{
    const char *pid_arg = NULL;
    enum out_mode mode = OUT_TEXT;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = OUT_JSON;
        else if (strcmp(argv[a], "--csv") == 0)  mode = OUT_CSV;
        else if (pid_arg == NULL)                pid_arg = argv[a];
        else {
            fprintf(stderr, "regions: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (pid_arg == NULL) {
        fputs("usage: winspect regions <pid> [--json | --csv]\n", stderr);
        return 1;
    }
    char *end = NULL;
    unsigned long pid = strtoul(pid_arg, &end, 10);
    if (end == pid_arg || *end != '\0' || pid == 0) {
        fprintf(stderr, "regions: '%s' is not a valid pid\n", pid_arg);
        return 1;
    }

    // VirtualQueryEx needs QUERY_INFORMATION; GetMappedFileName also needs VM_READ.
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h == NULL) {
        DWORD err = GetLastError();
        fprintf(stderr, "regions: cannot open pid %lu (error %lu)\n", pid, (unsigned long)err);
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "         (try an elevated console)\n");
        }
        return 1;
    }

    if (mode == OUT_TEXT) {
        printf("process  pid %lu\n\n", pid);
        printf("  %-18s %-12s %-4s %-8s %s\n", "base", "size", "perm", "type", "detail");
    } else if (mode == OUT_CSV) {
        puts("base,size,perm,type,private_exec,detail");
    } else {
        putchar('[');
    }

    uintptr_t addr = 0;
    unsigned committed = 0, suspicious = 0;
    for (unsigned guard = 0; guard < 1000000; guard++) {   // hard cap, never spin
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof mbi) != sizeof mbi) {
            break;   // past the top of the address space
        }

        uintptr_t base = (uintptr_t)mbi.BaseAddress;
        uintptr_t next = base + mbi.RegionSize;
        if (next <= addr) {
            break;   // no forward progress (overflow / wrap): stop
        }
        addr = next;

        // Only committed memory actually holds anything; skip free/reserved to
        // keep the map readable.
        if (mbi.State != MEM_COMMIT) {
            continue;
        }
        committed++;

        char rwx[4];
        prot_rwx(mbi.Protect, rwx);

        // Private + executable = code with no backing module. Flag it.
        int priv_exec = (mbi.Type == MEM_PRIVATE) && (rwx[2] == 'x');
        if (priv_exec) {
            suspicious++;
        }

        // For image/mapped regions, show the backing file path.
        char detail[MAX_PATH] = "";
        if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
            GetMappedFileNameA(h, mbi.BaseAddress, detail, sizeof detail);
        }
        if (priv_exec) {
            snprintf(detail, sizeof detail, "<= private executable (injected?)");
        }

        if (mode == OUT_TEXT) {
            printf("  0x%016llX %-12llu %-4s %-8s %s\n",
                   (unsigned long long)base, (unsigned long long)mbi.RegionSize,
                   rwx, mem_type(mbi.Type), detail);
        } else if (mode == OUT_CSV) {
            printf("0x%016llX,%llu,%s,%s,%s,",
                   (unsigned long long)base, (unsigned long long)mbi.RegionSize,
                   rwx, mem_type_clean(mbi.Type), priv_exec ? "yes" : "no");
            csv_str(detail);
            putchar('\n');
        } else {
            printf("%s{\"base\":\"0x%016llX\",\"size\":%llu,\"perm\":\"%s\",\"type\":\"%s\",\"private_exec\":%s,\"detail\":",
                   committed > 1 ? "," : "",
                   (unsigned long long)base, (unsigned long long)mbi.RegionSize,
                   rwx, mem_type_clean(mbi.Type), priv_exec ? "true" : "false");
            json_str(detail);
            putchar('}');
        }
    }

    CloseHandle(h);
    if (mode == OUT_TEXT) {
        printf("\n%u committed regions", committed);
        if (suspicious > 0) {
            printf(", %u private+executable (worth a closer look)", suspicious);
        }
        putchar('\n');
    } else if (mode == OUT_JSON) {
        puts("]");
    }
    return 0;
}
