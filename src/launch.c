// winspect launch - start a program suspended and show its entry point
//
// This is the loader's-eye view of process birth. We start the target with the
// CREATE_SUSPENDED flag: Windows creates the process and its first thread, maps
// the image, but does NOT let the thread run yet. In that frozen moment we can
// look at where execution is about to begin.
//
// Finding the entry point ties the static and dynamic worlds together:
//   1. ask the kernel for the new process's PEB (NtQueryInformationProcess)
//   2. read PEB.ImageBaseAddress - where the .exe actually landed (post-ASLR)
//   3. read that image's PE header to get AddressOfEntryPoint (an RVA)
//   4. entry virtual address = ImageBase + AddressOfEntryPoint
// Then we read the first bytes at that address and finally ResumeThread so the
// program runs normally. (This is ordinary debugger behaviour; the user chose
// the path to launch.)

#include "launch.h"

#include <windows.h>
#include <winternl.h>   // PROCESS_BASIC_INFORMATION, NtQueryInformationProcess
#include <stdio.h>

// ImageBaseAddress sits at offset 0x10 inside the 64-bit PEB (it is Reserved3[1]
// in winternl's layout). AddressOfEntryPoint sits at offset 0x28 from the start
// of the NT headers: signature(4) + IMAGE_FILE_HEADER(20) + 16 bytes into the
// Optional Header (its position is the same for PE32 and PE32+).
#define PEB_IMAGEBASE_OFFSET 0x10
#define NT_ENTRYPOINT_OFFSET 0x28

// Bounded, all-or-nothing ReadProcessMemory wrapper (same idea as inspect.c).
static int rpm(HANDLE h, const void *remote, void *local, SIZE_T n)
{
    SIZE_T got = 0;
    return (ReadProcessMemory(h, remote, local, n, &got) && got == n) ? 1 : 0;
}

int cmd_launch(int argc, char **argv)
{
    if (argc != 1) {
        fputs("usage: winspect launch <path>\n", stderr);
        return 1;
    }
    const char *path = argv[0];

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    ZeroMemory(&pi, sizeof pi);

    // lpApplicationName = path, lpCommandLine = NULL: launch exactly this file.
    if (!CreateProcessA(path, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "launch: cannot start '%s' (error %lu)\n",
                path, (unsigned long)GetLastError());
        return 1;
    }

    int rc = 1;
    printf("launched  %s\n", path);
    printf("  pid %lu, tid %lu  (suspended)\n",
           (unsigned long)pi.dwProcessId, (unsigned long)pi.dwThreadId);

    // Step 1: locate the new process's PEB.
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retlen = 0;
    NTSTATUS st = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                                            &pbi, sizeof pbi, &retlen);
    if (st < 0 || pbi.PebBaseAddress == NULL) {
        fprintf(stderr, "launch: cannot locate PEB (status 0x%08lX)\n", (unsigned long)st);
        goto resume;
    }

    // Step 2: ImageBaseAddress from the PEB (post-ASLR load address).
    BYTE *image_base = NULL;
    if (!rpm(pi.hProcess, (const BYTE *)pbi.PebBaseAddress + PEB_IMAGEBASE_OFFSET,
             &image_base, sizeof image_base) || image_base == NULL) {
        fputs("launch: cannot read ImageBaseAddress\n", stderr);
        goto resume;
    }
    printf("  ImageBase            %p\n", (void *)image_base);

    // Step 3: validate the mapped image and read AddressOfEntryPoint.
    IMAGE_DOS_HEADER dos;
    if (!rpm(pi.hProcess, image_base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fputs("launch: mapped image has no valid DOS header\n", stderr);
        goto resume;
    }
    DWORD entry_rva = 0;
    if (!rpm(pi.hProcess, image_base + dos.e_lfanew + NT_ENTRYPOINT_OFFSET,
             &entry_rva, sizeof entry_rva)) {
        fputs("launch: cannot read AddressOfEntryPoint\n", stderr);
        goto resume;
    }

    // Step 4: entry virtual address, and the first bytes that will execute.
    BYTE *entry_va = image_base + entry_rva;
    printf("  AddressOfEntryPoint  0x%08lX  (RVA)\n", (unsigned long)entry_rva);
    printf("  entry point          %p\n", (void *)entry_va);

    BYTE first[16];
    if (rpm(pi.hProcess, entry_va, first, sizeof first)) {
        printf("  first bytes          ");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", first[i]);
        }
        putchar('\n');
    }

    rc = 0;

resume:
    // Let the program run. We always resume so we never leave a frozen process
    // behind, even if reading its headers failed above.
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return rc;
}
