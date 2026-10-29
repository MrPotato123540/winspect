// winspect ssn - read the service number out of an ntdll stub (read-only)
//
// A native API such as NtQueryInformationProcess is reached through a small stub
// in ntdll. The stub loads an index value, the System Service Number (SSN), into
// a register and then hands control to the kernel. On a clean x86-64 ntdll the
// stub starts with "mov r10, rcx" (bytes 4C 8B D1) followed by "mov eax, imm32"
// (byte B8 then the 4-byte SSN). So the SSN is simply the 4-byte value that
// follows the B8 byte.
//
// This command only reads and prints that value from the ntdll already mapped in
// our own address space. It does not construct or perform the kernel transition
// itself; that is out of scope. The purpose is understanding and verification -
// the output shows how to confirm the same value in WinDbg.
//
// As a side effect it checks the leading bytes. If they are not the expected
// prologue (e.g. a jump was written over them) the stub has been patched inline,
// which is the signal the verify command (Phase 8) is built on.

#include "ssn.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <stdint.h>     // uintptr_t
#include <string.h>     // memcpy

// Opcode markers of a clean stub prologue.
#define OP_MOV_R10_RCX_0 0x4C
#define OP_MOV_R10_RCX_1 0x8B
#define OP_MOV_R10_RCX_2 0xD1
#define OP_MOV_EAX_IMM32 0xB8

int cmd_ssn(int argc, char **argv)
{
    const char *name = NULL;
    int json = 0;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) json = 1;
        else if (name == NULL)              name = argv[a];
        else {
            fprintf(stderr, "ssn: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (name == NULL) {
        fputs("usage: winspect ssn <NtFunctionName> [--json]\n"
              "   e.g. winspect ssn NtQueryInformationProcess\n", stderr);
        return 1;
    }

    // ntdll is mapped into every process, including ours, so its bytes are
    // readable through a plain pointer. GetProcAddress walks ntdll's export
    // table and returns the stub's address for us.
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        fputs("ssn: ntdll.dll is not mapped (unexpected)\n", stderr);
        return 1;
    }
    FARPROC stub = GetProcAddress(ntdll, name);
    if (stub == NULL) {
        fprintf(stderr, "ssn: ntdll has no export named '%s'\n", name);
        return 1;
    }

    // ISO C forbids casting a function pointer straight to an object pointer, so
    // copy the pointer's bits into an integer and rebuild an object pointer from
    // that. This reads the stub's bytes without tripping -Wpedantic.
    uintptr_t addr;
    memcpy(&addr, &stub, sizeof addr);
    const unsigned char *p = (const unsigned char *)addr;

    // A clean stub: 4C 8B D1 (mov r10, rcx) then B8 (mov eax, imm32).
    int clean = (p[0] == OP_MOV_R10_RCX_0 && p[1] == OP_MOV_R10_RCX_1 &&
                 p[2] == OP_MOV_R10_RCX_2 && p[3] == OP_MOV_EAX_IMM32);
    DWORD ssn = clean ? ((DWORD)p[4] | ((DWORD)p[5] << 8) |
                         ((DWORD)p[6] << 16) | ((DWORD)p[7] << 24)) : 0;

    if (json) {
        fputs("{\"function\":", stdout); json_str(name);
        printf(",\"stub_address\":\"0x%016llX\"", (unsigned long long)addr);
        printf(",\"first_bytes\":\"%02X%02X%02X%02X%02X%02X%02X%02X\"",
               p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        printf(",\"hooked\":%s", clean ? "false" : "true");
        if (clean) {
            printf(",\"ssn\":%lu", (unsigned long)ssn);
        } else {
            fputs(",\"ssn\":null", stdout);
        }
        puts("}");
        return 0;
    }

    printf("function  %s\n", name);
    printf("  stub address  0x%016llX\n", (unsigned long long)addr);
    printf("  first bytes   %02X %02X %02X %02X %02X %02X %02X %02X\n",
           p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
    if (clean) {
        printf("  SSN           %lu  (0x%lX)\n", (unsigned long)ssn, (unsigned long)ssn);
        printf("  verify in WinDbg:  u ntdll!%s L3\n", name);
    } else {
        puts("  SSN           (stub prologue not recognised - possibly hooked)");
        printf("  compare with WinDbg:  u ntdll!%s L3\n", name);
    }
    return 0;
}
