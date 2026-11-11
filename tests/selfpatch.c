// Test helper for "verify" / "triage": a process whose own code no longer
// matches its file, in the two shapes a hooking library produces, so the
// patch report has something known to describe. It only ever writes to
// ITSELF. Modes:
//   selfpatch direct   victim() starts with "jmp replacement" (E9 rel32)
//   selfpatch tramp    victim() jumps to a private page that holds
//                      "mov rax, replacement ; jmp rax" (the usual trampoline)
// Prints "ready" and exits after 60 s.
// Build: cc tests/selfpatch.c -o selfpatch.exe   (MinGW or MSVC, x64)
#include <windows.h>
#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

static volatile int sink;

NOINLINE static int victim(int a)
{
    // Enough real instructions that 5 patched bytes stay inside the function.
    sink += a * 3;
    sink ^= a + 7;
    sink += a * 5;
    return sink + a;
}

NOINLINE static int replacement(int a)
{
    return a + 1;
}

int main(int argc, char **argv)
{
    int tramp = argc > 1 && lstrcmpiA(argv[1], "tramp") == 0;
    unsigned char *v = (unsigned char *)(void *)victim;
    unsigned char *dest = (unsigned char *)(void *)replacement;

    if (tramp) {
        unsigned char *page = (unsigned char *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (page == NULL) return 3;
        unsigned char code[12] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
        memcpy(code + 2, &dest, 8);
        memcpy(page, code, sizeof code);
        DWORD oldp;
        VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &oldp);
        dest = page;
    }

    DWORD old;
    if (!VirtualProtect(v, 16, PAGE_EXECUTE_READWRITE, &old)) return 4;
    unsigned char jmp[5] = { 0xE9, 0, 0, 0, 0 };
    LONGLONG rel64 = (LONGLONG)(dest - (v + 5));
    if (rel64 > 0x7FFFFFFFLL || rel64 < -0x7FFFFFFFLL) {
        // The private page landed further than rel32 reaches: use the 12-byte
        // absolute form in place instead (still a recognised shape).
        unsigned char abs12[12] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
        memcpy(abs12 + 2, &dest, 8);
        memcpy(v, abs12, sizeof abs12);
    } else {
        LONG rel = (LONG)rel64;
        memcpy(jmp + 1, &rel, 4);
        memcpy(v, jmp, sizeof jmp);
    }
    VirtualProtect(v, 16, old, &old);
    FlushInstructionCache(GetCurrentProcess(), v, 16);

    printf("ready %d\n", victim(41));
    fflush(stdout);
    Sleep(60000);
    return 0;
}
