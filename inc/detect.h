#ifndef WINSPECT_DETECT_H
#define WINSPECT_DETECT_H

#include <windows.h>

// Shared deep-detection routines used by both `verify` and `triage`, so the
// heavy PE/memory analysis lives in one place instead of being copied.
//
// All of this is defensive and read-only: it compares what is on disk with what
// is mapped in memory and flags the differences. The *concepts* are the ones a
// memory scanner like pe-sieve uses (image tamper, IAT redirection); none of its
// code is reused - this is a clean-room reimplementation written to teach the
// idea. Nothing here injects, patches, or hides anything; it only reads.

// Result of comparing a process's main image in memory against its file on disk,
// section by section, after undoing relocations so a rebased module does not look
// modified. A non-zero modified_sections is the shape of process hollowing or an
// in-memory code patch.
#define TAMPER_MAX_PATCHES 24
#define TAMPER_PATCH_BYTES 16
struct tamper_patch {
    char     section[9];
    DWORD    rva;                // first changed byte
    DWORD    len;                // span of the patch
    DWORD    diff;               // changed bytes inside the span
    unsigned shown;              // bytes kept in disk[] / mem[]
    unsigned char disk[TAMPER_PATCH_BYTES];
    unsigned char mem[TAMPER_PATCH_BYTES];
    int      kind;               // enum patch_kind (patchdec.h)
    DWORD64  target;             // where the jump/call goes (0 = not a control transfer)
    char     target_module[64];  // module holding target; "" = unbacked (private) memory
    DWORD64  final_target;       // after following one trampoline in private memory, else 0
    char     final_module[64];
};

struct tamper_result {
    int      checked;            // 1 if the on-disk image could be read + compared
    int      modified_sections;  // executable sections whose bytes differ
    char     first_section[16];  // name of the first modified section
    unsigned diff_bytes;         // differing bytes counted in that section
    DWORD    first_diff_rva;     // RVA of the first differing byte
    char     note[128];          // why checked==0, when it is
    // The detail needed to judge a mismatch instead of guessing: every patch
    // (run of changed bytes) with the original and current bytes and, when the
    // new bytes are a jump/call, where it leads. A handful of 5..14 byte jumps
    // into a named module is a hooking product; megabytes of difference is a
    // replaced image.
    int      skipped_sections;   // executable sections left out on purpose (loader-written)
    char     skipped_section[16];// name of the last one skipped
    unsigned total_diff_bytes;   // across all executable sections
    unsigned patch_count;        // total patches found (may exceed TAMPER_MAX_PATCHES)
    unsigned npatches;           // entries filled in patches[]
    struct tamper_patch patches[TAMPER_MAX_PATCHES];
};

// Result of checking the main image's Import Address Table: each resolved slot
// should point into some loaded module. A slot pointing into unbacked (private)
// memory is the shape of an IAT hook/trampoline. We deliberately test "backed by
// ANY module" rather than "the named module", because API-set redirection makes
// the named-module test noisy on modern Windows.
struct iathook_result {
    int  checked;          // 1 if the IAT could be walked
    int  hooked_entries;   // IAT slots pointing into unbacked memory
    char first_dll[64];    // DLL of the first hooked entry
    DWORD64 first_target;  // the unbacked address the first hooked slot pointed to
    char note[128];
};

// Result of checking every thread's start address against the loaded modules.
// A thread whose Win32 start address is not inside any module is the shape of
// injected code running on its own thread (CreateRemoteThread shellcode, thread
// hijacking). We report the count and the first offender.
struct thread_result {
    int     checked;        // 1 if threads could be enumerated
    int     threads;        // total threads examined
    int     unbacked;       // threads whose start address is not in a module
    DWORD   first_tid;      // first offending thread id
    DWORD64 first_start;    // its start address
    char    note[128];
};

// Result of comparing each section's in-memory protection against the permission
// the PE header declared for it. A section that GAINED execute, or became
// writable+executable (RWX), is the shape of a patched or staged code section.
struct secperm_result {
    int      checked;
    int      mismatches;
    char     first_section[16];
    char     first_disk[8];    // header-intended "rwx"
    char     first_mem[8];     // actual in-memory "rwx"
    char     note[128];
};

// Each returns the suspicious count and fills *out. A return of 0 with
// checked==1 means "looked, found nothing".
int detect_image_tamper(HANDLE proc, struct tamper_result *out);
// Renders the patch list of a tamper result: text lines prefixed by indent, or
// a JSON array (no trailing newline). Both show at most the stored patches and
// say so when more exist. tamper_summary writes one line that characterises
// the whole difference ("3 patch(es), 15 byte(s): 3 jump(s) into foo.dll").
void detect_print_patches(const struct tamper_result *t, const char *indent);
void detect_json_patches(const struct tamper_result *t);
void detect_tamper_summary(const struct tamper_result *t, char *out, size_t n);
int detect_iat_hooks(HANDLE proc, struct iathook_result *out);
int detect_unbacked_threads(HANDLE proc, DWORD pid, struct thread_result *out);
int detect_section_perms(HANDLE proc, struct secperm_result *out);

#endif
