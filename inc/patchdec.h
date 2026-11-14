#ifndef WINSPECT_PATCHDEC_H
#define WINSPECT_PATCHDEC_H

// Helpers for explaining WHY an image section differs from its file: group the
// differing bytes into patches and recognise the handful of instruction
// shapes an inline hook is written with. Pure byte logic (no OS calls), so it
// is unit-tested on any platform. Used by detect_image_tamper.

#include <stddef.h>
#include <stdint.h>

// One contiguous modification. Differing bytes separated by at most
// PATCH_GAP equal bytes belong to the same patch: a 5-byte jump whose middle
// byte happens to equal the original is still one patch, not two.
#define PATCH_GAP 4
typedef struct {
    uint32_t off;     // offset of the first differing byte
    uint32_t len;     // span up to and including the last differing byte
    uint32_t diff;    // differing bytes inside the span
} patch_run;

// Fills runs[0..max) with the patches between a[] and b[] (both n bytes) and
// returns how many exist in total (which can exceed max). *total_diff, when
// not NULL, receives the number of differing bytes.
unsigned patch_runs(const unsigned char *a, const unsigned char *b, size_t n,
                    patch_run *runs, unsigned max, uint32_t *total_diff);

enum patch_kind {
    PATCH_OTHER = 0,     // not a recognised control transfer
    PATCH_JMP_REL,       // E9 rel32 / EB rel8        -> target is the destination
    PATCH_CALL_REL,      // E8 rel32                   -> target is the destination
    PATCH_JMP_MEM,       // FF 25 disp32               -> target is the SLOT holding the destination
    PATCH_MOV_JMP,       // 48 B8 imm64 FF E0, 49 BB imm64 41 FF E3 -> destination
    PATCH_PUSH_RET,      // 68 imm32 C3                -> destination
};

// Decodes the instruction at code[0..n), which sits at virtual address addr.
// is64 selects how FF 25 is read (RIP-relative on x64, absolute on x86).
// Returns the kind and stores the address described above in *target.
enum patch_kind patch_decode(const unsigned char *code, size_t n, uint64_t addr,
                             int is64, uint64_t *target);

// 1 for an executable section whose in-memory bytes the Windows loader
// itself rewrites, so a disk / memory difference there says nothing about
// tampering: "fothk" (function-override thunks, Windows 11 24H2+). name is
// the 8-byte, possibly unterminated, IMAGE_SECTION_HEADER.Name.
int patch_loader_written_section(const char *name);

// Short lowercase name for a kind ("jmp", "call", "jmp [mem]", ...).
const char *patch_kind_name(enum patch_kind k);

#endif
