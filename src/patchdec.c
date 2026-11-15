// Patch grouping and inline-hook shape recognition (see patchdec.h).
//
// This is deliberately NOT a disassembler. A hook has to redirect execution
// in very few bytes, so in practice it is one of a handful of encodings; we
// recognise exactly those and call everything else "other". Reporting "other"
// is honest: the bytes changed, but we do not pretend to know what they do.

#include "patchdec.h"

#include <string.h>

unsigned patch_runs(const unsigned char *a, const unsigned char *b, size_t n,
                    patch_run *runs, unsigned max, uint32_t *total_diff)
{
    unsigned count = 0;
    uint32_t total = 0;
    int open = 0;
    patch_run cur = { 0, 0, 0 };
    size_t last = 0;                       // offset of the last differing byte in cur
    for (size_t i = 0; i < n; i++) {
        if (a[i] == b[i]) continue;
        total++;
        if (open && i - last <= (size_t)PATCH_GAP + 1) {
            cur.len = (uint32_t)(i - cur.off + 1);
            cur.diff++;
        } else {
            if (open) {
                if (count < max) runs[count] = cur;
                count++;
            }
            cur.off = (uint32_t)i;
            cur.len = 1;
            cur.diff = 1;
            open = 1;
        }
        last = i;
    }
    if (open) {
        if (count < max) runs[count] = cur;
        count++;
    }
    if (total_diff) *total_diff = total;
    return count;
}

static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t le64(const unsigned char *p)
{
    return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32;
}

enum patch_kind patch_decode(const unsigned char *c, size_t n, uint64_t addr,
                             int is64, uint64_t *target)
{
    *target = 0;
    if (n >= 5 && (c[0] == 0xE9 || c[0] == 0xE8)) {
        // rel32 is signed and counted from the end of the 5-byte instruction.
        int64_t rel = (int32_t)le32(c + 1);
        uint64_t t = addr + 5 + (uint64_t)rel;
        *target = is64 ? t : (uint32_t)t;
        return c[0] == 0xE9 ? PATCH_JMP_REL : PATCH_CALL_REL;
    }
    if (n >= 2 && c[0] == 0xEB) {
        int64_t rel = (int8_t)c[1];
        uint64_t t = addr + 2 + (uint64_t)rel;
        *target = is64 ? t : (uint32_t)t;
        return PATCH_JMP_REL;
    }
    if (n >= 6 && c[0] == 0xFF && c[1] == 0x25) {
        // x64: slot = next instruction + disp32. x86: disp32 IS the slot address.
        if (is64) *target = addr + 6 + (uint64_t)(int64_t)(int32_t)le32(c + 2);
        else      *target = le32(c + 2);
        return PATCH_JMP_MEM;
    }
    if (n >= 12 && c[0] == 0x48 && c[1] == 0xB8 && c[10] == 0xFF && c[11] == 0xE0) {
        *target = le64(c + 2);             // mov rax, imm64 ; jmp rax
        return PATCH_MOV_JMP;
    }
    if (n >= 13 && c[0] == 0x49 && c[1] == 0xBB && c[10] == 0x41 && c[11] == 0xFF && c[12] == 0xE3) {
        *target = le64(c + 2);             // mov r11, imm64 ; jmp r11
        return PATCH_MOV_JMP;
    }
    if (n >= 7 && !is64 && c[0] == 0xB8 && c[5] == 0xFF && c[6] == 0xE0) {
        *target = le32(c + 1);             // mov eax, imm32 ; jmp eax
        return PATCH_MOV_JMP;
    }
    if (n >= 6 && c[0] == 0x68 && c[5] == 0xC3) {
        *target = le32(c + 1);             // push imm32 ; ret
        return PATCH_PUSH_RET;
    }
    return PATCH_OTHER;
}

const char *patch_kind_name(enum patch_kind k)
{
    switch (k) {
    case PATCH_JMP_REL:  return "jmp";
    case PATCH_CALL_REL: return "call";
    case PATCH_JMP_MEM:  return "jmp [mem]";
    case PATCH_MOV_JMP:  return "mov+jmp";
    case PATCH_PUSH_RET: return "push+ret";
    default:             return "other";
    }
}

int patch_loader_written_section(const char *name)
{
    char n[9];
    memcpy(n, name, 8);
    n[8] = '\0';
    return strcmp(n, "fothk") == 0;
}

int privx_weight(int regions, int rwx, int pe, int large, const char **why)
{
    *why = NULL;
    if (regions <= 0) return 0;
    if (pe > 0)    { *why = "private executable memory holds a PE header (manually / reflectively loaded module?)"; return 40; }
    if (rwx > 0)   { *why = "private memory both writable and executable (shellcode staging?)"; return 40; }
    if (large > 0) { *why = "large private executable region(s) with no backing module (injected code?)"; return 40; }
    *why = "small private executable pages only (each 64 KB or less, none writable, no PE header) - JIT stubs and thunk pools look like this";
    return 10;
}
