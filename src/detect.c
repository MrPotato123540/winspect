// winspect detect - shared deep-detection for verify and triage
//
// Two checks live here, both answering "does memory still match the file?":
//
//   detect_image_tamper - read the main module's bytes from disk and from the
//     target's memory and compare them section by section. Legitimate code does
//     not change after load, so a mismatch in an executable section is the shape
//     of process hollowing or an in-memory patch. The one honest complication is
//     relocations: if the module did not load at its preferred ImageBase, the
//     loader rewrote absolute addresses throughout the code, so a raw compare
//     would flag every relocated pointer. We undo that by applying the same
//     relocations to the on-disk copy before comparing, so only *real* edits
//     remain. (This is the idea behind pe-sieve's hook/patch scan, reimplemented
//     from scratch for teaching - no code borrowed.)
//
//   detect_iat_hooks - walk the main image's Import Address Table in memory and
//     check that each resolved function pointer lands inside some loaded module.
//     A slot pointing into unbacked (private) memory is a redirected import: an
//     IAT hook's trampoline. We test "backed by any module" rather than "the
//     module it names", because API-set redirection legitimately sends a
//     kernel32 import into kernelbase etc., which would otherwise false-positive.
//
// Everything is read-only user-mode: OpenProcess(read) + ReadProcessMemory +
// reading the file from disk. No driver, no writes to the target.

#include "detect.h"

#include <windows.h>
#include <psapi.h>      // EnumProcessModulesEx, GetModuleInformation
#include <tlhelp32.h>   // thread enumeration (CreateToolhelp32Snapshot)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// NtQueryInformationThread lives in ntdll; we declare the one info class we use.
// ThreadQuerySetWin32StartAddress (9) returns the address the thread was created
// to start at - what we validate against the module map.
#define WS_ThreadWin32StartAddress 9
typedef LONG (NTAPI *NtQIT_t)(HANDLE, int, PVOID, ULONG, PULONG);

#define DET_MAX_MODS     2048
#define DET_MAX_SCAN     (64u * 1024u * 1024u)   // cap a single section compare
#define DET_MAX_FILE     (256u * 1024u * 1024u)

// Bounded, all-or-nothing ReadProcessMemory.
static int rpm(HANDLE h, const void *remote, void *local, SIZE_T n)
{
    SIZE_T got = 0;
    return (ReadProcessMemory(h, remote, local, n, &got) && got == n) ? 1 : 0;
}

// A loaded module's address span, for the "is this address backed?" test.
struct modrange { uintptr_t base; uintptr_t end; };

static unsigned build_modules(HANDLE h, struct modrange *out, unsigned cap)
{
    HMODULE mods[DET_MAX_MODS];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(h, mods, sizeof mods, &needed, LIST_MODULES_ALL)) {
        return 0;
    }
    unsigned n = needed / sizeof(HMODULE);
    if (n > DET_MAX_MODS) {
        n = DET_MAX_MODS;
    }
    unsigned k = 0;
    for (unsigned i = 0; i < n && k < cap; i++) {
        MODULEINFO mi;
        if (GetModuleInformation(h, mods[i], &mi, sizeof mi)) {
            out[k].base = (uintptr_t)mi.lpBaseOfDll;
            out[k].end  = (uintptr_t)mi.lpBaseOfDll + mi.SizeOfImage;
            k++;
        }
    }
    return k;
}

static int addr_backed(const struct modrange *m, unsigned n, uintptr_t a)
{
    for (unsigned i = 0; i < n; i++) {
        if (a >= m[i].base && a < m[i].end) {
            return 1;
        }
    }
    return 0;
}

// Reads a whole file into a heap buffer; caller frees *buf. 0 on failure.
static int load_file(const char *path, unsigned char **buf, size_t *size)
{
    *buf = NULL;
    *size = 0;
    HANDLE f = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        return 0;
    }
    LARGE_INTEGER sz;
    int ok = 0;
    if (GetFileSizeEx(f, &sz) && sz.QuadPart > 0 && sz.QuadPart <= (LONGLONG)DET_MAX_FILE) {
        unsigned char *p = (unsigned char *)malloc((size_t)sz.QuadPart);
        if (p != NULL) {
            DWORD got = 0;
            if (ReadFile(f, p, (DWORD)sz.QuadPart, &got, NULL) && got == sz.QuadPart) {
                *buf = p;
                *size = (size_t)sz.QuadPart;
                ok = 1;
            } else {
                free(p);
            }
        }
    }
    CloseHandle(f);
    return ok;
}

// Copies len bytes at file offset off into dst if the range is inside the file.
static int file_at(const unsigned char *f, size_t fsize, size_t off, void *dst, size_t len)
{
    if (off > fsize || len > fsize - off) {
        return 0;
    }
    memcpy(dst, f + off, len);
    return 1;
}

// Section table RVA -> file offset (only the raw-backed span maps to disk).
static int rva_to_off(const IMAGE_SECTION_HEADER *s, unsigned n, DWORD rva, size_t *out)
{
    for (unsigned i = 0; i < n; i++) {
        DWORD va = s[i].VirtualAddress;
        DWORD raw = s[i].SizeOfRawData;
        if (rva >= va && rva < va + raw) {
            *out = (size_t)s[i].PointerToRawData + (rva - va);
            return 1;
        }
    }
    return 0;
}

// Applies the file's base relocations to one section copy, so a rebased module
// compares equal to disk. sec[] holds the section's disk bytes for RVA range
// [va, va+len); we add delta to every relocated field that lands inside it.
static void apply_relocs(unsigned char *sec, DWORD va, DWORD len,
                         const unsigned char *file, size_t fsize,
                         DWORD reloc_rva, DWORD reloc_size,
                         int is64, uint64_t delta,
                         const IMAGE_SECTION_HEADER *secs, unsigned nsec)
{
    if (delta == 0 || reloc_rva == 0 || reloc_size == 0) {
        return;   // loaded at preferred base: nothing was relocated
    }
    size_t ro;
    if (!rva_to_off(secs, nsec, reloc_rva, &ro)) {
        return;
    }
    size_t pos = ro;
    size_t endr = ro + reloc_size;
    if (endr > fsize) {
        endr = fsize;
    }
    while (pos + sizeof(IMAGE_BASE_RELOCATION) <= endr) {
        IMAGE_BASE_RELOCATION br;
        memcpy(&br, file + pos, sizeof br);
        if (br.SizeOfBlock < sizeof br || pos + br.SizeOfBlock > endr) {
            break;
        }
        unsigned count = (br.SizeOfBlock - (unsigned)sizeof br) / 2;
        const unsigned char *entries = file + pos + sizeof br;
        for (unsigned i = 0; i < count; i++) {
            WORD w;
            memcpy(&w, entries + i * 2, 2);
            int type = w >> 12;
            DWORD rva = br.VirtualAddress + (w & 0x0FFF);
            if (rva < va || rva >= va + len) {
                continue;
            }
            DWORD d = rva - va;
            if (is64 && type == IMAGE_REL_BASED_DIR64 && d + 8 <= len) {
                uint64_t v;
                memcpy(&v, sec + d, 8);
                v += delta;
                memcpy(sec + d, &v, 8);
            } else if (!is64 && type == IMAGE_REL_BASED_HIGHLOW && d + 4 <= len) {
                uint32_t v;
                memcpy(&v, sec + d, 4);
                v += (uint32_t)delta;
                memcpy(sec + d, &v, 4);
            }
        }
        pos += br.SizeOfBlock;
    }
}

int detect_image_tamper(HANDLE proc, struct tamper_result *out)
{
    memset(out, 0, sizeof *out);

    // Main module = the first entry EnumProcessModules returns.
    HMODULE first = NULL;
    DWORD needed = 0;
    if (!EnumProcessModulesEx(proc, &first, sizeof first, &needed, LIST_MODULES_DEFAULT) ||
        first == NULL) {
        snprintf(out->note, sizeof out->note, "cannot find the main module");
        return 0;
    }
    MODULEINFO mi;
    if (!GetModuleInformation(proc, first, &mi, sizeof mi)) {
        snprintf(out->note, sizeof out->note, "GetModuleInformation failed");
        return 0;
    }
    uintptr_t membase = (uintptr_t)mi.lpBaseOfDll;

    char path[MAX_PATH];
    if (GetModuleFileNameExA(proc, first, path, sizeof path) == 0) {
        snprintf(out->note, sizeof out->note, "cannot resolve the image path");
        return 0;
    }

    unsigned char *file = NULL;
    size_t fsize = 0;
    if (!load_file(path, &file, &fsize)) {
        snprintf(out->note, sizeof out->note, "cannot read image from disk");
        return 0;
    }

    // Parse just enough of the disk headers to find the section table, the
    // preferred ImageBase and the relocation directory.
    IMAGE_DOS_HEADER dos;
    IMAGE_FILE_HEADER fh;
    WORD magic;
    if (!file_at(file, fsize, 0, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0) {
        free(file);
        snprintf(out->note, sizeof out->note, "on-disk file is not a PE");
        return 0;
    }
    size_t nt = (size_t)dos.e_lfanew;
    DWORD sig;
    if (!file_at(file, fsize, nt, &sig, sizeof sig) || sig != IMAGE_NT_SIGNATURE ||
        !file_at(file, fsize, nt + 4, &fh, sizeof fh) ||
        !file_at(file, fsize, nt + 4 + sizeof fh, &magic, sizeof magic)) {
        free(file);
        snprintf(out->note, sizeof out->note, "on-disk PE headers are truncated");
        return 0;
    }

    size_t opt_off = nt + 4 + sizeof fh;
    int is64;
    uint64_t preferred;
    DWORD reloc_rva = 0, reloc_size = 0, n_dirs = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 opt;
        if (!file_at(file, fsize, opt_off, &opt, sizeof opt)) {
            free(file);
            snprintf(out->note, sizeof out->note, "on-disk optional header truncated");
            return 0;
        }
        is64 = 1;
        preferred = opt.ImageBase;
        n_dirs = opt.NumberOfRvaAndSizes;
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            reloc_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            reloc_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 opt;
        if (!file_at(file, fsize, opt_off, &opt, sizeof opt)) {
            free(file);
            snprintf(out->note, sizeof out->note, "on-disk optional header truncated");
            return 0;
        }
        is64 = 0;
        preferred = opt.ImageBase;
        n_dirs = opt.NumberOfRvaAndSizes;
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            reloc_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            reloc_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }
    } else {
        free(file);
        snprintf(out->note, sizeof out->note, "unknown optional header magic");
        return 0;
    }

    uint64_t delta = (uint64_t)membase - preferred;

    unsigned nsec = fh.NumberOfSections;
    if (nsec > 96) {
        nsec = 96;
    }
    size_t sec_off = opt_off + fh.SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER secs[96];
    for (unsigned i = 0; i < nsec; i++) {
        if (!file_at(file, fsize, sec_off + (size_t)i * sizeof(IMAGE_SECTION_HEADER),
                     &secs[i], sizeof(IMAGE_SECTION_HEADER))) {
            nsec = i;
            break;
        }
    }

    // False-positive guard: if the module did NOT load at its preferred base
    // (delta != 0) but carries no relocation directory, we cannot undo the
    // loader's address fix-ups, so every relocated pointer in code would look
    // "modified". Rather than cry wolf, we report that we could not verify.
    if (delta != 0 && (reloc_rva == 0 || reloc_size == 0)) {
        snprintf(out->note, sizeof out->note,
                 "image rebased but has no relocations; cannot verify reliably");
        free(file);
        return 0;   // checked stays 0 -> callers treat as "not evaluated"
    }

    out->checked = 1;

    // Compare every executable section.
    for (unsigned i = 0; i < nsec; i++) {
        if (!(secs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            continue;
        }
        DWORD va = secs[i].VirtualAddress;
        DWORD raw = secs[i].SizeOfRawData;
        DWORD vsize = secs[i].Misc.VirtualSize;
        DWORD len = (raw < vsize) ? raw : vsize;   // only the disk-backed span
        if (len == 0 || len > DET_MAX_SCAN) {
            continue;
        }
        size_t ro = secs[i].PointerToRawData;
        if (ro > fsize || len > fsize - ro) {
            continue;   // section claims more raw data than the file has
        }

        unsigned char *disk = (unsigned char *)malloc(len);
        unsigned char *mem  = (unsigned char *)malloc(len);
        if (disk == NULL || mem == NULL) {
            free(disk);
            free(mem);
            continue;
        }
        memcpy(disk, file + ro, len);
        if (!rpm(proc, (const void *)(membase + va), mem, len)) {
            free(disk);
            free(mem);
            continue;   // unreadable in memory: skip rather than guess
        }
        // Undo relocations on the disk copy so a rebased image compares equal.
        apply_relocs(disk, va, len, file, fsize, reloc_rva, reloc_size, is64, delta, secs, nsec);

        unsigned diff = 0;
        DWORD firstd = 0;
        for (DWORD b = 0; b < len; b++) {
            if (disk[b] != mem[b]) {
                if (diff == 0) {
                    firstd = va + b;
                }
                diff++;
            }
        }
        if (diff > 0) {
            if (out->modified_sections == 0) {
                memcpy(out->first_section, secs[i].Name, 8);
                out->first_section[8] = '\0';
                out->diff_bytes = diff;
                out->first_diff_rva = firstd;
            }
            out->modified_sections++;
        }
        free(disk);
        free(mem);
    }

    free(file);
    return out->modified_sections;
}

int detect_iat_hooks(HANDLE proc, struct iathook_result *out)
{
    memset(out, 0, sizeof *out);

    HMODULE first = NULL;
    DWORD needed = 0;
    if (!EnumProcessModulesEx(proc, &first, sizeof first, &needed, LIST_MODULES_DEFAULT) ||
        first == NULL) {
        snprintf(out->note, sizeof out->note, "cannot find the main module");
        return 0;
    }
    uintptr_t base = (uintptr_t)first;

    struct modrange mods[DET_MAX_MODS];
    unsigned nmods = build_modules(proc, mods, DET_MAX_MODS);
    if (nmods == 0) {
        snprintf(out->note, sizeof out->note, "cannot enumerate modules");
        return 0;
    }

    // Read the headers straight from memory (same layout as disk, not rebased).
    IMAGE_DOS_HEADER dos;
    if (!rpm(proc, (const void *)base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        snprintf(out->note, sizeof out->note, "cannot read image headers");
        return 0;
    }
    DWORD sig;
    IMAGE_FILE_HEADER fh;
    WORD magic;
    uintptr_t nt = base + (uintptr_t)dos.e_lfanew;
    if (!rpm(proc, (const void *)nt, &sig, sizeof sig) || sig != IMAGE_NT_SIGNATURE ||
        !rpm(proc, (const void *)(nt + 4), &fh, sizeof fh) ||
        !rpm(proc, (const void *)(nt + 4 + sizeof fh), &magic, sizeof magic)) {
        snprintf(out->note, sizeof out->note, "cannot read NT headers");
        return 0;
    }
    uintptr_t opt = nt + 4 + sizeof fh;
    int is64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    DWORD imp_rva = 0, n_dirs = 0;
    if (is64) {
        IMAGE_OPTIONAL_HEADER64 o;
        if (!rpm(proc, (const void *)opt, &o, sizeof o)) { return 0; }
        n_dirs = o.NumberOfRvaAndSizes;
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            imp_rva = o.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        }
    } else {
        IMAGE_OPTIONAL_HEADER32 o;
        if (!rpm(proc, (const void *)opt, &o, sizeof o)) { return 0; }
        n_dirs = o.NumberOfRvaAndSizes;
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            imp_rva = o.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        }
    }

    out->checked = 1;
    if (imp_rva == 0) {
        return 0;   // no imports: nothing to hook
    }

    for (unsigned d = 0; d < 4096; d++) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!rpm(proc, (const void *)(base + imp_rva + (uintptr_t)d * sizeof desc),
                 &desc, sizeof desc)) {
            break;
        }
        if (desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0) {
            break;   // terminator
        }
        char dll[64] = "";
        if (desc.Name != 0) {
            for (unsigned c = 0; c < sizeof dll - 1; c++) {
                char ch = 0;
                if (!rpm(proc, (const void *)(base + desc.Name + c), &ch, 1) || ch == 0) {
                    dll[c] = '\0';
                    break;
                }
                dll[c] = ch;
                dll[c + 1] = '\0';
            }
        }
        if (desc.FirstThunk == 0) {
            continue;
        }
        // Walk the resolved IAT slots in memory.
        for (unsigned e = 0; e < 8192; e++) {
            uint64_t slot = 0;
            size_t rd = is64 ? 8 : 4;
            if (!rpm(proc, (const void *)(base + desc.FirstThunk + (uintptr_t)e * (is64 ? 8 : 4)),
                     &slot, rd)) {
                break;
            }
            if (slot == 0) {
                break;   // end of this DLL's thunk array
            }
            uintptr_t target = (uintptr_t)slot;
            if (!addr_backed(mods, nmods, target)) {
                if (out->hooked_entries == 0) {
                    snprintf(out->first_dll, sizeof out->first_dll, "%s", dll);
                    out->first_target = (DWORD64)target;
                }
                out->hooked_entries++;
            }
        }
    }
    return out->hooked_entries;
}

// Builds a 3-char "rwx" string from a page-protection value's low byte.
static void prot_rwx(DWORD prot, char out[4])
{
    DWORD b = prot & 0xFF;
    int x = (b & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    int w = (b & (PAGE_READWRITE | PAGE_WRITECOPY |
                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    int r = (b & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                  PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    out[0] = r ? 'r' : '-';
    out[1] = w ? 'w' : '-';
    out[2] = x ? 'x' : '-';
    out[3] = '\0';
}

int detect_unbacked_threads(HANDLE proc, DWORD pid, struct thread_result *out)
{
    memset(out, 0, sizeof *out);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtQIT_t NtQIT = ntdll ? (NtQIT_t)(void(*)(void))GetProcAddress(ntdll, "NtQueryInformationThread") : NULL;
    if (NtQIT == NULL) {
        snprintf(out->note, sizeof out->note, "NtQueryInformationThread unavailable");
        return 0;
    }

    struct modrange mods[DET_MAX_MODS];
    unsigned nmods = build_modules(proc, mods, DET_MAX_MODS);
    if (nmods == 0) {
        snprintf(out->note, sizeof out->note, "cannot enumerate modules");
        return 0;
    }

    // Toolhelp gives us every thread in the system; we keep this process's.
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        snprintf(out->note, sizeof out->note, "thread snapshot failed");
        return 0;
    }
    THREADENTRY32 te;
    te.dwSize = sizeof te;
    out->checked = 1;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) {
                continue;
            }
            out->threads++;
            HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (th == NULL) {
                continue;
            }
            uintptr_t start = 0;
            if (NtQIT(th, WS_ThreadWin32StartAddress, &start, sizeof start, NULL) >= 0 &&
                start != 0 && !addr_backed(mods, nmods, start)) {
                if (out->unbacked == 0) {
                    out->first_tid = te.th32ThreadID;
                    out->first_start = (DWORD64)start;
                }
                out->unbacked++;
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out->unbacked;
}

int detect_section_perms(HANDLE proc, struct secperm_result *out)
{
    memset(out, 0, sizeof *out);

    HMODULE first = NULL;
    DWORD needed = 0;
    if (!EnumProcessModulesEx(proc, &first, sizeof first, &needed, LIST_MODULES_DEFAULT) ||
        first == NULL) {
        snprintf(out->note, sizeof out->note, "cannot find the main module");
        return 0;
    }
    uintptr_t base = (uintptr_t)first;

    // Read the headers from memory (same layout as disk; not rebased).
    IMAGE_DOS_HEADER dos;
    if (!rpm(proc, (const void *)base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        snprintf(out->note, sizeof out->note, "cannot read image headers");
        return 0;
    }
    uintptr_t nt = base + (uintptr_t)dos.e_lfanew;
    DWORD sig;
    IMAGE_FILE_HEADER fh;
    WORD magic;
    if (!rpm(proc, (const void *)nt, &sig, sizeof sig) || sig != IMAGE_NT_SIGNATURE ||
        !rpm(proc, (const void *)(nt + 4), &fh, sizeof fh) ||
        !rpm(proc, (const void *)(nt + 4 + sizeof fh), &magic, sizeof magic)) {
        snprintf(out->note, sizeof out->note, "cannot read NT headers");
        return 0;
    }
    uintptr_t sec = nt + 4 + sizeof fh + fh.SizeOfOptionalHeader;
    unsigned nsec = fh.NumberOfSections;
    if (nsec > 96) {
        nsec = 96;
    }

    out->checked = 1;
    for (unsigned i = 0; i < nsec; i++) {
        IMAGE_SECTION_HEADER sh;
        if (!rpm(proc, (const void *)(sec + (uintptr_t)i * sizeof sh), &sh, sizeof sh)) {
            break;
        }
        // What the header declared.
        int hx = (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        int hw = (sh.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(proc, (LPCVOID)(base + sh.VirtualAddress), &mbi, sizeof mbi) != sizeof mbi) {
            continue;
        }
        char memrwx[4];
        prot_rwx(mbi.Protect, memrwx);
        int mx = (memrwx[2] == 'x');
        int mw = (memrwx[1] == 'w');

        // Suspicious only when memory is MORE permissive in a dangerous way:
        //   - gained execute (data section now executable), or
        //   - became RWX while the header was not writable+executable.
        int suspicious = (mx && !hx) || (mx && mw && !(hx && hw));
        if (suspicious) {
            if (out->mismatches == 0) {
                memcpy(out->first_section, sh.Name, 8);
                out->first_section[8] = '\0';
                out->first_disk[0] = hx ? 'x' : '-';   // compact "x?/w?" note
                out->first_disk[1] = hw ? 'w' : '-';
                out->first_disk[2] = '\0';
                snprintf(out->first_mem, sizeof out->first_mem, "%s", memrwx);
            }
            out->mismatches++;
        }
    }
    return out->mismatches;
}
