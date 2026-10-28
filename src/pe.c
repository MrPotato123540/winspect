// winspect pe - static PE file parser
// Reads the whole file into memory, then walks the headers by file offset:
//   DOS header -> e_lfanew -> PE signature -> File Header -> Optional Header
//   -> Section table -> Imports (IAT) -> Exports (EAT)
// Everything here is "N bytes at file offset X"; the file never runs, we only read it.

#include "pe.h"
#include "jsonutil.h"
#include "md5.h"            // imphash / rich-header fingerprints
#include "entropy.h"         // section entropy (shared, tested)
#include "pecksum.h"         // PE checksum (shared, tested)
#include "imphash_ords.h"
#include "capa.h"   // frozen ws2_32/oleaut32 ordinal tables

#include <windows.h>    // CreateFileA, ReadFile, IMAGE_* structs (from winnt.h)
#include <stdio.h>
#include <stdlib.h>     // malloc, free
#include <string.h>     // memcpy, strcmp
#include <ctype.h>      // tolower, isprint
#include <math.h>       // log2 (for section entropy)
#include <time.h>       // time (anomaly: future build timestamp)

// Refuse absurdly large inputs instead of trying to malloc them
// Normal executables are a few MB, the biggest system DLLs are tens of MB
// Staying under 4 GB also lets every chunk size fit in ReadFile's DWORD parameter
#define MAX_PE_FILE_SIZE (256u * 1024u * 1024u)

// The PE format caps the section count at 96; attacker-controlled fields that
// index "arrays of things" get a sanity cap too, so a crafted file can never
// make us loop millions of times printing garbage.
#define MAX_SECTIONS    96
#define MAX_IMPORT_DLLS 1024
#define MAX_PER_DLL     8192
#define MAX_EXPORTS     65536

// The whole file as raw bytes
// From here on every header is just "N bytes at file offset X" inside this buffer
struct pe_file {
    BYTE  *data;
    size_t size;
};

// Copies len bytes starting at file offset off into dst
// Returns 1 on success, 0 if [off, off + len) is not completely inside the file
//
// This is the ONLY way the parser touches the buffer. Why so strict:
// - The file is untrusted input. A truncated or hand-crafted PE can put any
//   number into e_lfanew or a size field; following it without a check
//   would read past the end of our buffer.
// - The check is written as "len > size - off" instead of "off + len > size"
//   because off + len can overflow and wrap around to a small, "valid" number.
//   off > size is checked first so that size - off can never underflow.
// - memcpy into a local struct instead of casting a pointer into the buffer:
//   e_lfanew can be any value, even odd, and dereferencing a misaligned
//   struct pointer is undefined behaviour in C. x64 hardware tolerates it,
//   but the compiler's optimizer is allowed to assume it never happens.
static int read_at(const struct pe_file *f, size_t off, void *dst, size_t len)
{
    if (off > f->size || len > f->size - off) {
        return 0;
    }
    memcpy(dst, f->data + off, len);
    return 1;
}

// Copies a NUL-terminated C string that starts at file offset off into buf.
// Always leaves buf NUL-terminated (even on truncation) so callers can print
// it safely. Returns 0 only if off itself is already past the end of the file.
//
// PE files are full of strings (DLL names, imported/exported symbol names) that
// live at an arbitrary offset with no length prefix, so this is the string
// counterpart of read_at: it stops at the NUL or at the file's end, whichever
// comes first, and never walks off the buffer.
static int read_cstr(const struct pe_file *f, size_t off, char *buf, size_t buflen)
{
    if (buflen == 0) {
        return 0;
    }
    if (off >= f->size) {
        buf[0] = '\0';
        return 0;
    }
    size_t max = f->size - off;           // bytes available before end of file
    if (max > buflen - 1) {
        max = buflen - 1;                 // leave room for our own terminator
    }
    size_t i = 0;
    while (i < max && f->data[off + i] != '\0') {
        buf[i] = (char)f->data[off + i];
        i++;
    }
    buf[i] = '\0';
    return 1;
}

// Reads the whole file into a heap buffer
// Returns 1 on success; on failure prints the reason and returns 0
// On success the caller owns f->data and must free() it
static int load_file(const char *path, struct pe_file *f)
{
    f->data = NULL;
    f->size = 0;

    // GENERIC_READ: we only read. We also pass the widest possible share mode
    // (READ | WRITE | DELETE) so that opening the file never fails just because
    // some other process has it open. We read the bytes once and close the
    // handle immediately, so letting others write/delete meanwhile is harmless.
    // CreateFile reports failure with INVALID_HANDLE_VALUE, like Toolhelp (not NULL)
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "pe: cannot open '%s' (error %lu)\n", path, (unsigned long)GetLastError());
        return 0;
    }

    // From here on several things can fail, and every failure must close the handle
    // (and free the buffer once it exists). Instead of repeating that cleanup in
    // every branch, all failures jump to one "fail" label at the bottom.
    // This "goto cleanup" pattern is idiomatic C, the Linux kernel uses it everywhere
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) {
        fprintf(stderr, "pe: cannot get size of '%s' (error %lu)\n", path, (unsigned long)GetLastError());
        goto fail;
    }
    if (sz.QuadPart <= 0 || sz.QuadPart > MAX_PE_FILE_SIZE) {
        fprintf(stderr, "pe: '%s' is %lld bytes, expected 1 .. %u\n",
                path, (long long)sz.QuadPart, MAX_PE_FILE_SIZE);
        goto fail;
    }

    f->size = (size_t)sz.QuadPart;
    f->data = malloc(f->size);
    if (f->data == NULL) {
        fprintf(stderr, "pe: out of memory for %zu bytes\n", f->size);
        goto fail;
    }

    // ReadFile is allowed to return fewer bytes than asked for,
    // so keep reading until the whole file is in the buffer
    size_t done = 0;
    while (done < f->size) {
        DWORD got = 0;
        DWORD want = (DWORD)(f->size - done);   // fits, the file is below 4 GB
        if (!ReadFile(h, f->data + done, want, &got, NULL)) {
            fprintf(stderr, "pe: read failed at offset %zu (error %lu)\n", done, (unsigned long)GetLastError());
            goto fail;
        }
        // ReadFile returning TRUE with got == 0 means end-of-file reached early:
        // the file shrank under us after GetFileSizeEx. GetLastError would be
        // stale here, so report this as a distinct "short read" instead.
        if (got == 0) {
            fprintf(stderr, "pe: unexpected end of file at offset %zu (file shrank?)\n", done);
            goto fail;
        }
        done += got;
    }

    CloseHandle(h);
    return 1;

fail:
    free(f->data);      // free(NULL) is a no-op, so this is safe before malloc too
    f->data = NULL;
    f->size = 0;
    CloseHandle(h);
    return 0;
}

// One named bit inside a flags field
// Same idea as the command table in main.c: data drives the output,
// so adding a flag means adding one row, not another if-statement
struct flag_name {
    DWORD       mask;
    const char *name;
};

// File Header Characteristics bits we care about (winnt.h has a few more, all legacy)
static const struct flag_name file_flags[] = {
    { IMAGE_FILE_RELOCS_STRIPPED,     "RELOCS_STRIPPED"     },  // no .reloc: cannot be moved by ASLR
    { IMAGE_FILE_EXECUTABLE_IMAGE,    "EXECUTABLE_IMAGE"    },  // linker finished successfully
    { IMAGE_FILE_LINE_NUMS_STRIPPED,  "LINE_NUMS_STRIPPED"  },  // legacy COFF bit, MS link no longer
    { IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED" },  // sets these, GNU ld (MinGW) still does
    { IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE" },  // can handle addresses above 2 GB
    { IMAGE_FILE_32BIT_MACHINE,       "32BIT_MACHINE"       },
    { IMAGE_FILE_DEBUG_STRIPPED,      "DEBUG_STRIPPED"      },
    { IMAGE_FILE_SYSTEM,              "SYSTEM"              },  // driver / system file
    { IMAGE_FILE_DLL,                 "DLL"                 },
};

// Optional Header DllCharacteristics bits. These are the modern security
// switches the OS loader reads: whether the image opts in to ASLR, DEP,
// Control Flow Guard, and so on. Missing bits here are a real security signal,
// which is why we always want to see them spelled out.
static const struct flag_name dll_flags[] = {
    { IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,       "HIGH_ENTROPY_VA"       },  // 64-bit ASLR
    { IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,          "DYNAMIC_BASE"          },  // ASLR opt-in
    { IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,       "FORCE_INTEGRITY"       },  // must be signed
    { IMAGE_DLLCHARACTERISTICS_NX_COMPAT,             "NX_COMPAT"             },  // DEP opt-in
    { IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,          "NO_ISOLATION"          },
    { IMAGE_DLLCHARACTERISTICS_NO_SEH,                "NO_SEH"                },
    { IMAGE_DLLCHARACTERISTICS_NO_BIND,               "NO_BIND"               },
    { IMAGE_DLLCHARACTERISTICS_APPCONTAINER,          "APPCONTAINER"          },  // UWP sandbox
    { IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,            "WDM_DRIVER"            },
    { IMAGE_DLLCHARACTERISTICS_GUARD_CF,              "GUARD_CF"              },  // Control Flow Guard
    { IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TERMINAL_SERVER_AWARE" },
};

// Section Characteristics bits. The low bits say what the section *contains*
// (code / initialized data / uninitialized data); the top bits are the memory
// permissions the loader will stamp onto the pages (read/write/execute/shared).
// The R/W/X trio is the interesting part: it is the file-level source of the
// DEP/NX guarantee (.text is R-X so data can't run, .data is RW- so it can't).
static const struct flag_name section_flags[] = {
    { IMAGE_SCN_CNT_CODE,               "CODE"        },  // holds machine code
    { IMAGE_SCN_CNT_INITIALIZED_DATA,   "INIT_DATA"   },  // holds data present on disk
    { IMAGE_SCN_CNT_UNINITIALIZED_DATA, "UNINIT_DATA" },  // .bss: zero-filled at load, no disk bytes
    { IMAGE_SCN_MEM_DISCARDABLE,        "DISCARDABLE" },  // can be dropped after load (e.g. .reloc)
    { IMAGE_SCN_MEM_SHARED,             "SHARED"      },  // shared across processes
};

// Prints every set bit of value by name, joined with " | "
// Bits that are set but not in the table are printed as hex so nothing is hidden
static void print_flags(DWORD value, const struct flag_name *table, size_t count)
{
    DWORD rest = value;
    int first = 1;

    for (size_t i = 0; i < count; i++) {
        if (value & table[i].mask) {
            printf("%s%s", first ? "" : " | ", table[i].name);
            rest &= ~table[i].mask;
            first = 0;
        }
    }
    if (rest != 0) {
        printf("%s0x%lX", first ? "" : " | ", (unsigned long)rest);
        first = 0;
    }
    if (first) {
        fputs("(none)", stdout);
    }
    putchar('\n');
}

// Same decomposition as print_flags, but emits a JSON array of the set bits:
// named bits by name, any leftover bits as one "0x..." hex string.
static void flags_json(DWORD value, const struct flag_name *table, size_t count)
{
    DWORD rest = value;
    int first = 1;
    putchar('[');
    for (size_t i = 0; i < count; i++) {
        if (value & table[i].mask) {
            if (!first) { putchar(','); }
            json_str(table[i].name);
            rest &= ~table[i].mask;
            first = 0;
        }
    }
    if (rest != 0) {
        char hex[16];
        snprintf(hex, sizeof hex, "0x%lX", (unsigned long)rest);
        if (!first) { putchar(','); }
        json_str(hex);
    }
    putchar(']');
}

// Human name for the Machine field (which CPU the code is compiled for)
static const char *machine_name(WORD m)
{
    switch (m) {
    case IMAGE_FILE_MACHINE_AMD64: return "AMD64 (x64)";
    case IMAGE_FILE_MACHINE_I386:  return "I386 (x86)";
    case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
    case IMAGE_FILE_MACHINE_ARMNT: return "ARM (Thumb-2)";
    default:                       return "unknown";
    }
}

// Human name for the Subsystem field (which environment the image expects).
// GUI vs CUI is the one most people meet: it decides whether launching the
// program from a shell pops a window or attaches to the console.
static const char *subsystem_name(WORD s)
{
    switch (s) {
    case IMAGE_SUBSYSTEM_NATIVE:          return "NATIVE (no subsystem, e.g. drivers)";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:     return "WINDOWS_GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:     return "WINDOWS_CUI (console)";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "EFI_APPLICATION";
    case IMAGE_SUBSYSTEM_XBOX:            return "XBOX";
    default:                              return "unknown";
    }
}

// Builds a short "rwx" permission string for a section's Characteristics.
// A dash means the bit is clear. dst must hold at least 4 bytes ("rwx\0").
// We pass a caller-owned buffer instead of returning a static one so the
// function stays reentrant (no shared state between calls).
static void section_rwx(DWORD ch, char dst[4])
{
    dst[0] = (ch & IMAGE_SCN_MEM_READ)    ? 'r' : '-';
    dst[1] = (ch & IMAGE_SCN_MEM_WRITE)   ? 'w' : '-';
    dst[2] = (ch & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-';
    dst[3] = '\0';
}

// Shannon entropy (bits per byte, 0..8) of a section's raw bytes on disk.
// It measures how "random" the bytes look: normal code/data sits around 4-6,
// while compressed or encrypted content pushes toward 8. A value above ~7.0 is
// a common heuristic for a packed/obfuscated section (tools vary: DIE uses 6.5,
// pefile 7.4). We only read the raw span that actually exists on disk.
static double section_entropy(const struct pe_file *f, const IMAGE_SECTION_HEADER *sh)
{
    size_t off = sh->PointerToRawData;
    size_t len = sh->SizeOfRawData;
    if (off > f->size) {
        return 0.0;
    }
    if (len > f->size - off) {
        len = f->size - off;      // clamp to what is really in the file
    }
    if (len == 0) {
        return 0.0;               // e.g. .bss has no raw bytes
    }
    // The entropy math itself lives in the portable, unit-tested entropy module.
    return shannon_entropy(f->data + off, len);
}

// Translates a Relative Virtual Address (an offset from ImageBase in the mapped
// image) into a file offset (an offset into the bytes on disk). This is the
// single most important helper for Phase 3, because every pointer inside the
// import and export tables is stored as an RVA, but on disk the data sits at a
// different place: sections are packed to FileAlignment on disk but spread to
// SectionAlignment in memory, so Raw offset != Virtual offset.
//
// The map is the section table: each section says "RVA range [VA, VA+size) on
// disk lives at PointerToRawData". We find the section that contains rva and
// shift by the same delta. Returns 1 and writes *out on success, 0 if no
// section covers rva or the target byte is not backed by raw data on disk.
static int rva_to_off(const IMAGE_SECTION_HEADER *sections, unsigned n,
                      DWORD rva, size_t *out)
{
    for (unsigned i = 0; i < n; i++) {
        DWORD va  = sections[i].VirtualAddress;
        DWORD raw = sections[i].SizeOfRawData;   // bytes actually on disk
        // Only the raw span is backed by file bytes. A .bss-style section can
        // have VirtualSize > SizeOfRawData; addresses past the raw span exist
        // only in memory, never on disk, so we refuse to map them.
        if (rva >= va && rva < va + raw) {
            *out = (size_t)sections[i].PointerToRawData + (rva - va);
            return 1;
        }
    }
    return 0;
}

// ---- Imports (IAT) -----------------------------------------------------------
// The import table answers "which functions does this image borrow from which
// DLLs?". It is an array of IMAGE_IMPORT_DESCRIPTOR, one per DLL, terminated by
// an all-zero entry. Each descriptor points at two parallel thunk arrays:
//   OriginalFirstThunk (INT) -> the names/ordinals the image asked for (stable)
//   FirstThunk         (IAT) -> the slots the loader overwrites with real
//                               addresses at run time
// We walk OriginalFirstThunk because on disk it still holds the names; the IAT
// is only meaningful once the loader has filled it in a live process.
static void print_imports(const struct pe_file *f,
                          const IMAGE_SECTION_HEADER *sections, unsigned n_sections,
                          int is64, DWORD dir_rva, int json, capa_sum *caps)
{
    // The high bit of a thunk means "import by ordinal number, not by name".
    // It sits at a different position for 32- vs 64-bit thunks, so pick the
    // right mask and the right entry size up front.
    const ULONGLONG ordinal_flag = is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
    const size_t    thunk_size   = is64 ? sizeof(ULONGLONG) : sizeof(DWORD);

    size_t desc_off;
    if (!rva_to_off(sections, n_sections, dir_rva, &desc_off)) {
        if (json) { putchar('['); putchar(']'); }
        else      { puts("  (import directory RVA not inside any section)"); }
        return;
    }

    if (json) { putchar('['); }
    int dll_first = 1;
    for (unsigned d = 0; d < MAX_IMPORT_DLLS; d++) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!read_at(f, desc_off + (size_t)d * sizeof desc, &desc, sizeof desc)) {
            break;
        }
        // The array is terminated by a zeroed descriptor. OriginalFirstThunk is
        // an anonymous union member in winnt.h (aka Characteristics).
        if (desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0) {
            break;
        }

        char dll[256];
        size_t name_off;
        if (rva_to_off(sections, n_sections, desc.Name, &name_off)) {
            read_cstr(f, name_off, dll, sizeof dll);
        } else {
            snprintf(dll, sizeof dll, "(bad name RVA 0x%lX)", (unsigned long)desc.Name);
        }

        // Prefer the INT (OriginalFirstThunk); fall back to the IAT if the INT
        // is absent (some linkers/bound imports leave it zero).
        DWORD thunk_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        if (json) {
            printf("%s{\"dll\":", dll_first ? "" : ",");
            json_str(dll);
            fputs(",\"functions\":[", stdout);
        } else {
            printf("  %s\n", dll);
        }
        dll_first = 0;

        size_t thunk_off;
        if (!rva_to_off(sections, n_sections, thunk_rva, &thunk_off)) {
            if (json) { fputs("]}", stdout); }
            else      { puts("    (thunk array RVA not inside any section)"); }
            continue;
        }

        int fn_first = 1;
        for (unsigned e = 0; e < MAX_PER_DLL; e++) {
            ULONGLONG value = 0;
            // Read 4 or 8 bytes depending on bitness; 32-bit zero-extends.
            if (!read_at(f, thunk_off + (size_t)e * thunk_size, &value, thunk_size)) {
                break;
            }
            if (value == 0) {
                break;                      // end of this DLL's thunk list
            }
            if (value & ordinal_flag) {
                // Imported by ordinal: the low 16 bits are the ordinal number.
                if (json) {
                    printf("%s{\"by\":\"ordinal\",\"ordinal\":%llu}",
                           fn_first ? "" : ",", (unsigned long long)(value & 0xFFFF));
                    fn_first = 0;
                } else {
                    printf("    ordinal %llu\n", (unsigned long long)(value & 0xFFFF));
                }
            } else {
                // Imported by name: the low bits are an RVA to IMAGE_IMPORT_BY_NAME
                // { WORD Hint; char Name[]; }. We print the Hint and the name.
                DWORD  by_name_rva = (DWORD)value;
                size_t by_off;
                if (rva_to_off(sections, n_sections, by_name_rva, &by_off)) {
                    WORD hint = 0;
                    read_at(f, by_off, &hint, sizeof hint);
                    char sym[256];
                    read_cstr(f, by_off + sizeof hint, sym, sizeof sym);
                    if (caps != NULL) {
                        capa_add(caps, sym);
                    }
                    if (json) {
                        printf("%s{\"by\":\"name\",\"name\":", fn_first ? "" : ",");
                        json_str(sym);
                        printf(",\"hint\":%u}", hint);
                        fn_first = 0;
                    } else {
                        printf("    %s  (hint %u)\n", sym, hint);
                    }
                } else if (!json) {
                    printf("    (bad name RVA 0x%lX)\n", (unsigned long)by_name_rva);
                }
            }
        }
        if (json) { fputs("]}", stdout); }
    }
    if (json) { putchar(']'); }
}

// ---- Exports (EAT) -----------------------------------------------------------
// The export table is the catalogue a DLL offers to the outside world. It is
// one IMAGE_EXPORT_DIRECTORY pointing at three parallel arrays:
//   AddressOfNames        -> RVAs of the exported names (sorted, for bsearch)
//   AddressOfNameOrdinals -> for each name, an index into AddressOfFunctions
//   AddressOfFunctions    -> the code RVA (or a forwarder string) per ordinal
// GetProcAddress walks exactly this trio: find the name -> read its ordinal ->
// return AddressOfFunctions[ordinal]. We reproduce that walk here.
static void print_exports(const struct pe_file *f,
                          const IMAGE_SECTION_HEADER *sections, unsigned n_sections,
                          DWORD dir_rva, DWORD dir_size, int json)
{
    size_t ed_off;
    if (!rva_to_off(sections, n_sections, dir_rva, &ed_off)) {
        if (json) { fputs("null", stdout); }
        else      { puts("  (export directory RVA not inside any section)"); }
        return;
    }
    IMAGE_EXPORT_DIRECTORY ed;
    if (!read_at(f, ed_off, &ed, sizeof ed)) {
        if (json) { fputs("null", stdout); }
        else      { puts("  (file ends inside the export directory)"); }
        return;
    }

    char dllname[256] = "";
    size_t nm_off;
    int have_name = 0;
    if (rva_to_off(sections, n_sections, ed.Name, &nm_off)) {
        read_cstr(f, nm_off, dllname, sizeof dllname);
        have_name = 1;
    }

    if (json) {
        fputs("{\"internal_name\":", stdout);
        if (have_name) { json_str(dllname); } else { fputs("null", stdout); }
        printf(",\"ordinal_base\":%lu,\"function_count\":%lu,\"name_count\":%lu,\"symbols\":[",
               (unsigned long)ed.Base, (unsigned long)ed.NumberOfFunctions,
               (unsigned long)ed.NumberOfNames);
    } else {
        if (have_name) { printf("  internal name: %s\n", dllname); }
        printf("  ordinal base: %lu, functions: %lu, names: %lu\n",
               (unsigned long)ed.Base,
               (unsigned long)ed.NumberOfFunctions,
               (unsigned long)ed.NumberOfNames);
    }

    size_t names_off, ords_off, funcs_off;
    if (!rva_to_off(sections, n_sections, ed.AddressOfNames, &names_off) ||
        !rva_to_off(sections, n_sections, ed.AddressOfNameOrdinals, &ords_off) ||
        !rva_to_off(sections, n_sections, ed.AddressOfFunctions, &funcs_off)) {
        if (json) { fputs("]}", stdout); }
        else      { puts("  (one of the export arrays is not inside any section)"); }
        return;
    }

    DWORD n_names = ed.NumberOfNames;
    if (n_names > MAX_EXPORTS) {
        n_names = MAX_EXPORTS;
    }
    int first = 1;
    for (DWORD i = 0; i < n_names; i++) {
        DWORD name_rva = 0;
        WORD  ord      = 0;      // index into AddressOfFunctions
        if (!read_at(f, names_off + (size_t)i * sizeof(DWORD), &name_rva, sizeof name_rva) ||
            !read_at(f, ords_off  + (size_t)i * sizeof(WORD),  &ord,      sizeof ord)) {
            break;
        }
        char sym[256];
        size_t sym_off;
        if (rva_to_off(sections, n_sections, name_rva, &sym_off)) {
            read_cstr(f, sym_off, sym, sizeof sym);
        } else {
            snprintf(sym, sizeof sym, "(bad name RVA 0x%lX)", (unsigned long)name_rva);
        }

        DWORD func_rva = 0;
        if (ord < ed.NumberOfFunctions) {
            read_at(f, funcs_off + (size_t)ord * sizeof(DWORD), &func_rva, sizeof func_rva);
        }

        // A forwarded export does not point at code in this DLL; its RVA lands
        // *inside the export directory itself* and names another DLL+symbol,
        // e.g. "NTDLL.RtlAllocateHeap". That is how kernel32 forwards many
        // functions to ntdll. Detect it by the RVA falling in the directory range.
        int forwarded = (func_rva >= dir_rva && func_rva < dir_rva + dir_size);
        char fwd[256] = "";
        if (forwarded) {
            size_t fwd_off;
            if (rva_to_off(sections, n_sections, func_rva, &fwd_off)) {
                read_cstr(f, fwd_off, fwd, sizeof fwd);
            }
        }

        if (json) {
            printf("%s{\"ordinal\":%lu,\"name\":",
                   first ? "" : ",", (unsigned long)(ed.Base + ord));
            json_str(sym);
            if (forwarded) {
                fputs(",\"forward\":", stdout); json_str(fwd);
            } else {
                char rva[16];
                snprintf(rva, sizeof rva, "0x%08lX", (unsigned long)func_rva);
                fputs(",\"rva\":", stdout); json_str(rva);
            }
            putchar('}');
            first = 0;
        } else if (forwarded) {
            printf("    [%lu] %s  -> forward to %s\n",
                   (unsigned long)(ed.Base + ord), sym, fwd);
        } else {
            printf("    [%lu] %s  (RVA 0x%08lX)\n",
                   (unsigned long)(ed.Base + ord), sym, (unsigned long)func_rva);
        }
    }
    if (json) { fputs("]}", stdout); }
}

// ---- Debug directory -> PDB path ---------------------------------------------
// The debug directory records where the symbols (.pdb) for this image live. The
// CODEVIEW entry embeds the PDB's path and GUID the way the build machine wrote
// it, which is a surprisingly useful fingerprint (build paths, project names).
static void print_debug(const struct pe_file *f,
                        const IMAGE_SECTION_HEADER *sections, unsigned n,
                        DWORD dir_rva, DWORD dir_size, int json)
{
    size_t off;
    if (!rva_to_off(sections, n, dir_rva, &off)) {
        if (json) { fputs("{\"pdb_path\":null}", stdout); }
        else      { puts("  (debug directory RVA not inside any section)"); }
        return;
    }
    unsigned count = dir_size / (unsigned)sizeof(IMAGE_DEBUG_DIRECTORY);
    int found = 0;
    char pdb[512] = "";
    for (unsigned i = 0; i < count && i < 64; i++) {
        IMAGE_DEBUG_DIRECTORY dd;
        if (!read_at(f, off + (size_t)i * sizeof dd, &dd, sizeof dd)) {
            break;
        }
        if (dd.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
            // CV_INFO_PDB70 = { DWORD 'RSDS'; GUID(16); DWORD Age; char Pdb[] }.
            // dd.PointerToRawData already gives the file offset of that blob.
            DWORD cvsig = 0;
            if (read_at(f, dd.PointerToRawData, &cvsig, sizeof cvsig) &&
                cvsig == 0x53445352u) {   // 'RSDS'
                read_cstr(f, (size_t)dd.PointerToRawData + 4 + 16 + 4, pdb, sizeof pdb);
                found = 1;
                if (!json) { printf("  PDB path: %s\n", pdb); }
            }
        }
    }
    if (json) {
        fputs("{\"pdb_path\":", stdout);
        if (found) { json_str(pdb); } else { fputs("null", stdout); }
        putchar('}');
    } else if (!found) {
        puts("  (no CODEVIEW/PDB entry)");
    }
}

// ---- TLS callbacks -----------------------------------------------------------
// Thread Local Storage callbacks are functions the loader runs for every thread,
// and crucially the first ones run BEFORE the image entry point. That makes them
// a classic place to hide startup code, so "are there any?" is worth knowing.
static void print_tls(const struct pe_file *f,
                      const IMAGE_SECTION_HEADER *sections, unsigned n,
                      int is64, ULONGLONG image_base, DWORD dir_rva, int json)
{
    size_t off;
    if (!rva_to_off(sections, n, dir_rva, &off)) {
        if (json) { fputs("{\"callbacks\":0}", stdout); }
        else      { puts("  (TLS directory RVA not inside any section)"); }
        return;
    }
    // AddressOfCallBacks is a virtual address (not an RVA), so subtract ImageBase
    // to get back to an RVA we can map to a file offset.
    ULONGLONG cb_va = 0;
    if (is64) {
        IMAGE_TLS_DIRECTORY64 t;
        if (!read_at(f, off, &t, sizeof t)) {
            if (json) { fputs("{\"callbacks\":0}", stdout); }
            return;
        }
        cb_va = t.AddressOfCallBacks;
    } else {
        IMAGE_TLS_DIRECTORY32 t;
        if (!read_at(f, off, &t, sizeof t)) {
            if (json) { fputs("{\"callbacks\":0}", stdout); }
            return;
        }
        cb_va = t.AddressOfCallBacks;
    }
    if (cb_va == 0) {
        if (json) { fputs("{\"callbacks\":0}", stdout); }
        else      { puts("  callbacks: none"); }
        return;
    }
    size_t cb_off;
    if (cb_va < image_base ||
        !rva_to_off(sections, n, (DWORD)(cb_va - image_base), &cb_off)) {
        if (json) { fputs("{\"callbacks\":0}", stdout); }
        else      { puts("  callbacks: (address not mappable)"); }
        return;
    }
    // The array is a NULL-terminated list of callback VAs.
    unsigned callbacks = 0;
    size_t ptr_size = is64 ? sizeof(ULONGLONG) : sizeof(DWORD);
    for (; callbacks < 256; callbacks++) {
        ULONGLONG p = 0;
        if (!read_at(f, cb_off + (size_t)callbacks * ptr_size, &p, ptr_size) || p == 0) {
            break;
        }
    }
    if (json) { printf("{\"callbacks\":%u}", callbacks); }
    else      { printf("  callbacks: %u  (run before the entry point)\n", callbacks); }
}

// ---- Security feature analysis (winchecksec-style) ---------------------------
// Build-time exploit mitigations. Most come straight from DllCharacteristics,
// but the honest answers need two more sources and some derivation:
//   - DllCharacteristics alone lies about ASLR: DYNAMIC_BASE can be set while
//     relocations are stripped, in which case the loader cannot move the image
//     and ASLR is effectively off. CFG and high-entropy VA both depend on ASLR
//     actually working, so they are gated on it too.
//   - GS (stack cookie), SafeSEH and RFG live in the LOAD CONFIG directory, whose
//     size has grown over the years. We only trust a field if the directory the
//     file declares is large enough to actually contain it (size-thresholded).
//   - CET shadow-stack compatibility lives in an "extended DLL characteristics"
//     debug entry (type 20), not in the normal header.
// This mirrors how winchecksec (Apache-2.0) reasons; the code is our own.

// Extra bits not always in <winnt.h> under every toolchain.
#ifndef IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_SEH
#define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400
#endif
#ifndef IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
#define IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS 20
#endif
#define WS_EXT_CET_COMPAT 0x0001
#define WS_EXT_EHCONT     0x0010
// GuardFlags bits for Return Flow Guard (not reliably in older winnt.h).
#define WS_GUARD_RF_INSTRUMENTED 0x00020000u
#define WS_GUARD_RF_ENABLE       0x00040000u
#define WS_GUARD_RF_STRICT       0x00080000u

struct mitigations {
    int dynamic_base;
    int aslr;               // derived
    int relocs_stripped;    // caveat for aslr
    int high_entropy_va;    // derived
    int force_integrity;
    int nx;                 // derived (+ .NET fallback)
    int isolation;
    int seh;
    int cfg;                // derived (gated on aslr)
    int gs, gs_known;       // load config SecurityCookie
    int safe_seh, safe_seh_applicable;
    int rfg, rfg_known;
    int cet_compat, cet_known;
    int ehcont;
    int dotnet;
    int authenticode;       // SECURITY dir present (NOT cryptographically verified)
};

// Reads a pointer-sized value (4 or 8 bytes) from the file at absolute offset.
static int read_ptr_field(const struct pe_file *f, size_t off, int is64, ULONGLONG *out)
{
    if (is64) {
        ULONGLONG v;
        if (!read_at(f, off, &v, sizeof v)) { return 0; }
        *out = v;
    } else {
        DWORD v;
        if (!read_at(f, off, &v, sizeof v)) { return 0; }
        *out = v;
    }
    return 1;
}

static void analyze_mitigations(const struct pe_file *f,
                                const IMAGE_SECTION_HEADER *sections, unsigned n_sections,
                                WORD dll_char, WORD file_char, WORD machine, int is64,
                                int is_dotnet, int sec_present,
                                DWORD lcfg_rva, DWORD lcfg_size,
                                DWORD dbg_rva, DWORD dbg_size,
                                struct mitigations *m)
{
    memset(m, 0, sizeof *m);

    m->dotnet          = is_dotnet;
    m->dynamic_base    = (dll_char & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    m->relocs_stripped = (file_char & IMAGE_FILE_RELOCS_STRIPPED) != 0;
    m->force_integrity = (dll_char & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0;
    m->isolation       = (dll_char & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) == 0;
    m->seh             = (dll_char & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;
    m->authenticode    = sec_present ? 1 : 0;

    // ASLR: DYNAMIC_BASE wins only if relocations are present; .NET gets ASLR
    // from the runtime even without the bit.
    if (m->dynamic_base) {
        m->aslr = m->relocs_stripped ? 0 : 1;
    } else {
        m->aslr = m->dotnet ? 1 : 0;
    }
    // High-entropy ASLR and CFG are meaningless without working ASLR.
    m->high_entropy_va = (dll_char & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) && m->aslr;
    m->cfg             = (dll_char & IMAGE_DLLCHARACTERISTICS_GUARD_CF) && m->aslr;
    // DEP/NX, with the .NET runtime fallback.
    m->nx = (dll_char & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) ? 1 : (m->dotnet ? 1 : 0);

    m->safe_seh_applicable = (machine == IMAGE_FILE_MACHINE_I386);

    // Load config: read only fields the declared directory size actually covers.
    size_t lc_off;
    if (lcfg_rva != 0 && rva_to_off(sections, n_sections, lcfg_rva, &lc_off)) {
        DWORD cookie_off = is64 ? 0x58 : 0x3C;
        DWORD cookie_end = cookie_off + (is64 ? 8 : 4);
        if (lcfg_size >= cookie_end) {
            ULONGLONG cookie = 0;
            if (read_ptr_field(f, lc_off + cookie_off, is64, &cookie)) {
                m->gs_known = 1;
                m->gs = (cookie != 0);
            }
        }
        if (m->safe_seh_applicable) {
            // 32-bit layout: SEHandlerTable @0x40, SEHandlerCount @0x44.
            DWORD seh_end = 0x48;
            if (lcfg_size >= seh_end) {
                ULONGLONG table = 0, count = 0;
                if (read_ptr_field(f, lc_off + 0x40, 0, &table) &&
                    read_ptr_field(f, lc_off + 0x44, 0, &count)) {
                    m->safe_seh = (m->seh && table != 0 && count != 0);
                }
            }
        }
        DWORD gf_off = is64 ? 0x90 : 0x58;
        DWORD gf_end = gf_off + 4;
        if (lcfg_size >= gf_end) {
            DWORD gf = 0;
            if (read_at(f, lc_off + gf_off, &gf, sizeof gf)) {
                m->rfg_known = 1;
                m->rfg = (gf & WS_GUARD_RF_INSTRUMENTED) &&
                         ((gf & WS_GUARD_RF_ENABLE) || (gf & WS_GUARD_RF_STRICT));
            }
        }
    }

    // CET / EHCONT: an "extended DLL characteristics" debug entry (type 20) whose
    // raw data is a single u16 of extended flags.
    size_t dbg_off;
    if (dbg_rva != 0 && rva_to_off(sections, n_sections, dbg_rva, &dbg_off)) {
        unsigned count = dbg_size / (unsigned)sizeof(IMAGE_DEBUG_DIRECTORY);
        for (unsigned i = 0; i < count && i < 64; i++) {
            IMAGE_DEBUG_DIRECTORY dd;
            if (!read_at(f, dbg_off + (size_t)i * sizeof dd, &dd, sizeof dd)) {
                break;
            }
            if (dd.Type == IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS) {
                WORD ext = 0;
                if (read_at(f, dd.PointerToRawData, &ext, sizeof ext)) {
                    m->cet_known  = 1;
                    m->cet_compat = (ext & WS_EXT_CET_COMPAT) != 0;
                    m->ehcont     = (ext & WS_EXT_EHCONT) != 0;
                }
                break;
            }
        }
    }
}

// ---- imphash (pefile/YARA-compatible) ----------------------------------------
// imphash is MD5 of a string built from the import table: for every imported
// symbol, "<dll>.<func>" (both lowercased), joined with commas in file order.
// The dll name has a trailing .dll/.ocx/.sys stripped; ordinal imports become
// the frozen table name (ws2_32/oleaut32) or "ord<N>". Malware analysts pivot on
// it because samples from one builder share an import layout. We reproduce
// pefile's algorithm exactly so our value matches VirusTotal/YARA.

// A tiny growable string buffer, just for assembling the imphash input.
struct sbuf { char *p; size_t len, cap; };

static int sb_reserve(struct sbuf *s, size_t extra)
{
    if (s->len + extra + 1 <= s->cap) {
        return 1;
    }
    size_t nc = s->cap ? s->cap * 2 : 256;
    while (nc < s->len + extra + 1) {
        nc *= 2;
    }
    char *np = realloc(s->p, nc);
    if (np == NULL) {
        return 0;
    }
    s->p = np;
    s->cap = nc;
    return 1;
}

static int sb_putc(struct sbuf *s, char c)
{
    if (!sb_reserve(s, 1)) { return 0; }
    s->p[s->len++] = c;
    s->p[s->len] = '\0';
    return 1;
}

// Appends a C string, lowercasing as it goes.
static int sb_put_lower(struct sbuf *s, const char *str)
{
    size_t n = strlen(str);
    if (!sb_reserve(s, n)) { return 0; }
    for (size_t i = 0; i < n; i++) {
        s->p[s->len++] = (char)tolower((unsigned char)str[i]);
    }
    s->p[s->len] = '\0';
    return 1;
}

static int compute_imphash(const struct pe_file *f,
                           const IMAGE_SECTION_HEADER *sections, unsigned n_sections,
                           int is64, DWORD dir_rva, char out[33])
{
    out[0] = '\0';
    size_t desc_off;
    if (dir_rva == 0 || !rva_to_off(sections, n_sections, dir_rva, &desc_off)) {
        return 0;
    }
    const ULONGLONG ordinal_flag = is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
    const size_t    thunk_size   = is64 ? sizeof(ULONGLONG) : sizeof(DWORD);

    struct sbuf sb = { NULL, 0, 0 };
    int any = 0;
    for (unsigned d = 0; d < MAX_IMPORT_DLLS; d++) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!read_at(f, desc_off + (size_t)d * sizeof desc, &desc, sizeof desc)) {
            break;
        }
        if (desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0) {
            break;
        }
        size_t name_off;
        if (!rva_to_off(sections, n_sections, desc.Name, &name_off)) {
            continue;
        }
        char dll[256];
        read_cstr(f, name_off, dll, sizeof dll);

        // Lowercased DLL name WITH extension drives the ordinal table lookup.
        char dll_lower[256];
        size_t dl = 0;
        for (; dll[dl] != '\0' && dl < sizeof dll_lower - 1; dl++) {
            dll_lower[dl] = (char)tolower((unsigned char)dll[dl]);
        }
        dll_lower[dl] = '\0';
        // The "<dll>." prefix uses the name WITHOUT a trailing .dll/.ocx/.sys.
        // That exact rule (shared, unit-tested) lives in the imphash module.
        char libname[256];
        imphash_libname(dll, libname, sizeof libname);

        DWORD thunk_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        size_t thunk_off;
        if (!rva_to_off(sections, n_sections, thunk_rva, &thunk_off)) {
            continue;
        }
        for (unsigned e = 0; e < MAX_PER_DLL; e++) {
            ULONGLONG value = 0;
            if (!read_at(f, thunk_off + (size_t)e * thunk_size, &value, thunk_size)) {
                break;
            }
            if (value == 0) {
                break;
            }
            char func[256];
            if (value & ordinal_flag) {
                unsigned ord = (unsigned)(value & 0xFFFF);
                const char *nm = imphash_ord_name(dll_lower, ord);
                if (nm != NULL) {
                    snprintf(func, sizeof func, "%s", nm);
                } else {
                    snprintf(func, sizeof func, "ord%u", ord);
                }
            } else {
                DWORD by_rva = (DWORD)value;
                size_t by_off;
                if (!rva_to_off(sections, n_sections, by_rva, &by_off)) {
                    continue;
                }
                WORD hint = 0;
                read_at(f, by_off, &hint, sizeof hint);
                read_cstr(f, by_off + sizeof hint, func, sizeof func);
            }
            if (func[0] == '\0') {
                continue;
            }
            if (any && !sb_putc(&sb, ',')) { goto oom; }
            if (!sb_put_lower(&sb, libname) || !sb_putc(&sb, '.') ||
                !sb_put_lower(&sb, func)) {
                goto oom;
            }
            any = 1;
        }
    }
    if (any && sb.p != NULL) {
        md5_hex((const unsigned char *)sb.p, sb.len, out);
    }
    free(sb.p);
    return any;
oom:
    free(sb.p);
    out[0] = '\0';
    return 0;
}

// Export hash: MD5 of the DLL's exported names, lowercased and comma-joined, in
// export order (the pefile `get_exphash` idea). Where imphash fingerprints what a
// binary imports, exphash fingerprints what a library offers - useful for
// clustering related DLLs. Returns 1 and fills out[33] when there are names.
static int compute_exphash(const struct pe_file *f,
                           const IMAGE_SECTION_HEADER *sections, unsigned n_sections,
                           DWORD dir_rva, char out[33])
{
    out[0] = '\0';
    size_t ed_off;
    if (dir_rva == 0 || !rva_to_off(sections, n_sections, dir_rva, &ed_off)) {
        return 0;
    }
    IMAGE_EXPORT_DIRECTORY ed;
    if (!read_at(f, ed_off, &ed, sizeof ed)) {
        return 0;
    }
    size_t names_off;
    if (!rva_to_off(sections, n_sections, ed.AddressOfNames, &names_off)) {
        return 0;
    }
    DWORD n_names = ed.NumberOfNames;
    if (n_names > MAX_EXPORTS) {
        n_names = MAX_EXPORTS;
    }
    struct sbuf sb = { NULL, 0, 0 };
    int any = 0;
    for (DWORD i = 0; i < n_names; i++) {
        DWORD name_rva = 0;
        if (!read_at(f, names_off + (size_t)i * sizeof(DWORD), &name_rva, sizeof name_rva)) {
            break;
        }
        size_t sym_off;
        if (!rva_to_off(sections, n_sections, name_rva, &sym_off)) {
            continue;
        }
        char sym[256];
        read_cstr(f, sym_off, sym, sizeof sym);
        if (sym[0] == '\0') {
            continue;
        }
        if (any && !sb_putc(&sb, ',')) { goto oom; }
        if (!sb_put_lower(&sb, sym)) { goto oom; }
        any = 1;
    }
    if (any && sb.p != NULL) {
        md5_hex((const unsigned char *)sb.p, sb.len, out);
    }
    free(sb.p);
    return any;
oom:
    free(sb.p);
    out[0] = '\0';
    return 0;
}

// ---- .NET / CLR header (IMAGE_COR20_HEADER) ----------------------------------
// A managed image points IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR at a COR20 header:
// the CLR's own road map. We read its first fields - the runtime version it
// targets, its flags (IL-only, 32-bit required, strong-name signed, native
// entry) and the managed entry-point token. Layout is stable and documented, so
// we declare just the leading fields we print rather than pull in corhdr.h.
struct ws_cor20 {
    DWORD cb;
    WORD  major_runtime;
    WORD  minor_runtime;
    DWORD meta_rva;
    DWORD meta_size;
    DWORD flags;
    DWORD entry_token;      // or native entry-point RVA when NATIVE_ENTRYPOINT set
};
#define WS_COR_ILONLY          0x00000001u
#define WS_COR_32BITREQUIRED   0x00000002u
#define WS_COR_IL_LIBRARY      0x00000004u
#define WS_COR_STRONGNAMESIGNED 0x00000008u
#define WS_COR_NATIVE_ENTRY    0x00000010u
#define WS_COR_32BITPREFERRED  0x00020000u

struct dotnet_info {
    int      present;
    unsigned major, minor;
    DWORD    flags;
    DWORD    entry_token;
};

static void parse_dotnet(const struct pe_file *f,
                         const IMAGE_SECTION_HEADER *sections, unsigned n_sections,
                         DWORD com_rva, struct dotnet_info *out)
{
    memset(out, 0, sizeof *out);
    size_t off;
    if (com_rva == 0 || !rva_to_off(sections, n_sections, com_rva, &off)) {
        return;
    }
    struct ws_cor20 h;
    if (!read_at(f, off, &h, sizeof h)) {
        return;
    }
    out->present = 1;
    out->major = h.major_runtime;
    out->minor = h.minor_runtime;
    out->flags = h.flags;
    out->entry_token = h.entry_token;
}

// ---- Rich header -------------------------------------------------------------
// Microsoft linkers stamp an obfuscated block between the DOS stub and the PE
// header recording every MS tool (compiler, assembler, linker) that touched the
// object files, each as a (product-id, build, use-count) triple. It is a strong
// toolchain fingerprint for clustering/attribution. The block runs from a "DanS"
// marker to a "Rich" marker; everything is XOR'd with a 4-byte key stored right
// after "Rich". We reproduce pefile's decode, including its Rich hash = MD5 of
// the de-obfuscated bytes.

#define RICH_DANS 0x536E6144u    // 'DanS'
#define RICH_RICH 0x68636952u    // 'Rich'

struct rich_entry { unsigned product_id; unsigned build; unsigned count; };
struct rich_info {
    int           present;
    int           malformed;
    unsigned long key;
    char          hash[33];
    struct rich_entry ents[256];
    unsigned      n;
};

static DWORD le32(const unsigned char *p)
{
    return (DWORD)p[0] | ((DWORD)p[1] << 8) | ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

static int find_bytes(const unsigned char *hay, size_t start, size_t end,
                      const unsigned char *needle, size_t nlen, size_t *out)
{
    if (end < nlen || start > end - nlen) {
        return 0;
    }
    for (size_t i = start; i + nlen <= end; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            *out = i;
            return 1;
        }
    }
    return 0;
}

static void compute_rich(const struct pe_file *f, size_t e_lfanew, struct rich_info *ri)
{
    memset(ri, 0, sizeof *ri);
    size_t limit = (e_lfanew <= f->size) ? e_lfanew : f->size;

    // "Rich" footer: search from 0x50 up to the PE header.
    size_t rich_at;
    static const unsigned char RICH_SIG[4] = { 'R', 'i', 'c', 'h' };
    if (limit < 0x50 + 8 ||
        !find_bytes(f->data, 0x50, limit, RICH_SIG, 4, &rich_at) ||
        rich_at + 8 > f->size) {
        return;
    }
    const unsigned char *key = f->data + rich_at + 4;   // 4 key bytes
    ri->key = le32(key);

    // "DanS" start marker, XOR-encoded with the key. If not found, fall back to
    // the classic default stub layout (0x80).
    unsigned char enc_dans[4] = {
        (unsigned char)('D' ^ key[0]), (unsigned char)('a' ^ key[1]),
        (unsigned char)('n' ^ key[2]), (unsigned char)('S' ^ key[3])
    };
    size_t dans_at;
    if (!find_bytes(f->data, 0x40, limit, enc_dans, 4, &dans_at)) {
        dans_at = 0x80;
    }
    if (dans_at + 16 > rich_at) {
        return;   // no room for DanS + the 3 checksum dwords before "Rich"
    }
    ri->present = 1;

    // Rich hash = MD5 of the de-obfuscated bytes from DanS up to "Rich".
    size_t raw_len = rich_at - dans_at;
    unsigned char *clear = (unsigned char *)malloc(raw_len ? raw_len : 1);
    if (clear != NULL) {
        for (size_t i = 0; i < raw_len; i++) {
            clear[i] = (unsigned char)(f->data[dans_at + i] ^ key[i % 4]);
        }
        md5_hex(clear, raw_len, ri->hash);
        free(clear);
    }

    // Validation: DanS^key then the key repeated 3x.
    if (le32(f->data + dans_at) != (RICH_DANS ^ ri->key) ||
        le32(f->data + dans_at + 4) != ri->key ||
        le32(f->data + dans_at + 8) != ri->key ||
        le32(f->data + dans_at + 12) != ri->key) {
        ri->malformed = 1;
    }

    // Entries: (comp_id, count) pairs after the 4 leading dwords, until "Rich".
    for (size_t off = dans_at + 16; off + 8 <= rich_at && ri->n < 256; off += 8) {
        DWORD v0 = le32(f->data + off);
        if (v0 == RICH_RICH) {
            break;
        }
        DWORD comp_id = v0 ^ ri->key;
        DWORD count   = le32(f->data + off + 4) ^ ri->key;
        ri->ents[ri->n].product_id = comp_id >> 16;
        ri->ents[ri->n].build      = comp_id & 0xFFFF;
        ri->ents[ri->n].count      = count;
        ri->n++;
    }
}

// ---- Version info resource ---------------------------------------------------
// The RT_VERSION resource carries the human-facing identity of the file:
// CompanyName, ProductName, OriginalFilename, FileVersion, FileDescription. The
// single most useful one for triage is OriginalFilename: the name the author
// shipped the binary as. When it disagrees with the name on disk (svchost.exe on
// disk whose OriginalFilename is something else), that is a classic masquerade
// tell. The data lives behind a resource directory tree and then a nested,
// 4-byte-aligned, UTF-16 node structure (VS_VERSIONINFO) that is notoriously
// fiddly, so every read here is bounds-checked against the blob.

struct verinfo {
    int  present;
    char company[256];
    char product[256];
    char original_filename[256];
    char internal_name[256];
    char file_version[128];
    char product_version[128];
    char file_description[256];
    char legal_copyright[256];
};

// Reads a UTF-16LE NUL-terminated string from blob[off..] into a UTF-8 buffer.
// Sets *consumed to the byte count INCLUDING the 2-byte terminator. Returns 0 if
// the string runs past the blob (no terminator in bounds).
static int w2u8(const unsigned char *blob, size_t size, size_t off,
                char *out, size_t outsz, size_t *consumed)
{
    size_t i = off;
    while (i + 1 < size) {
        if (blob[i] == 0 && blob[i + 1] == 0) {
            break;
        }
        i += 2;
    }
    if (i + 1 >= size) {
        return 0;   // no terminator within bounds
    }
    size_t wchars = (i - off) / 2;   // not counting terminator
    *consumed = (i + 2) - off;
    if (wchars == 0) {
        if (outsz > 0) { out[0] = '\0'; }
        return 1;
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, (const WCHAR *)(blob + off), (int)wchars,
                                out, (int)outsz - 1, NULL, NULL);
    if (n < 0) { n = 0; }
    out[n] = '\0';
    return 1;
}

static size_t align4(size_t x) { return (x + 3) & ~(size_t)3; }

// Reads a WORD at a bounded offset; returns 0 (and sets *ok=0) if out of range.
static WORD blob_u16(const unsigned char *blob, size_t size, size_t off, int *ok)
{
    if (off + 2 > size) { *ok = 0; return 0; }
    return (WORD)(blob[off] | (blob[off + 1] << 8));
}

// Compares the UTF-16LE key at off against an ASCII literal.
static int key_is(const unsigned char *blob, size_t size, size_t off, const char *ascii)
{
    for (size_t i = 0; ascii[i] != '\0'; i++) {
        if (off + 2 > size) { return 0; }
        WORD w = (WORD)(blob[off] | (blob[off + 1] << 8));
        if (w != (WORD)(unsigned char)ascii[i]) { return 0; }
        off += 2;
    }
    // key must terminate (NUL wchar) right after the literal
    if (off + 2 > size) { return 0; }
    return blob[off] == 0 && blob[off + 1] == 0;
}

// Copies one extracted key/value pair into the right struct field.
static void vi_store(struct verinfo *vi, const char *key, const char *val)
{
    struct { const char *k; char *dst; size_t n; } map[] = {
        { "CompanyName",      vi->company,           sizeof vi->company },
        { "ProductName",      vi->product,           sizeof vi->product },
        { "OriginalFilename", vi->original_filename, sizeof vi->original_filename },
        { "InternalName",     vi->internal_name,     sizeof vi->internal_name },
        { "FileVersion",      vi->file_version,      sizeof vi->file_version },
        { "ProductVersion",   vi->product_version,   sizeof vi->product_version },
        { "FileDescription",  vi->file_description,  sizeof vi->file_description },
        { "LegalCopyright",   vi->legal_copyright,   sizeof vi->legal_copyright },
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) {
        if (strcmp(key, map[i].k) == 0) {
            snprintf(map[i].dst, map[i].n, "%s", val);
            return;
        }
    }
}

// Parses the children of a StringTable node: a run of String nodes, each a
// (key = field name, value = UTF-16 text) pair.
static void parse_string_table(const unsigned char *blob, size_t size,
                               size_t start, size_t end, struct verinfo *vi)
{
    size_t off = start;
    while (off + 6 <= end) {
        int ok = 1;
        WORD wLength = blob_u16(blob, size, off, &ok);
        WORD wValLen = blob_u16(blob, size, off + 2, &ok);
        if (!ok || wLength == 0) {
            break;   // malformed / end
        }
        size_t node_end = off + wLength;
        if (node_end > end) { node_end = end; }

        char key[128], val[256];
        size_t consumed = 0;
        if (!w2u8(blob, size, off + 6, key, sizeof key, &consumed)) {
            break;
        }
        size_t voff = align4(off + 6 + consumed);
        // wValLen for string values is a COUNT OF CHARACTERS; but the value is
        // also NUL-terminated, so a bounded w2u8 reads it correctly.
        if (wValLen > 0) {
            size_t vconsumed = 0;
            if (w2u8(blob, size, voff, val, sizeof val, &vconsumed)) {
                vi_store(vi, key, val);
            }
        }
        off = align4(node_end);
        if (off <= start && off >= end) { break; }   // no progress guard
    }
}

static void parse_version_info(const struct pe_file *f,
                               const IMAGE_SECTION_HEADER *sections, unsigned n_sections,
                               DWORD rsrc_rva, struct verinfo *vi)
{
    memset(vi, 0, sizeof *vi);
    if (rsrc_rva == 0) { return; }
    size_t base;
    if (!rva_to_off(sections, n_sections, rsrc_rva, &base)) { return; }

    // --- Walk the 3-level resource tree to the RT_VERSION (type 16) leaf. ---
    // Level 1: find the id entry whose Name == 16.
    int ok = 1;
    WORD named = blob_u16(f->data, f->size, base + 12, &ok);
    WORD ids   = blob_u16(f->data, f->size, base + 14, &ok);
    if (!ok) { return; }
    size_t entries = base + 16;
    size_t ver_sub = 0;
    for (unsigned i = 0; i < (unsigned)(named + ids); i++) {
        size_t e = entries + (size_t)i * 8;
        if (e + 8 > f->size) { return; }
        DWORD name = le32(f->data + e);
        DWORD offd = le32(f->data + e + 4);
        if (i >= named && name == 16 && (offd & 0x80000000u)) {   // id entry, RT_VERSION, subdir
            ver_sub = base + (offd & 0x7FFFFFFFu);
            break;
        }
    }
    if (ver_sub == 0) { return; }

    // Level 2 (name) -> take first entry -> must be a subdir.
    WORD n2 = blob_u16(f->data, f->size, ver_sub + 12, &ok);
    WORD i2 = blob_u16(f->data, f->size, ver_sub + 14, &ok);
    if (!ok || (n2 + i2) == 0) { return; }
    DWORD off2 = le32(f->data + ver_sub + 16 + 4);
    if (!(off2 & 0x80000000u)) { return; }
    size_t lang_sub = base + (off2 & 0x7FFFFFFFu);

    // Level 3 (language) -> first entry -> leaf data entry.
    WORD n3 = blob_u16(f->data, f->size, lang_sub + 12, &ok);
    WORD i3 = blob_u16(f->data, f->size, lang_sub + 14, &ok);
    if (!ok || (n3 + i3) == 0) { return; }
    if (lang_sub + 16 + 8 > f->size) { return; }
    DWORD off3 = le32(f->data + lang_sub + 16 + 4);
    if (off3 & 0x80000000u) { return; }   // expected a leaf, got a subdir
    size_t leaf = base + (off3 & 0x7FFFFFFFu);
    if (leaf + 8 > f->size) { return; }

    DWORD data_rva = le32(f->data + leaf);        // this is an RVA, not base-relative
    DWORD data_sz  = le32(f->data + leaf + 4);
    size_t vi_off;
    if (data_sz == 0 || data_sz > 64 * 1024 ||
        !rva_to_off(sections, n_sections, data_rva, &vi_off) ||
        vi_off + data_sz > f->size) {
        return;
    }

    // --- Parse the VS_VERSIONINFO blob (work on a bounded copy). ---
    const unsigned char *blob = f->data + vi_off;
    size_t size = data_sz;

    // Root node: header(6) + key "VS_VERSION_INFO".
    if (!key_is(blob, size, 6, "VS_VERSION_INFO")) { return; }
    int ok2 = 1;
    WORD root_vallen = blob_u16(blob, size, 2, &ok2);
    if (!ok2) { return; }
    // key "VS_VERSION_INFO" = 15 wchars + NUL = 32 bytes; after header that is 6+32=38.
    size_t after_key = align4(6 + (15 + 1) * 2);
    size_t child = align4(after_key + root_vallen);   // skip VS_FIXEDFILEINFO if present
    vi->present = 1;

    // Children: StringFileInfo / VarFileInfo. We only want StringFileInfo.
    while (child + 6 <= size) {
        int c_ok = 1;
        WORD wLength = blob_u16(blob, size, child, &c_ok);
        if (!c_ok || wLength == 0) { break; }
        size_t node_end = child + wLength;
        if (node_end > size) { node_end = size; }

        if (key_is(blob, size, child + 6, "StringFileInfo")) {
            // Its children are StringTable nodes; theirs are String nodes.
            size_t st = align4(child + 6 + (14 + 1) * 2);   // "StringFileInfo" = 14 wchars
            while (st + 6 <= node_end) {
                int s_ok = 1;
                WORD stLen = blob_u16(blob, size, st, &s_ok);
                if (!s_ok || stLen == 0) { break; }
                size_t st_end = st + stLen;
                if (st_end > node_end) { st_end = node_end; }
                // StringTable key is an 8-char hex lang/codepage id.
                char lk[32];
                size_t lkc = 0;
                if (!w2u8(blob, size, st + 6, lk, sizeof lk, &lkc)) { break; }
                size_t str_start = align4(st + 6 + lkc);
                parse_string_table(blob, size, str_start, st_end, vi);
                st = align4(st_end);
            }
        }
        child = align4(node_end);
    }
}

// ---- Anomaly scanner (pefile-style "warnings") -------------------------------
// A PE file's headers can disagree with themselves in ways a normal compiler and
// linker never produce. None of these is proof of anything on its own, but each
// is a "why is this here?" worth surfacing - the idea behind pefile's `warnings`.
// All of it is pure static reading of the already-loaded file buffer.

// The standard PE checksum (the same value CheckSumMappedFile computes): a 16-bit
// ones-complement-style word sum over the whole file with the 4 CheckSum bytes
// treated as zero, folded and then added to the file size.
// The checksum algorithm itself lives in the portable, unit-tested pecksum
// module (inc/pecksum.h).

struct pe_anom { const char *type; char detail[160]; };

static int collect_anomalies(const struct pe_file *f, const IMAGE_SECTION_HEADER *s,
                             unsigned n, DWORD ts, DWORD entry_rva, int is_dll,
                             size_t opt_off, struct pe_anom *a, int cap)
{
    int na = 0;
    (void)is_dll;
    #define PUSH(t, ...) do { \
        if (na < cap) { a[na].type = (t); \
            snprintf(a[na].detail, sizeof a[na].detail, __VA_ARGS__); na++; } } while (0)

    // 1. PE checksum: 0 means "not set" (common), so only a non-zero mismatch
    //    is interesting - it means the file was edited after linking.
    size_t csfield = opt_off + 64;   // CheckSum sits at optional-header offset 64
    if (csfield + 4 <= f->size) {
        DWORD stored = 0;
        memcpy(&stored, f->data + csfield, 4);
        DWORD comp = pe_checksum(f->data, f->size, csfield);
        if (stored != 0 && stored != comp) {
            PUSH("checksum", "PE checksum mismatch: header 0x%08lX, computed 0x%08lX",
                 (unsigned long)stored, (unsigned long)comp);
        }
    }

    // 2. Entry point should land inside a section.
    if (entry_rva != 0) {
        int inside = 0;
        for (unsigned i = 0; i < n; i++) {
            DWORD va = s[i].VirtualAddress;
            DWORD sz = s[i].Misc.VirtualSize ? s[i].Misc.VirtualSize : s[i].SizeOfRawData;
            if (entry_rva >= va && entry_rva < va + sz) { inside = 1; break; }
        }
        if (!inside) {
            PUSH("entry-point", "entry point RVA 0x%lX is not inside any section",
                 (unsigned long)entry_rva);
        }
    }

    // 3/4/5: per-section shapes.
    const char *packer_seen = NULL;     // report each packer once, not per section
    for (unsigned i = 0; i < n; i++) {
        char name[9];
        memcpy(name, s[i].Name, 8);
        name[8] = '\0';
        int wx = (s[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
                 (s[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
        if (wx) {
            PUSH("wx-section", "section '%.8s' is both writable and executable (W^X violation)", name);
        }
        if ((s[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && s[i].SizeOfRawData == 0) {
            PUSH("empty-code", "executable section '%.8s' has no raw data (unpacked at runtime?)", name);
        }
        int badname = 0;
        for (int c = 0; c < 8 && s[i].Name[c] != 0; c++) {
            if (!isprint((unsigned char)s[i].Name[c])) { badname = 1; break; }
        }
        if (badname) {
            PUSH("section-name", "section %u has a non-printable name", i);
        }
        const char *packer = capa_packer_section(name);
        if (packer != NULL && packer != packer_seen) {
            packer_seen = packer;
            PUSH("packer", "section '%.8s' is typical of %s (packed: real imports/strings hidden)",
                 name, packer);
        }
    }

    // 6. Overlapping sections in the virtual address space.
    for (unsigned i = 0; i < n; i++) {
        DWORD ai = s[i].VirtualAddress;
        DWORD az = s[i].Misc.VirtualSize ? s[i].Misc.VirtualSize : s[i].SizeOfRawData;
        for (unsigned j = i + 1; j < n; j++) {
            DWORD bi = s[j].VirtualAddress;
            DWORD bz = s[j].Misc.VirtualSize ? s[j].Misc.VirtualSize : s[j].SizeOfRawData;
            if (ai < bi + bz && bi < ai + az) {
                PUSH("overlap", "sections '%.8s' and '%.8s' overlap in memory",
                     s[i].Name, s[j].Name);
            }
        }
    }

    // 7. A build timestamp in the future is impossible for an honest build.
    if (ts != 0 && (time_t)ts > time(NULL)) {
        PUSH("timestamp", "build timestamp 0x%08lX is in the future", (unsigned long)ts);
    }

    #undef PUSH
    return na;
}

// The application manifest (RT_MANIFEST resource) carries the requested
// execution level - asInvoker / requireAdministrator / highestAvailable - which
// is the "does this ask for elevation at launch?" fact. The manifest is embedded
// as literal XML, so rather than re-walk the resource tree we scan the file for
// the requestedExecutionLevel element; it is distinctive enough to be reliable.
// Returns NULL when no manifest level is found.
static const char *manifest_exec_level(const struct pe_file *f)
{
    static const char key[] = "requestedExecutionLevel";
    size_t klen = sizeof key - 1;
    const unsigned char *d = f->data;
    size_t n = f->size;
    for (size_t i = 0; i + klen <= n; i++) {
        if (memcmp(d + i, key, klen) != 0) {
            continue;
        }
        size_t end = i + klen + 256;
        if (end > n) { end = n; }
        for (size_t j = i + klen; j + 7 <= end; j++) {
            if (memcmp(d + j, "level=\"", 7) != 0) {
                continue;
            }
            size_t v = j + 7;
            if (v + 20 <= n && memcmp(d + v, "requireAdministrator", 20) == 0) return "requireAdministrator";
            if (v + 16 <= n && memcmp(d + v, "highestAvailable", 16) == 0)    return "highestAvailable";
            if (v + 9  <= n && memcmp(d + v, "asInvoker", 9) == 0)            return "asInvoker";
            return "other";
        }
    }
    return NULL;
}

int cmd_pe(int argc, char **argv)
{
    const char *path = NULL;
    int json = 0;
    capa_sum caps;          // filled while walking the imports
    capa_init(&caps);
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0) json = 1;
        else if (path == NULL)              path = argv[a];
        else {
            fprintf(stderr, "pe: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (path == NULL) {
        fputs("usage: winspect pe <path> [--json]\n", stderr);
        return 1;
    }

    struct pe_file f;
    if (!load_file(path, &f)) {
        return 1;
    }

    // Same cleanup idea as load_file: every exit after this point goes through
    // "done", which frees the buffer. rc stays 1 until we reach the very end
    int rc = 1;

    if (!json) { printf("file  %s  (%zu bytes)\n\n", path, f.size); }

    // ---- DOS header (file offset 0) ------------------------------------------
    // 64 bytes left over from MS-DOS. Only two fields still matter:
    // e_magic (is this an MZ file at all?) and e_lfanew (where the real headers are)
    IMAGE_DOS_HEADER dos;
    if (!read_at(&f, 0, &dos, sizeof dos)) {
        fprintf(stderr, "pe: file is too small for a DOS header (%zu < %zu bytes)\n",
                f.size, sizeof dos);
        goto done;
    }

    // On disk the first two bytes are 4D 5A ('M' 'Z')
    // x86 is little-endian: the lower-addressed byte is the LOW byte of the WORD,
    // so reading them as one WORD gives 0x5A4D, which is IMAGE_DOS_SIGNATURE
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "pe: not a PE file, expected 'MZ' (0x5A4D) but found 0x%04X\n", dos.e_magic);
        goto done;
    }

    // e_lfanew is declared as a signed LONG
    // A negative value would point before the start of the file, reject it
    // before converting to an unsigned offset
    if (dos.e_lfanew <= 0) {
        fprintf(stderr, "pe: invalid e_lfanew %ld\n", (long)dos.e_lfanew);
        goto done;
    }
    size_t nt_off = (size_t)dos.e_lfanew;

    if (!json) {
        puts("DOS header");
        printf("  e_magic              0x%04X  \"MZ\"\n", dos.e_magic);
        printf("  e_lfanew             0x%08lX\n\n", (unsigned long)dos.e_lfanew);
    }

    // ---- PE signature (at e_lfanew) ------------------------------------------
    DWORD signature;
    if (!read_at(&f, nt_off, &signature, sizeof signature)) {
        fprintf(stderr, "pe: e_lfanew 0x%zX points past the end of the file\n", nt_off);
        goto done;
    }
    // Bytes on disk: 50 45 00 00 ('P' 'E' '\0' '\0') -> little-endian DWORD 0x00004550
    if (signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "pe: expected 'PE\\0\\0' (0x00004550) at 0x%zX but found 0x%08lX\n",
                nt_off, (unsigned long)signature);
        goto done;
    }

    if (!json) {
        printf("NT headers (file offset 0x%08zX)\n", nt_off);
        printf("  Signature            0x%08lX  \"PE\\0\\0\"\n\n", (unsigned long)signature);
    }

    // ---- File Header (right after the signature) -----------------------------
    IMAGE_FILE_HEADER fh;
    size_t fh_off = nt_off + sizeof signature;
    if (!read_at(&f, fh_off, &fh, sizeof fh)) {
        fprintf(stderr, "pe: file ends inside the File Header\n");
        goto done;
    }

    if (!json) {
        puts("File header");
        printf("  Machine              0x%04X  %s\n", fh.Machine, machine_name(fh.Machine));
        printf("  NumberOfSections     %u\n", fh.NumberOfSections);
        printf("  TimeDateStamp        0x%08lX\n", (unsigned long)fh.TimeDateStamp);
        printf("  SizeOfOptionalHeader %u\n", fh.SizeOfOptionalHeader);
        printf("  Characteristics      0x%04X  ", fh.Characteristics);
        print_flags(fh.Characteristics, file_flags, sizeof file_flags / sizeof file_flags[0]);
        putchar('\n');
    }

    // ---- Optional Header (right after the File Header) ------------------------
    // "Optional" is a misnomer: every .exe/.dll image has one. It is the loader's
    // road map for turning the file on disk into a running image in RAM.
    // Two layouts, told apart by the Magic WORD at its very start:
    //   PE32  (0x10B): 32-bit, ImageBase is a 32-bit field, has BaseOfData
    //   PE32+ (0x20B): 64-bit, ImageBase is a 64-bit field, no BaseOfData
    size_t opt_off = fh_off + sizeof fh;

    WORD magic;
    if (!read_at(&f, opt_off, &magic, sizeof magic)) {
        fprintf(stderr, "pe: file ends inside the Optional Header (no Magic)\n");
        goto done;
    }

    // Fields we display plus the two data directories Phase 3 needs, pulled into
    // width-independent locals so the rest of the code ignores 32- vs 64-bit.
    const char *pe_kind;
    int       is64;
    DWORD     entry_rva, sect_align, file_align, size_image, size_headers, n_dirs;
    ULONGLONG image_base;
    WORD      subsystem, dll_char;
    DWORD     imp_rva = 0, imp_size = 0;   // IMAGE_DIRECTORY_ENTRY_IMPORT
    DWORD     exp_rva = 0, exp_size = 0;   // IMAGE_DIRECTORY_ENTRY_EXPORT
    DWORD     dbg_rva = 0, dbg_size = 0;   // IMAGE_DIRECTORY_ENTRY_DEBUG
    DWORD     tls_rva = 0;                 // IMAGE_DIRECTORY_ENTRY_TLS
    DWORD     lcfg_rva = 0, lcfg_size = 0; // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG (10)
    DWORD     com_va = 0;                  // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (14) -> .NET
    DWORD     sec_va = 0, sec_size = 0;    // IMAGE_DIRECTORY_ENTRY_SECURITY (4) -> Authenticode
    DWORD     rsrc_rva = 0;                // IMAGE_DIRECTORY_ENTRY_RESOURCE (2) -> version info

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 opt;
        if (!read_at(&f, opt_off, &opt, sizeof opt)) {
            fprintf(stderr, "pe: file ends inside the PE32 Optional Header\n");
            goto done;
        }
        pe_kind = "PE32 (32-bit)"; is64 = 0;
        entry_rva  = opt.AddressOfEntryPoint; image_base = opt.ImageBase;
        sect_align = opt.SectionAlignment;    file_align = opt.FileAlignment;
        size_image = opt.SizeOfImage;         size_headers = opt.SizeOfHeaders;
        subsystem  = opt.Subsystem;           dll_char   = opt.DllCharacteristics;
        n_dirs     = opt.NumberOfRvaAndSizes;
        // Each DataDirectory[k] is an { RVA, Size } pair. Only read an index the
        // header actually claims to have (NumberOfRvaAndSizes), else it's garbage.
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            exp_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exp_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            imp_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            imp_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            dbg_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            dbg_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_TLS) {
            tls_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
            lcfg_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
            lcfg_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            sec_va   = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            sec_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            com_va = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            rsrc_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 opt;
        if (!read_at(&f, opt_off, &opt, sizeof opt)) {
            fprintf(stderr, "pe: file ends inside the PE32+ Optional Header\n");
            goto done;
        }
        pe_kind = "PE32+ (64-bit)"; is64 = 1;
        entry_rva  = opt.AddressOfEntryPoint; image_base = opt.ImageBase;
        sect_align = opt.SectionAlignment;    file_align = opt.FileAlignment;
        size_image = opt.SizeOfImage;         size_headers = opt.SizeOfHeaders;
        subsystem  = opt.Subsystem;           dll_char   = opt.DllCharacteristics;
        n_dirs     = opt.NumberOfRvaAndSizes;
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            exp_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exp_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            imp_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            imp_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            dbg_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            dbg_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_TLS) {
            tls_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
            lcfg_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
            lcfg_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            sec_va   = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            sec_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            com_va = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        }
        if (n_dirs > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            rsrc_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        }
    } else {
        fprintf(stderr, "pe: unknown Optional Header Magic 0x%04X (expected 0x10B or 0x20B)\n", magic);
        goto done;
    }
    (void)imp_size;   // size is handy for bounds but the terminator drives the import loop

    if (!json) {
        puts("Optional header");
        printf("  Magic                0x%04X  %s\n", magic, pe_kind);
        printf("  AddressOfEntryPoint  0x%08lX  (RVA)\n", (unsigned long)entry_rva);
        printf("  ImageBase            0x%016llX\n", (unsigned long long)image_base);
        printf("  SectionAlignment     0x%lX  (memory)\n", (unsigned long)sect_align);
        printf("  FileAlignment        0x%lX  (disk)\n", (unsigned long)file_align);
        printf("  SizeOfImage          0x%lX  (%lu bytes mapped)\n",
               (unsigned long)size_image, (unsigned long)size_image);
        printf("  SizeOfHeaders        0x%lX\n", (unsigned long)size_headers);
        printf("  Subsystem            %u  %s\n", subsystem, subsystem_name(subsystem));
        printf("  DllCharacteristics   0x%04X  ", dll_char);
        print_flags(dll_char, dll_flags, sizeof dll_flags / sizeof dll_flags[0]);
        printf("  NumberOfRvaAndSizes  %lu  (data directory entries)\n\n", (unsigned long)n_dirs);
    }

    // ---- Section table (read FIRST: the mitigation analysis and every RVA
    // lookup below need the whole table) --------------------------------------
    // Use fh.SizeOfOptionalHeader (what the file claims), NOT sizeof the struct:
    // trusting the struct size is the classic bug that reads sections from the
    // wrong offset.
    size_t sec_off = opt_off + fh.SizeOfOptionalHeader;

    unsigned n_sections = fh.NumberOfSections;
    if (n_sections > MAX_SECTIONS) {
        fprintf(stderr, "pe: NumberOfSections %u exceeds the PE limit of %u, clamping\n",
                n_sections, MAX_SECTIONS);
        n_sections = MAX_SECTIONS;
    }

    IMAGE_SECTION_HEADER sections[MAX_SECTIONS];
    for (unsigned i = 0; i < n_sections; i++) {
        if (!read_at(&f, sec_off + (size_t)i * sizeof(IMAGE_SECTION_HEADER),
                     &sections[i], sizeof(IMAGE_SECTION_HEADER))) {
            fprintf(stderr, "pe: file ends inside section header %u\n", i);
            goto done;
        }
    }

    // ---- Security feature analysis (winchecksec-style) -----------------------
    // One struct, derived once from DllCharacteristics + load config + debug dir,
    // used by both the text and the JSON output. See analyze_mitigations.
    struct mitigations mit;
    analyze_mitigations(&f, sections, n_sections, dll_char, fh.Characteristics,
                        fh.Machine, is64, com_va != 0, (sec_va != 0 && sec_size != 0),
                        lcfg_rva, lcfg_size, dbg_rva, dbg_size, &mit);

    // Manifest requested execution level (asInvoker / requireAdministrator / ...).
    const char *manifest = manifest_exec_level(&f);

    if (!json) {
        puts("Security features");
        printf("  ASLR                 %s%s\n",
               mit.aslr ? "yes" : "NO",
               (mit.dynamic_base && mit.relocs_stripped)
                   ? "  (relocs stripped -> cannot actually move)" : "");
        printf("  DEP / NX             %s\n", mit.nx ? "yes" : "NO");
        printf("  Control Flow Guard   %s\n", mit.cfg ? "yes" : "NO");
        printf("  High-entropy ASLR    %s\n", mit.high_entropy_va ? "yes" : "no");
        printf("  Force integrity      %s\n", mit.force_integrity ? "yes" : "no");
        printf("  GS / stack cookie    %s\n",
               mit.gs_known ? (mit.gs ? "yes" : "no") : "(load config too small)");
        if (mit.safe_seh_applicable) {
            printf("  SafeSEH              %s\n", mit.safe_seh ? "yes" : "no");
        } else {
            printf("  SafeSEH              n/a (x64/ARM use table-based SEH)\n");
        }
        printf("  SEH allowed          %s\n", mit.seh ? "yes" : "no");
        printf("  Return Flow Guard    %s\n",
               mit.rfg_known ? (mit.rfg ? "yes" : "no") : "(load config too small)");
        printf("  CET shadow stack     %s\n",
               mit.cet_known ? (mit.cet_compat ? "yes" : "no") : "(no ext-chars entry)");
        printf("  EH Continuation      %s\n",
               mit.cet_known ? (mit.ehcont ? "yes" : "no") : "(no ext-chars entry)");
        printf("  Isolation            %s\n", mit.isolation ? "yes" : "no");
        printf("  .NET / managed       %s\n", mit.dotnet ? "yes" : "no");
        printf("  Authenticode dir     %s\n",
               mit.authenticode ? "present (not verified here; use `sign`)" : "no");
        printf("  Manifest exec level  %s\n\n", manifest ? manifest : "(none / asInvoker)");
    }

    // ---- Fingerprints & identity (imphash / exphash / Rich / version / .NET) --
    char imphash[33];
    int has_imphash = compute_imphash(&f, sections, n_sections, is64, imp_rva, imphash);
    char exphash[33];
    int has_exphash = compute_exphash(&f, sections, n_sections, exp_rva, exphash);
    struct rich_info rich;
    compute_rich(&f, nt_off, &rich);
    struct verinfo vinfo;
    parse_version_info(&f, sections, n_sections, rsrc_rva, &vinfo);
    struct dotnet_info dnet;
    parse_dotnet(&f, sections, n_sections, com_va, &dnet);

    if (!json) {
        puts("Identity");
        printf("  imphash              %s\n", has_imphash ? imphash : "(no imports)");
        if (has_exphash) {
            printf("  exphash              %s\n", exphash);
        }
        if (rich.present) {
            printf("  Rich header          %u tool record(s), hash %s%s\n",
                   rich.n, rich.hash, rich.malformed ? "  (non-MS format)" : "");
        } else {
            printf("  Rich header          (none)\n");
        }
        if (dnet.present) {
            printf("  .NET CLR header      runtime v%u.%u, flags 0x%08lX%s%s%s\n",
                   dnet.major, dnet.minor, (unsigned long)dnet.flags,
                   (dnet.flags & WS_COR_ILONLY) ? " IL_ONLY" : "",
                   (dnet.flags & WS_COR_32BITREQUIRED) ? " 32BIT_REQ" : "",
                   (dnet.flags & WS_COR_STRONGNAMESIGNED) ? " STRONG_NAME" : "");
        }
        if (vinfo.present) {
            if (vinfo.original_filename[0]) printf("  OriginalFilename     %s\n", vinfo.original_filename);
            if (vinfo.company[0])           printf("  CompanyName          %s\n", vinfo.company);
            if (vinfo.product[0])           printf("  ProductName          %s\n", vinfo.product);
            if (vinfo.file_version[0])      printf("  FileVersion          %s\n", vinfo.file_version);
            if (vinfo.file_description[0])  printf("  FileDescription      %s\n", vinfo.file_description);
        } else {
            printf("  Version info         (none)\n");
        }
        putchar('\n');
    }

    if (!json) {
        printf("Sections (%u)\n", n_sections);
        printf("  %-8s  %-4s  %-10s %-10s  %-10s %-10s  %-5s  %s\n",
               "name", "perm", "virt.addr", "virt.size", "raw.addr", "raw.size", "entr", "flags");
        for (unsigned i = 0; i < n_sections; i++) {
            const IMAGE_SECTION_HEADER *sh = &sections[i];
            char rwx[4];
            section_rwx(sh->Characteristics, rwx);
            double entr = section_entropy(&f, sh);
            // sh->Name is 8 raw bytes, not guaranteed NUL-terminated; "%-8.8s" reads
            // at most 8 bytes and pads to width 8, so we never run off the field.
            // A '!' after the entropy flags a section above the packed-content
            // heuristic (~7.0 bits/byte).
            printf("  %-8.8s  %-4s  0x%08lX 0x%08lX  0x%08lX 0x%08lX  %4.2f%c  ",
                   (const char *)sh->Name, rwx,
                   (unsigned long)sh->VirtualAddress,
                   (unsigned long)sh->Misc.VirtualSize,
                   (unsigned long)sh->PointerToRawData,
                   (unsigned long)sh->SizeOfRawData,
                   entr, entr >= 7.0 ? '!' : ' ');
            print_flags(sh->Characteristics, section_flags, sizeof section_flags / sizeof section_flags[0]);
        }
        putchar('\n');
    }

    // ---- Overlay size (needed by both output modes) --------------------------
    // Any bytes past the end of the last section's raw data are "overlay": not
    // described by the section table. Authenticode signatures live here, but so
    // do appended archives and installer payloads, so its size is worth noting.
    size_t max_end = 0;
    for (unsigned i = 0; i < n_sections; i++) {
        size_t end = (size_t)sections[i].PointerToRawData + sections[i].SizeOfRawData;
        if (end > max_end) {
            max_end = end;
        }
    }

    if (json) {
        // ---- JSON path: one object mirroring the whole text report -----------
        printf("{\"file\":");               json_str(path);
        printf(",\"size\":%zu", f.size);
        printf(",\"dos_header\":{\"e_magic\":\"0x%04X\",\"e_lfanew\":\"0x%08lX\"}",
               dos.e_magic, (unsigned long)dos.e_lfanew);
        printf(",\"nt_signature\":\"0x%08lX\"", (unsigned long)signature);

        printf(",\"file_header\":{\"machine\":\"0x%04X\",\"machine_name\":", fh.Machine);
        json_str(machine_name(fh.Machine));
        printf(",\"number_of_sections\":%u,\"timedatestamp\":\"0x%08lX\",\"size_of_optional_header\":%u",
               fh.NumberOfSections, (unsigned long)fh.TimeDateStamp, fh.SizeOfOptionalHeader);
        printf(",\"characteristics\":\"0x%04X\",\"characteristics_flags\":", fh.Characteristics);
        flags_json(fh.Characteristics, file_flags, sizeof file_flags / sizeof file_flags[0]);
        putchar('}');

        printf(",\"optional_header\":{\"magic\":\"0x%04X\",\"kind\":", magic);
        json_str(pe_kind);
        printf(",\"is64\":%s", is64 ? "true" : "false");
        printf(",\"address_of_entry_point\":\"0x%08lX\",\"image_base\":\"0x%016llX\"",
               (unsigned long)entry_rva, (unsigned long long)image_base);
        printf(",\"section_alignment\":\"0x%lX\",\"file_alignment\":\"0x%lX\"",
               (unsigned long)sect_align, (unsigned long)file_align);
        printf(",\"size_of_image\":%lu,\"size_of_headers\":%lu",
               (unsigned long)size_image, (unsigned long)size_headers);
        printf(",\"subsystem\":%u,\"subsystem_name\":", subsystem);
        json_str(subsystem_name(subsystem));
        printf(",\"dll_characteristics\":\"0x%04X\",\"dll_characteristics_flags\":", dll_char);
        flags_json(dll_char, dll_flags, sizeof dll_flags / sizeof dll_flags[0]);
        printf(",\"number_of_rva_and_sizes\":%lu}", (unsigned long)n_dirs);

        {
            // A tristate field prints true/false when known, null when the file
            // did not carry enough to decide (e.g. load config too small).
            #define TRI(known, val) ((known) ? ((val) ? "true" : "false") : "null")
            printf(",\"security_features\":{\"aslr\":%s,\"dynamic_base\":%s,\"relocs_stripped\":%s",
                   mit.aslr ? "true" : "false",
                   mit.dynamic_base ? "true" : "false",
                   mit.relocs_stripped ? "true" : "false");
            printf(",\"dep_nx\":%s,\"cfg\":%s,\"high_entropy_aslr\":%s,\"force_integrity\":%s",
                   mit.nx ? "true" : "false",
                   mit.cfg ? "true" : "false",
                   mit.high_entropy_va ? "true" : "false",
                   mit.force_integrity ? "true" : "false");
            printf(",\"gs\":%s,\"seh\":%s,\"safe_seh\":%s",
                   TRI(mit.gs_known, mit.gs),
                   mit.seh ? "true" : "false",
                   TRI(mit.safe_seh_applicable, mit.safe_seh));
            printf(",\"rfg\":%s,\"cet_shadow_stack\":%s,\"eh_continuation\":%s",
                   TRI(mit.rfg_known, mit.rfg),
                   TRI(mit.cet_known, mit.cet_compat),
                   TRI(mit.cet_known, mit.ehcont));
            printf(",\"isolation\":%s,\"dotnet\":%s,\"authenticode_dir\":%s}",
                   mit.isolation ? "true" : "false",
                   mit.dotnet ? "true" : "false",
                   mit.authenticode ? "true" : "false");
            #undef TRI
        }

        // Fingerprints.
        fputs(",\"imphash\":", stdout);
        if (has_imphash) { json_str(imphash); } else { fputs("null", stdout); }

        fputs(",\"exphash\":", stdout);
        if (has_exphash) { json_str(exphash); } else { fputs("null", stdout); }

        fputs(",\"dotnet\":", stdout);
        if (dnet.present) {
            printf("{\"runtime_version\":\"%u.%u\",\"flags\":\"0x%08lX\"",
                   dnet.major, dnet.minor, (unsigned long)dnet.flags);
            printf(",\"il_only\":%s", (dnet.flags & WS_COR_ILONLY) ? "true" : "false");
            printf(",\"requires_32bit\":%s", (dnet.flags & WS_COR_32BITREQUIRED) ? "true" : "false");
            printf(",\"strong_name_signed\":%s", (dnet.flags & WS_COR_STRONGNAMESIGNED) ? "true" : "false");
            printf(",\"native_entry\":%s", (dnet.flags & WS_COR_NATIVE_ENTRY) ? "true" : "false");
            printf(",\"entry_token\":\"0x%08lX\"}", (unsigned long)dnet.entry_token);
        } else {
            fputs("null", stdout);
        }

        fputs(",\"rich_header\":", stdout);
        if (rich.present) {
            printf("{\"hash\":");            json_str(rich.hash);
            printf(",\"malformed\":%s,\"entries\":[", rich.malformed ? "true" : "false");
            for (unsigned i = 0; i < rich.n; i++) {
                printf("%s{\"product_id\":%u,\"build\":%u,\"count\":%u}",
                       i ? "," : "", rich.ents[i].product_id,
                       rich.ents[i].build, rich.ents[i].count);
            }
            fputs("]}", stdout);
        } else {
            fputs("null", stdout);
        }

        fputs(",\"version_info\":", stdout);
        if (vinfo.present) {
            fputs("{\"original_filename\":", stdout); json_str(vinfo.original_filename);
            fputs(",\"company_name\":", stdout);      json_str(vinfo.company);
            fputs(",\"product_name\":", stdout);      json_str(vinfo.product);
            fputs(",\"internal_name\":", stdout);     json_str(vinfo.internal_name);
            fputs(",\"file_version\":", stdout);      json_str(vinfo.file_version);
            fputs(",\"product_version\":", stdout);   json_str(vinfo.product_version);
            fputs(",\"file_description\":", stdout);  json_str(vinfo.file_description);
            fputs(",\"legal_copyright\":", stdout);   json_str(vinfo.legal_copyright);
            putchar('}');
        } else {
            fputs("null", stdout);
        }

        fputs(",\"manifest_exec_level\":", stdout);
        if (manifest) { json_str(manifest); } else { fputs("null", stdout); }

        fputs(",\"sections\":[", stdout);
        for (unsigned i = 0; i < n_sections; i++) {
            const IMAGE_SECTION_HEADER *sh = &sections[i];
            char rwx[4];
            section_rwx(sh->Characteristics, rwx);
            double entr = section_entropy(&f, sh);
            // sh->Name is 8 raw bytes, not guaranteed NUL-terminated; copy at
            // most 8 then terminate so json_str never runs off the field.
            char secname[9];
            memcpy(secname, sh->Name, 8);
            secname[8] = '\0';
            printf("%s{\"name\":", i ? "," : "");
            json_str(secname);
            printf(",\"perm\":\"%s\",\"virtual_address\":\"0x%08lX\",\"virtual_size\":%lu",
                   rwx, (unsigned long)sh->VirtualAddress, (unsigned long)sh->Misc.VirtualSize);
            printf(",\"raw_address\":\"0x%08lX\",\"raw_size\":%lu,\"entropy\":%.2f,\"packed\":%s,\"flags\":",
                   (unsigned long)sh->PointerToRawData, (unsigned long)sh->SizeOfRawData,
                   entr, entr >= 7.0 ? "true" : "false");
            flags_json(sh->Characteristics, section_flags, sizeof section_flags / sizeof section_flags[0]);
            putchar('}');
        }
        putchar(']');

        fputs(",\"imports\":", stdout);
        if (imp_rva == 0) { fputs("[]", stdout); }
        else { print_imports(&f, sections, n_sections, is64, imp_rva, 1, &caps); }

        // Behaviour categories of the named imports (capa.c): what the code
        // CAN call - common in legitimate software too, so no verdict.
        fputs(",\"capabilities\":[", stdout);
        {
            int cfirst = 1;
            for (int i = 0; i < CAPA_NCAT; i++) {
                if (caps.count[i] == 0) {
                    continue;
                }
                printf("%s{\"category\":\"%s\",\"count\":%u,\"examples\":[",
                       cfirst ? "" : ",", capa_name(i), caps.count[i]);
                unsigned ne = caps.count[i] < CAPA_EXAMPLES ? caps.count[i] : CAPA_EXAMPLES;
                for (unsigned e = 0; e < ne; e++) {
                    if (e) putchar(',');
                    json_str(caps.example[i][e]);
                }
                fputs("]}", stdout);
                cfirst = 0;
            }
        }
        putchar(']');

        fputs(",\"exports\":", stdout);
        if (exp_rva == 0) { fputs("null", stdout); }
        else { print_exports(&f, sections, n_sections, exp_rva, exp_size, 1); }

        fputs(",\"debug\":", stdout);
        if (dbg_rva == 0) { fputs("{\"pdb_path\":null}", stdout); }
        else { print_debug(&f, sections, n_sections, dbg_rva, dbg_size, 1); }

        fputs(",\"tls\":", stdout);
        if (tls_rva == 0) { fputs("{\"callbacks\":0}", stdout); }
        else { print_tls(&f, sections, n_sections, is64, image_base, tls_rva, 1); }

        printf(",\"overlay\":{\"present\":%s,\"offset\":\"0x%zX\",\"size\":%zu}",
               f.size > max_end ? "true" : "false", max_end,
               f.size > max_end ? f.size - max_end : (size_t)0);

        {
            struct pe_anom an[32];
            int nan = collect_anomalies(&f, sections, n_sections, fh.TimeDateStamp,
                                        entry_rva, (fh.Characteristics & IMAGE_FILE_DLL) != 0,
                                        opt_off, an, 32);
            fputs(",\"anomalies\":[", stdout);
            for (int i = 0; i < nan; i++) {
                printf("%s{\"type\":\"%s\",\"detail\":", i ? "," : "", an[i].type);
                json_str(an[i].detail);
                putchar('}');
            }
            putchar(']');
        }

        puts("}");
        rc = 0;
        goto done;
    }

    // ---- Imports (IMAGE_DIRECTORY_ENTRY_IMPORT) ------------------------------
    puts("Imports");
    if (imp_rva == 0) {
        puts("  (none)");
    } else {
        print_imports(&f, sections, n_sections, is64, imp_rva, 0, &caps);
    }
    putchar('\n');

    // ---- Import capabilities ------------------------------------------------
    // Coarse behaviour categories of the named imports (capa.c). This says what
    // the code CAN call; debuggers, installers and AV import these too.
    puts("Import capabilities  (what the code can call - not a verdict)");
    {
        int any = 0;
        for (int i = 0; i < CAPA_NCAT; i++) {
            if (caps.count[i] == 0) {
                continue;
            }
            any = 1;
            printf("  %-18s %2u  %s\n", capa_name(i), caps.count[i],
                   capa_explain(capa_name(i)));
            fputs("                         e.g.", stdout);
            unsigned ne = caps.count[i] < CAPA_EXAMPLES ? caps.count[i] : CAPA_EXAMPLES;
            for (unsigned e = 0; e < ne; e++) {
                printf(" %s", caps.example[i][e]);
            }
            putchar('\n');
        }
        if (!any) {
            puts("  (none of the tracked categories)");
        }
    }
    putchar('\n');

    // ---- Exports (IMAGE_DIRECTORY_ENTRY_EXPORT) ------------------------------
    // .exe files usually have no exports; that is normal, not an error.
    puts("Exports");
    if (exp_rva == 0) {
        puts("  (none)");
    } else {
        print_exports(&f, sections, n_sections, exp_rva, exp_size, 0);
    }
    putchar('\n');

    // ---- Debug directory (PDB path) -----------------------------------------
    puts("Debug");
    if (dbg_rva == 0) {
        puts("  (none)");
    } else {
        print_debug(&f, sections, n_sections, dbg_rva, dbg_size, 0);
    }
    putchar('\n');

    // ---- TLS callbacks -------------------------------------------------------
    puts("TLS");
    if (tls_rva == 0) {
        puts("  (none)");
    } else {
        print_tls(&f, sections, n_sections, is64, image_base, tls_rva, 0);
    }
    putchar('\n');

    // ---- Overlay -------------------------------------------------------------
    puts("Overlay");
    if (f.size > max_end) {
        printf("  %zu bytes past the last section (offset 0x%zX)\n",
               f.size - max_end, max_end);
    } else {
        puts("  (none)");
    }
    putchar('\n');

    // ---- Anomalies -----------------------------------------------------------
    {
        struct pe_anom an[32];
        int nan = collect_anomalies(&f, sections, n_sections, fh.TimeDateStamp,
                                    entry_rva, (fh.Characteristics & IMAGE_FILE_DLL) != 0,
                                    opt_off, an, 32);
        puts("Anomalies");
        if (nan == 0) {
            puts("  (none)");
        } else {
            for (int i = 0; i < nan; i++) {
                printf("  [!] %-13s %s\n", an[i].type, an[i].detail);
            }
        }
    }

    rc = 0;

done:
    free(f.data);
    return rc;
}
