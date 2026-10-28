#ifndef WINSPECT_CAPA_H
#define WINSPECT_CAPA_H

// Import "capability" tagging: map an imported API name to a coarse behaviour
// category (process injection, anti-debug, keyboard input, network, crypto,
// privilege/token, service control). The idea comes from tools like pestudio
// and capa; the table here is our own, deliberately short and educational.
//
// It answers "what CAN this code call?", not "is it malicious?" - debuggers,
// installers, AV and remote-support tools legitimately import most of these.
// Very common APIs (LoadLibrary, GetProcAddress, CreateProcess, RegSetValue...)
// are left out on purpose: they appear in almost every program, so tagging them
// would only add noise. Portable C, unit-tested on any OS.

#include <stddef.h>

#define CAPA_NCAT     7
#define CAPA_EXAMPLES 4

// Category of an API name, or NULL if it is not in the table. A trailing
// ANSI/Unicode suffix ('A'/'W') is ignored, so "SetWindowsHookExW" matches.
const char *capa_category(const char *api);

// Short explanation for a category name (for the text report).
const char *capa_explain(const char *category);

// Accumulates hits per category with up to CAPA_EXAMPLES example APIs each.
typedef struct {
    unsigned count[CAPA_NCAT];
    char     example[CAPA_NCAT][CAPA_EXAMPLES][48];
} capa_sum;

void capa_init(capa_sum *s);
void capa_add(capa_sum *s, const char *api);

// Category name for index i (0..CAPA_NCAT-1).
const char *capa_name(int i);

// Well-known packer / protector section names ("UPX0", ".vmp0", ".MPRESS1",
// ".themida", ...). Returns the packer's name, or NULL. Packed code is not
// malicious by itself (commercial software uses protectors too), but a packed
// file hides its real imports and strings, so static analysis says little
// until it is unpacked. Exact, case-sensitive match on the 8-byte name.
const char *capa_packer_section(const char *section_name);

#endif
