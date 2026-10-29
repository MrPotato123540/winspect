#ifndef WINSPECT_IMPHASH_ORDS_H
#define WINSPECT_IMPHASH_ORDS_H

#include <stddef.h>

// Frozen imphash ordinal tables (see imphash_ords.c). Returns the mapped symbol
// name (already lowercased) for an ordinal import from ws2_32/wsock32/oleaut32,
// or NULL when the DLL is not one of those or the ordinal is not in the table
// (the caller then uses the "ord<N>" form).
const char *imphash_ord_name(const char *dll_lower, unsigned ordinal);

// Builds the imphash "library" token from a DLL name, following pefile's exact
// rule: lowercase the name and, only if the extension is .dll / .ocx / .sys,
// drop it (other extensions, e.g. .exe, are kept). Getting this rule right is
// what makes our imphash match VirusTotal/YARA. Writes a NUL-terminated result.
void imphash_libname(const char *dll, char *out, size_t n);

#endif
