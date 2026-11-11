#ifndef WINSPECT_OFFICEPARSE_H
#define WINSPECT_OFFICEPARSE_H

// Microsoft Office security artifacts in a user's registry hive. Portable,
// unit-tested.
//
// Trusted Documents - under Software\Microsoft\Office\<ver>\<App>\Security,
//   key "Trusted Documents\TrustRecords": one value per document the user clicked
//   a yellow bar for. Name = the document's path or URL (environment
//   variables and forward slashes as Office wrote them). Data (24 bytes):
//     @0   FILETIME  when the trust decision was made
//     @8   8 bytes   time-zone bias data (not used here)
//     @20  u32       0x7FFFFFFF = "Enable Content" (macros / active content
//                    allowed to run); any other value = "Enable Editing"
//                    only (the document left Protected View)

#include <stddef.h>
#include <stdint.h>

// Returns 0 and the time + whether active content was enabled, -1 if the
// data is too short to be a trust record.
int trustrec_parse(const unsigned char *d, size_t n, uint64_t *filetime, int *content_enabled);

// Value name -> a path in the usual Windows form: forward slashes become
// backslashes, except in URLs (anything with "://"), which are kept as is.
void trustrec_path(const char *name, char *out, size_t n);

// Why a trusted document deserves a look, or NULL. Only documents whose
// ACTIVE CONTENT was enabled are judged, by where the file was: a mail
// attachment cache, a download or temp folder, the internet, a network share.
const char *trustrec_reason(const char *path, int content_enabled);

// Why a macro-security setting deserves a look, or NULL. name is the value
// under ...\<App>\Security:
//   VBAWarnings = 1                       all macros run without asking
//   AccessVBOM = 1                        programs may modify VBA projects
//   BlockContentExecutionFromInternet = 0 macros in files from the internet are not blocked
const char *office_setting_reason(const char *name, uint32_t value);

// Why a trusted location deserves a look, or NULL: files opened from a
// trusted location skip every macro check, so one in a download / temp
// folder, on the network or at a URL is an open door.
const char *trustloc_reason(const char *path);

#endif
