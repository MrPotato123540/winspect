#ifndef WINSPECT_MAGICPARSE_H
#define WINSPECT_MAGICPARSE_H

// File type by content (the idea of the Unix `file` command, with winspect's
// own small table of well-known signatures - no magic database is used), and
// the checks that compare a file's NAME with what it really is. Portable,
// unit-tested.

#include <stddef.h>

// Looks at the first bytes of a file (pass up to 36 KiB: the ISO 9660
// signature sits at 0x8001). Returns a description, e.g. "PE executable (x64)",
// and through *group a coarse class used by the name checks:
//   "program"  PE / ELF / Mach-O code            "script"   batch, HTA, shell
//   "archive"  zip, rar, 7z, cab, iso, vhd ...   "document" pdf, Office, rtf
//   "image"    png, jpeg, gif, bmp ...           "media"    audio / video
//   "system"   Windows artifacts (evtx, hive..)  "shortcut" .lnk
//   "text"     plain text                        "data"     not recognised
// An unrecognised file is "data" - never an error.
const char *magic_sniff(const unsigned char *d, size_t n, const char **group);

// Why a file name deserves a look, or NULL. name is the file name (UTF-8,
// no directory); group is what magic_sniff said about its content.
//   - content is a program but the extension is that of a picture, document,
//     media or text file (a disguised executable)
//   - double extension: "invoice.pdf.exe" - a document-like extension
//     directly before a program / script one
//   - a right-to-left override character (U+202E) in the name ("exe.fdp" can
//     be displayed as "pdf.exe" reversed)
//   - a long run of spaces before the extension pushes it out of view
const char *magic_name_reason(const char *name, const char *group);

#endif
