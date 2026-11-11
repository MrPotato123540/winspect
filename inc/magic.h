#ifndef WINSPECT_MAGIC_H
#define WINSPECT_MAGIC_H

// winspect magic - what a file really is, from its content instead of its
// name (the idea of the Unix `file` command): PE programs / DLLs / drivers
// with their architecture, ELF, archives and disk images (zip, rar, 7z, cab,
// iso, vhd, wim), documents (PDF, OLE2 and Open XML Office, RTF, OneNote,
// CHM), shortcuts, pictures, media, scripts (batch, HTA), Windows artifacts
// (evtx, hive, SQLite, Prefetch, ESE, dumps) and plain text; anything else
// is "data". For a folder every file is listed (-r descends). Flagged, with
// the reason: a program behind a picture / document / media extension, a
// double extension (invoice.pdf.exe), a right-to-left override character in
// the name, a long run of spaces hiding the extension. --flagged keeps only
// those - a quick way to sweep a Downloads folder or a mounted image.
// Reads at most the first 36 KiB of each file. Read-only. Usage:
//   winspect magic <file | folder> [-r] [--flagged] [--json | --csv]
int cmd_magic(int argc, char **argv);

#endif
