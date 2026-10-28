#ifndef WINSPECT_SIGN_H
#define WINSPECT_SIGN_H

// winspect sign - Authenticode check of a file, reporting two things people
// often mix up: is the signature cryptographically valid AND trusted by this
// machine (WinVerifyTrust, embedded or catalog), and who signed it (signer,
// chain, timestamp, file hash). Presence of a signature does not prove trust.
// --scan walks a folder and lists files without a trusted signature (--all
// lists every executable). Read-only. Usage:
//   winspect sign <path> [--json]
//   winspect sign --scan <dir> [--all] [--json | --csv]
int cmd_sign(int argc, char **argv);

#include <stddef.h>
#include <wchar.h>

// Is this file signed by someone the machine trusts - embedded Authenticode or
// a catalog signature? Returns 1 if trusted; *source is set to "embedded",
// "catalog" or "none". No revocation check (offline, fast). Read-only.
int sign_file_trust(const wchar_t *wpath, const char **source);

// Resolve the file a COMMAND LINE runs (quoted/unquoted exe, rundll32/regsvr32
// DLL argument, %VARIABLES%, bare names via the search path, kernel-style
// driver paths) and check its signature. image (UTF-8) receives the resolved
// path. Returns 1 trusted, 0 present but not trusted, -1 could not resolve /
// file missing. *source as for sign_file_trust ("embedded", "catalog", "none").
int sign_command_trust(const char *cmdline, char *image, size_t n, const char **source);

#endif
