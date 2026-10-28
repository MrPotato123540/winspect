#ifndef WINSPECT_LNK_H
#define WINSPECT_LNK_H

// winspect lnk - parse Windows shortcut (.lnk) files: target path, arguments,
// working directory, the target's timestamps, the volume it was on (type,
// serial, label - "removable" answers "opened from a USB stick?"), the network
// share, and the NetBIOS name + MAC of the machine the link was created on
// (TrackerDataBlock). With no argument it reads
// the current user's Recent folder (files and folders opened recently - a
// classic DFIR artifact). Flags shortcuts that launch a script host, point
// into a user-writable directory, or are crafted to hide their command line
// (string count > 260, blank padding). Read-only. Usage:
//   winspect lnk [<file.lnk> | <folder>] [--json | --csv]
int cmd_lnk(int argc, char **argv);

#include <wchar.h>
#include "lnkparse.h"

// Read and parse one .lnk file (used by autoruns for Startup shortcuts).
// Returns 0 on success.
int lnk_load(const wchar_t *wpath, lnk_info *info);

#endif
