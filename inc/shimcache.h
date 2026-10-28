#ifndef WINSPECT_SHIMCACHE_H
#define WINSPECT_SHIMCACHE_H

// winspect shimcache - list the Application Compatibility Cache (ShimCache):
// executable paths Windows has seen, newest first, with each file's
// last-modified time. Shows programs that existed (even if since deleted); on
// Windows 10+ it does not by itself prove execution. Windows 10/11 layout
// only; usually needs elevation. Read-only. Usage:
//   winspect shimcache [--json | --csv]
int cmd_shimcache(int argc, char **argv);

#endif
