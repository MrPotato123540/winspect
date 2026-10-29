#ifndef WINSPECT_DRIVERS_H
#define WINSPECT_DRIVERS_H

// winspect drivers - list the kernel-mode drivers currently loaded in the
// system, with each one's load address and backing file; flags files missing
// from disk or in user-writable dirs, and with --sig checks each driver's
// signature (embedded or catalog). Read-only (PSAPI + WinVerifyTrust).
// Usage: winspect drivers [--sig] [--json | --csv]
int cmd_drivers(int argc, char **argv);

#endif
