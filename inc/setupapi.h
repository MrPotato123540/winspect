#ifndef WINSPECT_SETUPAPI_H
#define WINSPECT_SETUPAPI_H

// winspect setupapi - device and driver installs from the SetupAPI text logs
// (%SystemRoot%\INF\setupapi.dev.log, setupapi.setup.log and their rotated
// copies setupapi.dev.YYYYMMDD_hhmmss.log). One row per logged section: when
// it started and ended, what it was (device install, driver package import,
// ...), the device id or INF path, the exit status, the signer named in the
// section and its error/warning line counts. A USB storage device's first
// "Device Install" is the classic first-connected time. Times in the log are
// LOCAL: for the live logs they are converted with this machine's time zone;
// for a copied file --utc-offset <+hh:mm> converts them, otherwise time_utc
// stays empty. Sections without a target (policy checks, cleanup) are only
// shown with --all. Flags a driver package installed from a user-writable
// folder. A file or folder argument reads a copy. Read-only. Usage:
//   winspect setupapi [<file | INF folder>] [--all] [--flagged] [--find <text>]
//                     [--utc-offset <+hh:mm>] [--json | --csv]
int cmd_setupapi(int argc, char **argv);

#endif
