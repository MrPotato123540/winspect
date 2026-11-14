#ifndef WINSPECT_HUNT_H
#define WINSPECT_HUNT_H

// winspect hunt - system-wide "Hunt Evil" checks over the live process list:
// core Windows processes with an unexpected parent (lsass not started by
// wininit, svchost not started by services, ...), duplicates of processes that
// must be unique (two lsass.exe), core binary names running from outside
// System32 (masquerading), svchost without a "-k" service group, core
// processes not running as SYSTEM, and boot-time processes (lsass, services,
// wininit) that started long after boot, and system tools running under
// another file name (the version resource still says cmd.exe / PsExec /
// rundll32 ... while the file is called something else). Rules come
// from the public SANS "Hunt Evil" guidance. Read-only. Usage:
//   winspect hunt [--all] [--json | --csv]
int cmd_hunt(int argc, char **argv);

#endif
