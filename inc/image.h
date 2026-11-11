#ifndef WINSPECT_IMAGE_H
#define WINSPECT_IMAGE_H

// winspect image - triage of a Windows installation that is NOT running: a
// mounted disk image, a copied system drive or a collection that keeps the
// original folder layout. Give the root (the folder holding Windows\ and
// Users\); winspect finds the registry hives, Amcache, Prefetch, scheduled
// tasks, event logs (also read for the logon history), crash reports, Defender's Detection History, the
// Recycle Bin and every user's NTUSER.DAT (autoruns, Office macro trust ...),
// UsrClass.dat and PowerShell history, runs each offline-capable command on
// them and prints one findings-only report: machine facts, local accounts,
// then every flagged entry with its source, user and reason (one JSON object
// with --json). Read-only. Usage:
//   winspect image <root> [--json]
int cmd_image(int argc, char **argv);

#endif
