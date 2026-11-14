#ifndef WINSPECT_CAPABILITY_H
#define WINSPECT_CAPABILITY_H

// winspect capability - which programs used the microphone, the camera, the
// location service and the other privacy-guarded capabilities, and when.
// Windows records it itself (Settings > Privacy shows the same data) in the
// Capability Access Manager "ConsentStore": per capability one key per
// packaged app and, under NonPackaged, one per desktop program (its path with
// '#' for '\'), each with LastUsedTimeStart / LastUsedTimeStop. A stop time
// of zero means the capability is in use right now. Machine-wide (HKLM) and
// per-user (HKCU) stores are read. For desktop programs still on disk the
// signature is checked (file column: signed / UNSIGNED / gone). Flagged, for
// the microphone and the camera only: an UNSIGNED program in a user-writable
// folder, or - when the file can no longer be checked - one that ran from a
// temp, Downloads, Public or Recycle Bin folder. Signed per-user installs
// (Discord, Teams, games under AppData) are listed, not flagged. Entries that never used
// the capability are hidden unless --all. Offline: --software / --ntuser read
// hive files. Read-only. Usage:
//   winspect capability [--all] [--find <text>] [--flagged] [--json | --csv]
//   winspect capability [--software <SOFTWARE>] [--ntuser <NTUSER.DAT>] ...
int cmd_capability(int argc, char **argv);

#endif
