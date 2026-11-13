#ifndef WINSPECT_CAPABILITY_H
#define WINSPECT_CAPABILITY_H

// winspect capability - which programs used the microphone, the camera, the
// location service and the other privacy-guarded capabilities, and when.
// Windows records it itself (Settings > Privacy shows the same data) in the
// Capability Access Manager "ConsentStore": per capability one key per
// packaged app and, under NonPackaged, one per desktop program (its path with
// '#' for '\'), each with LastUsedTimeStart / LastUsedTimeStop. A stop time
// of zero means the capability is in use right now. Machine-wide (HKLM) and
// per-user (HKCU) stores are read. Flagged: a desktop program in a
// user-writable folder that used the microphone or the camera - how a
// remote-access tool or stalkerware shows up here. Entries that never used
// the capability are hidden unless --all. Offline: --software / --ntuser read
// hive files. Read-only. Usage:
//   winspect capability [--all] [--find <text>] [--flagged] [--json | --csv]
//   winspect capability [--software <SOFTWARE>] [--ntuser <NTUSER.DAT>] ...
int cmd_capability(int argc, char **argv);

#endif
