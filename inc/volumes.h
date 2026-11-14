#ifndef WINSPECT_VOLUMES_H
#define WINSPECT_VOLUMES_H

// winspect volumes - the mounted volumes: drive letter, type (fixed,
// removable, network, CD), label, file system, size and free space, the
// volume GUID path and above all the volume SERIAL NUMBER. Shortcuts (lnk),
// jump lists and Prefetch files record the serial of the volume a file was
// on; this is the list to look those numbers up in - "serial 1A2B-3C4D" in a
// shortcut is drive E: if it is here, and a drive that is no longer attached
// (a USB stick: see `usb`) if it is not. The serial is shown in both forms
// the other commands print (XXXX-XXXX and XXXXXXXX). --find keeps rows whose
// letter, label or serial contains the text. For a network drive the remote
// path is shown. Read-only. Usage:
//   winspect volumes [--find <text>] [--json | --csv]
int cmd_volumes(int argc, char **argv);

#endif
