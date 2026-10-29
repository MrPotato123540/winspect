#ifndef WINSPECT_USB_H
#define WINSPECT_USB_H

// winspect usb - USB mass-storage devices this machine has seen, from the
// Plug-and-Play record under HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR:
// vendor, product, revision, serial (instance id), friendly name, first
// install / last plugged-in / last removal times (Windows 8+ device
// properties - readable only by SYSTEM live, so use --hive with a copy of the
// SYSTEM hive), partition-manager disk id and the drive letters MountedDevices
// tied to the serial. A standard DFIR question ("which USB sticks were
// plugged in, and when?"). Read-only.
// Usage: winspect usb [--hive <SYSTEM>] [--json | --csv]
int cmd_usb(int argc, char **argv);

#endif
