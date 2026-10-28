#ifndef WINSPECT_USB_H
#define WINSPECT_USB_H

// winspect usb - USB mass-storage devices this machine has seen, from the
// Plug-and-Play record under HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR:
// vendor, product, revision, serial (instance id) and friendly name, plus the
// instance key's last-write time as a rough "last seen/changed" hint. A
// standard DFIR question ("which USB sticks were plugged in?"). Read-only.
// Usage: winspect usb [--json | --csv]
int cmd_usb(int argc, char **argv);

#endif
