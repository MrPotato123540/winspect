#ifndef WINSPECT_SHELLBAGS_H
#define WINSPECT_SHELLBAGS_H

// winspect shellbags - folders a user browsed in Explorer, from the ShellBags
// (BagMRU tree in NTUSER.DAT and UsrClass.dat): full path rebuilt from the
// shell items, item type, the folder's created / modified / accessed times
// recorded in the item, and the BagMRU key's last-write time. Folders stay
// listed after they are deleted or the USB stick / share is gone, which is
// what makes them evidence. Live: current user (HKCU + its UsrClass under
// HKCU\Software\Classes); offline: --ntuser / --usrclass hive files.
// Read-only. Usage:
//   winspect shellbags [--ntuser <NTUSER.DAT>] [--usrclass <UsrClass.dat>] [--json | --csv]
int cmd_shellbags(int argc, char **argv);

#endif
