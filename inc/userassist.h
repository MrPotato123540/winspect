#ifndef WINSPECT_USERASSIST_H
#define WINSPECT_USERASSIST_H

// winspect userassist - programs the current user started from the Explorer
// GUI (Start menu, desktop, Explorer windows), with run count and last run
// time, from the UserAssist registry key. Names are stored ROT13-encoded and
// often begin with a Known Folder GUID; both are decoded. Flags programs run
// from user-writable dirs or script hosts. Live mode covers the current user;
// --hive reads another user's NTUSER.DAT (an offline copy). Read-only. Usage:
//   winspect userassist [--hive <NTUSER.DAT>] [--json | --csv]
int cmd_userassist(int argc, char **argv);

#endif
