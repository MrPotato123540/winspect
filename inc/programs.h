#ifndef WINSPECT_PROGRAMS_H
#define WINSPECT_PROGRAMS_H

// winspect programs - installed software from the Uninstall keys (machine
// 64-bit and 32-bit views, plus the user's own per-user installs): name,
// version, publisher, install date, location and the key's last-write time,
// newest first. Well-known remote-access / RMM tools (AnyDesk, ScreenConnect,
// TeamViewer, ...) are flagged "confirm it is authorised" - intruders install
// them for hands-on access. Live, or offline from SOFTWARE / NTUSER.DAT.
// Read-only. Usage:
//   winspect programs [--software <SOFTWARE>] [--ntuser <NTUSER.DAT>] [--flagged] [--json | --csv]
int cmd_programs(int argc, char **argv);

#endif
