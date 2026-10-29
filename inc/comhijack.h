#ifndef WINSPECT_COMHIJACK_H
#define WINSPECT_COMHIJACK_H

// winspect comhijack - per-user COM class registrations (HKCU\Software\Classes
// \CLSID, also the WOW6432Node view) compared with the machine ones (HKLM).
// For a process running as that user the per-user registration WINS, so a
// user-writable key can silently replace a system class's DLL or EXE without
// admin rights (COM hijacking, MITRE T1546.015). A per-user class that also
// exists machine-wide with a DIFFERENT server file is flagged. Classes that
// exist only per-user (OneDrive, Teams, ... register many) are shown with
// --all but not flagged. --usrclass reads a user's UsrClass.dat copy and
// --software the matching SOFTWARE hive (both from the same machine) for
// offline use. Read-only. Usage:
//   winspect comhijack [--usrclass <UsrClass.dat> [--software <SOFTWARE>]]
//                      [--all] [--flagged] [--json | --csv]
int cmd_comhijack(int argc, char **argv);

#endif
