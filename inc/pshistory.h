#ifndef WINSPECT_PSHISTORY_H
#define WINSPECT_PSHISTORY_H

// winspect pshistory - PowerShell command history kept by PSReadLine
// (%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt):
// every command a user typed into an interactive console, oldest first, kept
// even after the window is closed. Lines matching well-known attacker patterns
// (encoded commands, download cradles, AMSI / Defender tampering, credential
// dumping, log clearing, persistence) are flagged with a reason. --all-users
// reads every profile under C:\Users (needs admin); a file or folder argument
// reads a copy (e.g. from a disk image). Read-only. Usage:
//   winspect pshistory [<file | folder> | --all-users] [--flagged] [--json | --csv]
int cmd_pshistory(int argc, char **argv);

#endif
