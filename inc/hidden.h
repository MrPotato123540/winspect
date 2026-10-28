#ifndef WINSPECT_HIDDEN_H
#define WINSPECT_HIDDEN_H

// winspect hidden - cross-view checks for things hidden from the usual tools:
//   processes: Toolhelp snapshot vs NtQuerySystemInformation vs opening every
//              PID directly (a user-mode hook can hide a process from one list
//              but the process object still opens)
//   services:  the registry's Services key vs what the Service Control Manager
//              lists (a service whose security descriptor denies read access
//              disappears from "sc query" and services.msc, MITRE T1564)
// Candidates are re-checked to rule out processes/services that simply started
// or stopped between the two views. Read-only. Usage:
//   winspect hidden [--json | --csv]
int cmd_hidden(int argc, char **argv);

#endif
