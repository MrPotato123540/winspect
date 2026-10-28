#ifndef WINSPECT_TASKS_H
#define WINSPECT_TASKS_H

// winspect tasks - list scheduled tasks by reading their XML definitions under
// %SystemRoot%\System32\Tasks (or a copied folder with --dir): the command and
// arguments or the COM handler (CLSID -> DLL), the account it runs as, its
// triggers (logon, boot, calendar...), registration date and author. Flags
// commands or handler DLLs in user-writable locations, COM handlers
// registered per-user (HKCU hijack, T1546.015), hidden tasks and script hosts
// outside the Microsoft\ folder. Scheduled tasks are a common persistence
// mechanism. Read-only. Usage:
//   winspect tasks [--dir <Tasks folder>] [--flagged] [--json | --csv]
int cmd_tasks(int argc, char **argv);

#endif
