#ifndef WINSPECT_TASKS_H
#define WINSPECT_TASKS_H

// winspect tasks - list scheduled tasks by reading their XML definitions under
// %SystemRoot%\System32\Tasks, pulling out the command, arguments and author,
// and flagging ones that run from user-writable locations. Scheduled tasks are a
// common persistence mechanism. Read-only. Usage:
//   winspect tasks [--flagged] [--json | --csv]
int cmd_tasks(int argc, char **argv);

#endif
