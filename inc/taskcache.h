#ifndef WINSPECT_TASKCACHE_H
#define WINSPECT_TASKCACHE_H

// winspect taskcache - scheduled tasks as the Task Scheduler's registry cache
// (TaskCache\Tree) records them, cross-checked for the ways a task is HIDDEN
// from schtasks / Task Scheduler: no SD value (the "Tarrask" technique), an SD
// containing deny ACEs, or no matching XML file under System32\Tasks
// (registry-only task). Usually needs elevation. Read-only. Usage:
//   winspect taskcache [--flagged] [--json | --csv]
int cmd_taskcache(int argc, char **argv);

#endif
