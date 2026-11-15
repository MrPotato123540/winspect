#ifndef WINSPECT_THREADS_H
#define WINSPECT_THREADS_H

// winspect threads - every thread of a process: priority, CPU time, state /
// wait reason, start address (resolved to module+offset) and a register
// snapshot (RIP/RSP); -s adds a symbolised call stack. A thread whose start
// address lies outside every module is the classic shape of injected code.
// Read-only (threads are only briefly suspended to read their context).
// Usage:
//   winspect threads <pid | name> [-s] [--json | --csv]
int cmd_threads(int argc, char **argv);

#endif
