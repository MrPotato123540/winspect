// pidarg - turn a command's process argument into a PID
//
// Commands that look at one process (triage, inspect, modules, threads,
// regions, token, verify, handles, net) accept either a PID ("12996") or an
// image name ("explorer" or "explorer.exe", case-insensitive). A name must
// match exactly one running process; when several do, their PIDs are listed
// so the user can pick one.

#ifndef WINSPECT_PIDARG_H
#define WINSPECT_PIDARG_H

// Returns 1 and sets *pid on success; prints why to stderr (prefixed with
// cmd) and returns 0 otherwise.
int pid_from_arg(const char *cmd, const char *arg, unsigned long *pid);

#endif
