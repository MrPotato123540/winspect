#ifndef WINSPECT_SWEEP_H
#define WINSPECT_SWEEP_H

// winspect sweep - one-shot machine triage: runs the system-wide checks in
// "findings only" mode (posture --warn, hunt, hidden, net, autoruns/services/tasks/
// taskcache/firewall/prefetch --flagged, defender, wmi, users/comhijack/bits/recyclebin --flagged,
// pshistory / browser --all-users --flagged, events) and prints them as one
// report. With --json the result is a single object, one key per check; a
// check that could not run (e.g. needs elevation) is null instead of breaking
// the document. Read-only - it only calls the read-only commands. Usage:
//   winspect sweep [--json]
int cmd_sweep(int argc, char **argv);

#endif
