#ifndef WINSPECT_PIPES_H
#define WINSPECT_PIPES_H

// winspect pipes - list the named pipes present on the system. Named pipes are
// a common IPC and C2 channel, so "what pipes exist?" is a useful triage view.
// Read-only: it only lists the \\.\pipe\ directory. Usage:
//   winspect pipes [--json | --csv]
int cmd_pipes(int argc, char **argv);

#endif
