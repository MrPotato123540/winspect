#ifndef WINSPECT_SESSIONS_H
#define WINSPECT_SESSIONS_H

// winspect sessions - the terminal/logon sessions on this machine: id, window
// station, connection state and the user signed in. Read-only. Usage:
//   winspect sessions [--json | --csv]
int cmd_sessions(int argc, char **argv);

#endif
