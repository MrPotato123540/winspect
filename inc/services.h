#ifndef WINSPECT_SERVICES_H
#define WINSPECT_SERVICES_H

// winspect services - enumerate Windows services with their config: state,
// start type, owning PID, binary path and the account they run as. Read-only
// (SCM query access only). Flags unquoted paths with spaces and binaries /
// ServiceDlls in user-writable dirs, each with a reason.
// --sig verifies the binary (or svchost ServiceDll) signature.
// Usage: winspect services [--drivers] [--flagged] [--sig] [--json | --csv]
int cmd_services(int argc, char **argv);

#endif
