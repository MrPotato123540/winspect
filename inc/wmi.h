#ifndef WINSPECT_WMI_H
#define WINSPECT_WMI_H

// winspect wmi - permanent WMI event subscriptions in root\subscription: event
// filters (the trigger), consumers (the action) and the bindings that connect
// them. A filter + CommandLine/ActiveScript consumer + binding is a well-known
// fileless persistence technique (MITRE T1546.003); consumers that run code are
// flagged. Read-only WQL SELECT queries. Usage:
//   winspect wmi [--json | --csv]
int cmd_wmi(int argc, char **argv);

#endif
