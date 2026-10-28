#ifndef WINSPECT_FIREWALL_H
#define WINSPECT_FIREWALL_H

// winspect firewall - Windows Defender Firewall rules read straight from the
// registry (local store + Group Policy store): direction, action, protocol,
// ports, program and name. Flags active inbound ALLOW rules whose program sits
// in a user-writable directory - a classic way to open a door for a dropped
// tool. Read-only (never adds/changes rules). Usage:
//   winspect firewall [--inbound] [--allow] [--active] [--flagged] [--json | --csv]
int cmd_firewall(int argc, char **argv);

#endif
