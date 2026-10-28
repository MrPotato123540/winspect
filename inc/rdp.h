#ifndef WINSPECT_RDP_H
#define WINSPECT_RDP_H

// winspect rdp - OUTGOING Remote Desktop history of a user, from the client's
// registry: Terminal Server Client\Default (MRU0..MRU9: the last hosts typed
// into mstsc, newest first) and Terminal Server Client\Servers\<host> (every
// host connected to, the user name used - UsernameHint - and whether a server
// certificate was accepted). Classic evidence of lateral movement FROM this
// account. Live mode: current user; --hive reads another user's NTUSER.DAT.
// (Incoming RDP logons are in "events".) Read-only. Usage:
//   winspect rdp [--hive <NTUSER.DAT>] [--json | --csv]
int cmd_rdp(int argc, char **argv);

#endif
