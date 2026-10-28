#ifndef WINSPECT_BITSJOBS_H
#define WINSPECT_BITSJOBS_H

// winspect bits - Background Intelligent Transfer Service jobs: name, owner,
// state, creation / modification / completion times and every file (remote
// URL -> local path). A job can name a command that BITS runs when it ends,
// which survives reboots and runs under the owner's account (MITRE T1197);
// such jobs are flagged, as are downloads from a bare IP address and programs
// or scripts landing in a user-writable folder. Other users' jobs need admin;
// without it only the caller's own jobs are listed (and said so). Read-only:
// jobs are only enumerated, never created, changed or cancelled. Usage:
//   winspect bits [--flagged] [--json | --csv]
int cmd_bits(int argc, char **argv);

#endif
