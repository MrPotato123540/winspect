#ifndef WINSPECT_SHARES_H
#define WINSPECT_SHARES_H

// winspect shares - the SMB shares this machine exposes (name, type, comment),
// marking the special administrative shares (C$, ADMIN$, IPC$). Read-only.
// Usage: winspect shares [--json | --csv]
int cmd_shares(int argc, char **argv);

#endif
