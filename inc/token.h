#ifndef WINSPECT_TOKEN_H
#define WINSPECT_TOKEN_H

// winspect token - a process's security context: user and groups (with
// attributes), integrity level, elevation, token type, logon session, the
// linked (UAC split) token and every privilege with its state - powerful ones
// (SeDebug, SeImpersonate, SeLoadDriver, ...) are highlighted, and marked when
// ENABLED. Read-only (TOKEN_QUERY). Usage:
//   winspect token <pid | name> [--json]
int cmd_token(int argc, char **argv);

#endif
