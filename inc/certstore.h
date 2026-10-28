#ifndef WINSPECT_CERTSTORE_H
#define WINSPECT_CERTSTORE_H

// winspect certstore - list the certificates in a system certificate store
// (Root by default). A rogue trusted-root certificate lets an attacker's
// signatures and TLS be trusted, so the Root store is worth baselining.
// Read-only. Usage:
//   winspect certstore [--store <name>] [--user] [--json | --csv]
int cmd_certstore(int argc, char **argv);

#endif
