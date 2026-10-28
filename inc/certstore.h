#ifndef WINSPECT_CERTSTORE_H
#define WINSPECT_CERTSTORE_H

// winspect certstore - list the certificates in a system certificate store
// (Root by default). A rogue trusted-root certificate lets an attacker's
// signatures and TLS be trusted, so the Root store is worth baselining.
// Flags roots with a local private key, roots that are not self-signed and
// entries whose stored SHA-1 differs from the certificate's real one.
// --software / --ntuser read the registry-backed stores of a copied SOFTWARE
// or NTUSER.DAT hive (also the Group Policy copy). Read-only. Usage:
//   winspect certstore [--store <name>] [--user | --software <S> | --ntuser <N>] [--json | --csv]
int cmd_certstore(int argc, char **argv);

#endif
