#ifndef WINSPECT_HASH_H
#define WINSPECT_HASH_H

// winspect hash - compute a file's MD5, SHA1 and SHA256 digests, the identifiers
// used to look a sample up in threat-intel. Read-only. Usage:
//   winspect hash <path> [--json]
int cmd_hash(int argc, char **argv);

#endif
