#ifndef WINSPECT_VERIFY_H
#define WINSPECT_VERIFY_H

// winspect verify - consistency checks inside one process, each reading the
// same truth from two places: ntdll stubs vs a clean copy (hooks), PEB image
// path vs kernel path (masquerade), loader list vs enumeration (hidden
// modules), private executable memory, main image in memory vs on disk
// (tamper, relocation-aware), IAT targets, thread start addresses and section
// permissions. Read-only. Usage:
//   winspect verify <pid> [--json]
int cmd_verify(int argc, char **argv);

#endif
