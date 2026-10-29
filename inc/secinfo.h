#ifndef WINSPECT_SECINFO_H
#define WINSPECT_SECINFO_H

// winspect secinfo - who may do what to an object (AccessChk-style): owner,
// integrity label, DACL/SACL with rights decoded per object type, and YOUR
// effective access (or another account's with --account, via Authz). Objects:
// a process (pid), a file/folder (path), a service (--service) or a registry
// key (--key). --privileges lists the rights an ACCOUNT holds on the system.
// Read-only. Usage:
//   winspect secinfo <pid | path> [--service <name>] [--key <regpath>]
//                    [--account <acct>] [--privileges <acct>] [--rights]
//                    [--sddl] [--json]
int cmd_secinfo(int argc, char **argv);

#endif
