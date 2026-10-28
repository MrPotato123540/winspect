#ifndef WINSPECT_USERS_H
#define WINSPECT_USERS_H

// winspect users - local accounts: name, RID, enabled, member of the local
// Administrators group, last logon, password last set, logon and bad-password
// counts, and the machine SID. Flags names ending in '$' that are not machine
// accounts (hidden from "net user"), an enabled Guest and enabled accounts
// that need no password. Live through the NetUser API; --sam reads a copied
// SAM hive (only the account names and the fixed "F" record - the password
// hashes are never read; group membership is not shown offline). Read-only.
// Usage:
//   winspect users [--sam <SAM>] [--flagged] [--json | --csv]
int cmd_users(int argc, char **argv);

#endif
