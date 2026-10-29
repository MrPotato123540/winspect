#ifndef WINSPECT_SYSINFO_H
#define WINSPECT_SYSINFO_H

// winspect sysinfo - the first page of an investigation, from the registry:
// computer name (and older names in other control sets), Windows edition /
// build / install date, last shutdown, time zone, last logged-on user, network
// interfaces with their addresses, user profiles (SID, path, last load) and
// the networks the machine has joined (NetworkList: name, wired / wireless /
// VPN, domain / private / public, first and last connection in LOCAL time).
// Live, or offline from SOFTWARE / SYSTEM hive files. Read-only. Usage:
//   winspect sysinfo [--software <SOFTWARE>] [--system <SYSTEM>] [--json]
int cmd_sysinfo(int argc, char **argv);

#endif
