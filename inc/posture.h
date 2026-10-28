#ifndef WINSPECT_POSTURE_H
#define WINSPECT_POSTURE_H

// winspect posture - host security-posture audit from the registry: UAC, LSA
// protection, WDigest cleartext credentials, NTLM level, SMBv1, RDP/NLA,
// LLMNR, Secure Boot, firewall profiles, AlwaysInstallElevated, AutoLogon
// password presence, PowerShell logging. Each check prints OK / WARN / INFO
// with a one-line reason. Secrets are never printed (only "present").
// Offline: the same rules on hive files from another machine.
// Read-only. Usage:
//   winspect posture [--warn] [--software <SOFTWARE>] [--system <SYSTEM>] [--ntuser <NTUSER.DAT>] [--json | --csv]
int cmd_posture(int argc, char **argv);

#endif
