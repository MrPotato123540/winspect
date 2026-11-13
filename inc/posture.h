#ifndef WINSPECT_POSTURE_H
#define WINSPECT_POSTURE_H

// winspect posture - host security-posture audit from the registry: UAC, LSA
// protection, WDigest cleartext credentials, NTLM level, LM hashes, anonymous
// SAM listing, Credential Guard, remote local-admin token filtering, SMBv1,
// SMB signing, RDP/NLA, LLMNR, Secure Boot, firewall profiles,
// AlwaysInstallElevated, AutoLogon password presence, PowerShell logging and
// transcription, command lines in 4688 events, port-forwarding (portproxy)
// rules, anonymously reachable pipes, accounts hidden from the sign-in screen,
// a WSUS server over plain HTTP, RDP shadowing without consent, Sysmon
// presence. Each check prints OK / WARN / INFO
// with a one-line reason. Secrets are never printed (only "present").
// Offline: the same rules on hive files from another machine.
// Read-only. Usage:
//   winspect posture [--warn] [--software <SOFTWARE>] [--system <SYSTEM>] [--ntuser <NTUSER.DAT>] [--json | --csv]
int cmd_posture(int argc, char **argv);

#endif
