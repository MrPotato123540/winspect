#ifndef WINSPECT_AUTORUNS_H
#define WINSPECT_AUTORUNS_H

// winspect autoruns - read-only sweep of common auto-start locations: Run /
// RunOnce (+Wow6432Node, +Policies\Explorer\Run), Winlogon Userinit/Shell,
// IFEO Debugger, SilentProcessExit, AppInit_DLLs, BootExecute, LSA packages,
// print monitors, NetSh helpers, AppCertDlls, cmd.exe AutoRun, logon scripts,
// Active Setup, time providers, screensaver, exefile / ms-settings handler
// hijacks, the "Office test" key and the Startup folders. Each flagged entry
// carries a reason (user-writable path / non-default value / rare location).
// A transparent subset of what Sysinternals Autoruns inspects.
// --sig verifies the signature of what each entry runs (Autoruns' "Verify
// code signatures") and flags untrusted images and images whose file is gone.
// Usage: winspect autoruns [--flagged] [--sig] [--json | --csv]
int cmd_autoruns(int argc, char **argv);

#endif
