#ifndef WINSPECT_AUTORUNS_H
#define WINSPECT_AUTORUNS_H

// winspect autoruns - read-only sweep of common auto-start locations: Run /
// RunOnce (+Wow6432Node, +Policies\Explorer\Run), Winlogon Userinit/Shell,
// IFEO Debugger, SilentProcessExit, AppInit_DLLs, BootExecute, LSA packages,
// print monitors, NetSh helpers, AppCertDlls, cmd.exe AutoRun, logon scripts,
// Active Setup, time providers, screensaver, exefile / ms-settings handler
// hijacks, the "Office test" key and the Startup folders; plus the less-known
// family: the legacy Load / Run values, Winlogon Notify DLLs, AeDebug / .NET /
// WER debuggers, SetupExecute / PlatformExecute,
// BootVerificationProgram, LSA extensions, Winlogon mpnotify, DNS
// ServerLevelPluginDll, WinSock AutodialDLL, Group Policy extensions,
// TelemetryController commands, search-indexer DLL overrides, service
// FailureCommand, AMSI providers, .NET profiler / start-up hook variables,
// custom shim databases and the programs they apply to, Setup's
// ErrorHandler.cmd and PowerShell profiles. Each flagged entry
// carries a reason (user-writable path / non-default value / rare location).
// A transparent subset of what Sysinternals Autoruns inspects.
// --sig verifies the signature of what each entry runs (Autoruns' "Verify
// code signatures") and flags untrusted images and images whose file is gone.
// Entries named like a core Windows binary but placed outside System32 (e.g.
// System32\dllhost\svchost.exe) are flagged as masquerading.
// Offline: --software / --system / --ntuser read hive FILES instead of the
// live registry (any combination; Startup folders and --sig need the live
// machine and are skipped / refused).
// Usage: winspect autoruns [--flagged] [--sig] [--json | --csv]
//        winspect autoruns [--software <SOFTWARE>] [--system <SYSTEM>] [--ntuser <NTUSER.DAT>]
//                          [--flagged] [--json | --csv]
int cmd_autoruns(int argc, char **argv);

#endif
