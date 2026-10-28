#ifndef WINSPECT_SSN_H
#define WINSPECT_SSN_H

// winspect ssn - read an ntdll system-call stub and show its syscall number
// (SSN), and whether the stub still has the expected shape or was patched
// (an inline hook, as EDRs and some malware install). Educational view of how
// user mode enters the kernel. Read-only. Usage:
//   winspect ssn <NtFunctionName> [--json]
int cmd_ssn(int argc, char **argv);

#endif
