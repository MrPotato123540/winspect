#ifndef WINSPECT_TRIAGE_H
#define WINSPECT_TRIAGE_H

// winspect triage - one-shot "is this process suspicious?" report.
// Combines the signals the individual commands expose (signature trust,
// PEB/kernel path masquerade, ntdll inline hooks, private executable memory,
// token integrity) into a weighted suspicion score and a list of reasons.
// Usage: winspect triage <pid | name> [--json]
int cmd_triage(int argc, char **argv);

#endif
