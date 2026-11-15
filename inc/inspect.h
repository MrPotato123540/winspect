#ifndef WINSPECT_INSPECT_H
#define WINSPECT_INSPECT_H

// winspect inspect - read a live process's PEB: image base, BeingDebugged,
// command line, image path, current directory and the loader's module list,
// plus the process mitigation policies in force (DEP, ASLR, CFG, signature
// policy, dynamic code). Read-only (PROCESS_QUERY_INFORMATION | VM_READ).
// Usage:
//   winspect inspect <pid | name> [--json]
int cmd_inspect(int argc, char **argv);

#endif
