#ifndef WINSPECT_MODULES_H
#define WINSPECT_MODULES_H

// winspect modules - the modules (EXE + DLLs) loaded in a live process, with
// each one's load address, size and backing file, flagging modules whose file
// is missing from disk or sits in a user-writable location. --sig also checks
// each module's signature (embedded or catalog); --unsigned shows only the ones
// without a trusted signature (the ListDLLs -u idea). Read-only. Usage:
//   winspect modules <pid> [--sig | --unsigned] [--json | --csv]
int cmd_modules(int argc, char **argv);

#endif
