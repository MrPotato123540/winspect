#ifndef WINSPECT_OBJECTS_H
#define WINSPECT_OBJECTS_H

// winspect objects - list named kernel objects in an Object Manager directory
// (default: this session's \Sessions\<N>\BaseNamedObjects), with each object's
// type (Mutant, Event, Section, Semaphore, ...). Malware frequently creates a
// uniquely-named mutex as a "single instance" marker, so these names are a
// classic indicator. Read-only (DIRECTORY_QUERY). Usage:
//   winspect objects [<\object\dir> | --global] [--type <T>] [--json | --csv]
int cmd_objects(int argc, char **argv);

#endif
