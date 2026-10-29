#ifndef WINSPECT_REGIONS_H
#define WINSPECT_REGIONS_H

// winspect regions - the virtual memory map of a process (VirtualQueryEx):
// base, size, protection, type (image / mapped / private) and the backing
// file. Private executable regions - code with no file behind it - are
// flagged. Read-only. Usage:
//   winspect regions <pid> [--json | --csv]
int cmd_regions(int argc, char **argv);

#endif
