#ifndef WINSPECT_HANDLES_H
#define WINSPECT_HANDLES_H

// winspect handles - the kernel object handles a process holds: type, name and
// granted access decoded per object type (File, Key, Process, Thread, Token,
// Section, ...). Handles to OTHER processes/threads with write or
// thread-control rights are marked [INJECTABLE -> pid]: the capability behind
// code injection. --find searches EVERY process for handles whose object name
// contains the text ("who has this file / key / mutex open?"), optionally of
// one --type. Uses the extended handle table (full-width PIDs and handle
// values); file names are queried with a timeout so a blocking pipe cannot
// hang the tool. Read-only (handles are duplicated only to query them).
// Usage:
//   winspect handles <pid | name> [--json | --csv]
//   winspect handles --find <text> [--type <T>] [--json | --csv]
int cmd_handles(int argc, char **argv);

#endif
