#ifndef WINSPECT_MRU_H
#define WINSPECT_MRU_H

// winspect mru - what the current user recently typed or opened, in order:
// RunMRU (commands typed into Win+R), TypedPaths (paths typed into the
// Explorer address bar) and RecentDocs (recently opened documents). The newest
// entry of each list also gets its time (the key's last-write time). Flags
// Run-box commands that start a script host or carry an encoded PowerShell
// command. Current user only. Read-only. Usage:
//   winspect mru [--json | --csv]
int cmd_mru(int argc, char **argv);

#endif
