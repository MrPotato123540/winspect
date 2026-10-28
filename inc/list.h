#ifndef WINSPECT_LIST_H
#define WINSPECT_LIST_H

// winspect list - the live process tree from a Toolhelp snapshot: each process
// under its real parent (PID reuse is detected by creation time), with thread
// counts. -t adds each process's threads, -l adds the image path and integrity
// level. -j / --json and --csv emit flat records (pid, ppid, name, threads,
// integrity, path) instead of the tree. Read-only. Usage:
//   winspect list [-t | --threads] [-l | --long] [-j | --json | --csv]
int cmd_list(int argc, char** argv);

#endif
