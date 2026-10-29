#ifndef WINSPECT_PCA_H
#define WINSPECT_PCA_H

// winspect pca - Program Compatibility Assistant records (Windows 11 22H2+):
// C:\Windows\appcompat\pca\PcaAppLaunchDic.txt (full path + last launch time,
// UTC) and PcaGeneralDb0/1.txt (time, run status, path, description, vendor,
// version, program id). Execution evidence that survives Prefetch being
// disabled. Lines whose shape does not match the documented layout are shown
// raw instead of being guessed at. Flags programs in user-writable folders.
// A folder argument reads a copy (e.g. from a disk image). Read-only. Usage:
//   winspect pca [<folder>] [--flagged] [--json | --csv]
int cmd_pca(int argc, char **argv);

#endif
