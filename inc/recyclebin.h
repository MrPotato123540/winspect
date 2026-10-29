#ifndef WINSPECT_RECYCLEBIN_H
#define WINSPECT_RECYCLEBIN_H

// winspect recyclebin - what was deleted, by whom and when. Reads the "$I"
// metadata files in <drive>:\$Recycle.Bin\<user SID>\ on every local drive
// (Vista..8.1 and Windows 10+ formats) and XP's RECYCLER\<SID>\INFO2: the
// original path, size and deletion time, the owning account, and whether the
// "$R" copy of the content is still there. Deleted programs and scripts are
// flagged. Other users' folders need admin. A file or folder argument reads a
// copy (e.g. from a disk image). Read-only. Usage:
//   winspect recyclebin [<$I file | INFO2 | folder>] [--flagged] [--json | --csv]
int cmd_recyclebin(int argc, char **argv);

#endif
