#ifndef WINSPECT_BAM_H
#define WINSPECT_BAM_H

// winspect bam - Background Activity Moderator records: per user (SID), the
// executables that ran and when each last ran. Windows 10 1709+; usually needs
// elevation. Read-only. Usage:
//   winspect bam [--json | --csv]
int cmd_bam(int argc, char **argv);

#endif
