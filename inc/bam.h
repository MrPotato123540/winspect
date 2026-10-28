#ifndef WINSPECT_BAM_H
#define WINSPECT_BAM_H

// winspect bam - Background Activity Moderator records: per user (SID), the
// executables that ran and when each last ran, from both the current
// (bam\State\UserSettings) and the legacy 1709 (bam\UserSettings) key.
// Windows 10 1709+; usually needs elevation. --hive reads an offline SYSTEM
// hive instead. Read-only. Usage:
//   winspect bam [--hive <SYSTEM>] [--json | --csv]
int cmd_bam(int argc, char **argv);

#endif
