#ifndef WINSPECT_HIVE_H
#define WINSPECT_HIVE_H

// winspect hive - browse an OFFLINE registry hive file (NTUSER.DAT, SYSTEM,
// SOFTWARE, SAM, Amcache.hve ... copied off a machine): header facts (dirty
// = transaction logs not replayed, checksum, embedded original path), then a
// key with its last-write time, subkeys and decoded values (strings, numbers,
// hex for binary). --recurse walks the subtree. Never touches the live
// registry; the file is only read. The per-user / SYSTEM artifact commands
// take the same files with --hive (userassist, mru, bam, shimcache). Usage:
//   winspect hive <file> [<key\\path>] [--recurse] [--json]
int cmd_hive(int argc, char **argv);

#endif
