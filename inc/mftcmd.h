#ifndef WINSPECT_MFTCMD_H
#define WINSPECT_MFTCMD_H

// winspect mft - files from a copied NTFS $MFT (collected with a triage tool
// or taken from a mounted image): full path (deleted files included, broken
// chains under $Orphan), size, the four $STANDARD_INFORMATION times and the
// $FILE_NAME creation time, and the Object ID's creation time / MAC when
// there is one. --timestomp lists only files whose $SI creation time is
// earlier than their $FN creation time - a timestomping CANDIDATE list, not
// a verdict: files from install media and archives look the same (on a real
// XP image a third of all files did). --find filters by path text,
// --deleted keeps records that are no longer in use. Read-only. Usage:
//   winspect mft <$MFT file> [--find <text>] [--deleted] [--timestomp] [--json | --csv]
int cmd_mft(int argc, char **argv);

#endif
