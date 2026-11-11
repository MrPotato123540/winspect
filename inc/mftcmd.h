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
// --deleted keeps records that are no longer in use. --live <drive> reads
// the running system's $MFT through a read-only volume handle (boot sector
// -> the $MFT's own record -> its data runs; administrator). --image <file>
// does the same on a raw image of one NTFS partition (dd / FTK "raw"), so no
// mounting is needed. A fragmented $MFT is followed through record 0's
// attribute list; if its extents still cannot all be found, a WARNING on
// stderr says the listing is incomplete. A file created and deleted within
// seconds may never reach the on-disk $MFT at all (NTFS writes records
// lazily): cross-check with `usn`. Read-only. Usage:
//   winspect mft <$MFT file> | --live <drive> | --image <volume image>
//                [--find <text>] [--deleted] [--timestomp] [--json | --csv]
int cmd_mft(int argc, char **argv);

#endif
